import logging
import random
import socket
import threading
import time
from io import RawIOBase
from collections import deque
from typing import IO, Deque, Optional, Mapping, Any, Union, Tuple

from . import RTPMediaProfiles, RTPPacketsStats
from .packet import RTPPacket
from ..constants import SUPPORTED_RTP_PROFILES
from ..exceptions import (
    RTPBrokenStreamError,
    RTPMismatchedStreamError,
    RTPUnsupportedVersion, RTPParseError,
)


_logger = logging.getLogger(__name__)


class RTPStreamBuffer(RawIOBase, IO):
    """
    A buffer for RTP packets. It keeps track of data and timestamps offset.
    Use a deque to implement a bytes circular buffer, consuming it once read from.
    Also keeps track of the offset of packets, so that we can handle out of order
    ones, we keep them in a separate pending queue, and attempt to rebuild the stream,
    if they're not too late.
    """

    DEFAULT_SIZE: int = 160
    SSRC_MAX: int = 2**32
    SEQUENCE_MAX: int = 2**16
    SEQUENCE_WRAP_DELTA: int = 2**10
    TIMESTAMP_MAX: int = 2**32
    TIMESTAMP_WRAP_DELTA: int = DEFAULT_SIZE * 2**10

    def __init__(
        self,
        mode: str,
        ssrc: Optional[int] = None,
        initial_sequence: Optional[int] = None,
        initial_timestamp: Optional[int] = None,
        max_pending: int = 10,
        lost_filler: bytes = b"\x00",
    ):
        if mode not in ("r", "w"):
            raise ValueError("mode must be either 'r' or 'w'")

        if initial_sequence is None:
            initial_sequence = (
                random.randint(0, self.SEQUENCE_MAX)
                if mode == "r"
                else -self.SEQUENCE_MAX
            )
        if initial_timestamp is None:
            initial_timestamp = (
                int(time.monotonic_ns() // 1e6) % self.TIMESTAMP_MAX  # ms
                if mode == "r"
                else -self.TIMESTAMP_MAX
            )
        if ssrc is None and mode == "r":
            ssrc = random.randrange(0, self.SSRC_MAX)

        self._mode: str = mode
        self._max_pending: int = max_pending
        self._lost_filler: bytes = lost_filler
        self._fill_size: int = self.DEFAULT_SIZE

        self.ssrc: Optional[int] = ssrc
        self.sequence: int = initial_sequence
        self.timestamp: int = initial_timestamp
        self._buffer: Deque[bytes] = deque()
        self._pending: Deque[RTPPacket] = deque()
        self._buf_lock: threading.RLock = threading.RLock()

        self._seen_count: int = 0
        """Seen packets count: any packet received by the buffer."""
        self._out_of_order_count: int = 0
        """Out of order packets count: packets received out of order, recovered or not."""
        self._drop_count: int = 0
        """Dropped packets count: usually re-transmitted, or duplicate ones."""
        self._lost_count: int = 0
        """Lost packets count: out of order ones that are too old to recover."""
        self._ok_count: int = 0
        """Ok packets count: packets succesfully written to the buffer."""

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def seen_count(self) -> int:
        return self._seen_count

    @property
    def out_of_order_count(self) -> int:
        return self._out_of_order_count

    @property
    def drop_count(self) -> int:
        return self._drop_count

    @property
    def lost_count(self) -> int:
        return self._lost_count

    @property
    def ok_count(self) -> int:
        return self._ok_count

    @property
    def buffer_len(self) -> int:
        return sum(len(b) for b in self._buffer)

    def read(self, size: int = DEFAULT_SIZE) -> bytes:
        """
        Read up to size bytes from the buffer, if size is -1, read all available bytes.
        """
        with self._buf_lock:
            if size == -1:
                size = self.buffer_len
            else:
                size = min(size, self.buffer_len)

            data = b""
            while size > 0:
                buf = self._buffer.popleft()
                if len(buf) <= size:
                    data += buf
                    size -= len(buf)
                else:
                    data += buf[:size]
                    self._buffer.appendleft(buf[size:])
                    size = 0

        return data

    def read_packet(
        self, packet: Union[RTPPacket, Mapping[str, Any]], size: int = DEFAULT_SIZE
    ) -> Optional[RTPPacket]:
        """
        Read up to size bytes from the buffer, and return a packet with the given values.
        N.B. payload, ssrc, sequence, and timestamp will be overwritten.
        """
        if self._mode != "r":
            raise ValueError("Can only read packets in mode='r'")

        assert self.ssrc is not None

        if not isinstance(packet, (Mapping, RTPPacket)):
            raise TypeError(f"Expected a mapping or RTPPacket, got {type(packet)}")

        with self._buf_lock:
            data = self.read(size)
            if not data:
                return None
            self.sequence = (self.sequence + 1) % self.SEQUENCE_MAX
            self.timestamp = (self.timestamp + size) % self.TIMESTAMP_MAX

        if isinstance(packet, Mapping):
            packet = RTPPacket(
                **packet,
                payload=data,
                ssrc=self.ssrc,
                sequence=self.sequence,
                timestamp=self.timestamp,
            )
        else:
            assert isinstance(packet, RTPPacket)
            packet.payload = data
            packet.ssrc = self.ssrc
            packet.sequence = self.sequence
            packet.timestamp = self.timestamp
        return packet

    def write(self, data: bytes) -> int:
        """
        Write data to the buffer, and return the number of bytes written.
        """
        with self._buf_lock:
            self._buffer.append(data)
        return len(data)

    def write_packet(self, packet: RTPPacket) -> int:
        """
        Write a packet to the buffer, and return the number of bytes written.
        """
        if self._mode != "w":
            raise ValueError("Can only write packets in mode='w'")

        with self._buf_lock:
            if self.ssrc is None:
                self.ssrc = packet.ssrc
                self.sequence = packet.sequence - 1

            if self.ssrc != packet.ssrc:
                raise RTPMismatchedStreamError(
                    f"Packet does not match stream SSRC {self.ssrc} != {packet.ssrc}"
                )

            self._pending.append(packet)
            self._seen_count += 1
            if packet.sequence != ((self.sequence + 1) % self.SEQUENCE_MAX):
                self._out_of_order_count += 1

            # sort pending packets by sequence, if we have more than one
            if len(self._pending) > 1:
                self._pending = deque(sorted(self._pending, key=lambda p: p.sequence))

            # add packets to buffer
            written: int = 0
            while self._pending:
                next_packet: RTPPacket = self._pending[0]

                # if we have a packet with a completely different sequence, reset internal
                if abs(next_packet.sequence - self.sequence) > self.SEQUENCE_WRAP_DELTA:
                    self.sequence = next_packet.sequence - 1

                # if the packet is next in sequence, add it to the buffer
                if next_packet.sequence == self.sequence + 1:
                    new_packet: RTPPacket = self._pending.popleft()
                    written += self.write(new_packet.payload)
                    self.sequence = new_packet.sequence
                    self.timestamp = new_packet.timestamp
                    self._fill_size = len(new_packet.payload)
                    self._ok_count += 1

                # if the next packet is too late, or duplicate, silently drop it
                elif next_packet.sequence <= self.sequence:
                    self._pending.popleft()
                    self._drop_count += 1

                # otherwise check if we have too many pending packets
                elif len(self._pending) > self._max_pending:
                    # if the next packed is close enough in the future, fill missing data
                    if next_packet.sequence - self.sequence < self._max_pending:
                        written += self.write(self._lost_filler * self._fill_size)
                        self.sequence += 1  # let the loop figure this out
                        self._lost_count += 1
                    # otherwise, we have lost too many packets, raise an error
                    else:
                        raise RTPBrokenStreamError("Too many lost packets")

                # otherwise, we're missing just a few packets, don't do anything for now
                else:
                    break

        return written

    # TODO: implement a way to "reset" the stream? Otherwise we could just create a new one


class RTPClient:
    """Implements an RTP client using UDP sockets."""

    def __init__(
        self,
        local_addr: Tuple[str, int],
        remote_addr: Tuple[str, int],
        profile: RTPMediaProfiles,
        send_delay_factor: float = 1.0,
    ):
        self._local_addr: Tuple[str, int] = local_addr
        self._remote_addr: Tuple[str, int] = remote_addr

        if profile.name not in SUPPORTED_RTP_PROFILES:
            raise RTPUnsupportedVersion(f"Unsupported RTP profile {profile.name}")
        self._profile: RTPMediaProfiles = profile

        self._send_delay_factor: float = send_delay_factor

        # we write packets to
        self._recv_stream: RTPStreamBuffer = RTPStreamBuffer(mode="w")
        # we read packets from
        self._send_stream: RTPStreamBuffer = RTPStreamBuffer(mode="r")

        self._socket: Optional[socket.socket] = None

        self._recv_thread: Optional[threading.Thread] = None
        self._send_thread: Optional[threading.Thread] = None

        # TODO: move these to the streams?
        self._recv_stats: RTPPacketsStats = RTPPacketsStats()
        self._send_stats: RTPPacketsStats = RTPPacketsStats()

        self._closed: bool = False
        self._closing: bool = False

    @property
    def recv_stats(self) -> RTPPacketsStats:
        return self._recv_stats

    @property
    def send_stats(self) -> RTPPacketsStats:
        return self._send_stats

    @property
    def closed(self):
        return self._closed

    def start(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setblocking(False)
        self._socket.bind(self._local_addr)

        self._recv_thread = threading.Thread(target=self._recv_loop)
        self._send_thread = threading.Thread(target=self._send_loop)

        self._recv_thread.start()
        self._send_thread.start()

    def stop(self):
        self._closing = True
        self._recv_thread.join()
        self._send_thread.join()
        self._socket.close()
        self._closed = True

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def _recv_loop(self) -> None:
        """
        Receives data packets into the input stream buffer, until the client is closed.
        """
        while not self._closing:
            try:
                start_time_ns: int = time.perf_counter_ns()

                data, addr = self._socket.recvfrom(8192)

                packet: RTPPacket = RTPPacket.parse(data)
                self._recv_stream.write_packet(packet)

                end_time_ns: int = time.perf_counter_ns()
                self._recv_stats.add(packet, (end_time_ns - start_time_ns) / 1e9)

            except (socket.timeout, BlockingIOError):
                pass

            except RTPParseError as e:
                _logger.debug(f"Error parsing packet: {e}")

            time.sleep(1e-6)

    def _send_loop(self) -> None:
        """
        Sends pending data in the output stream buffer, until the client is closed.
        """
        packet_data = dict(
            version=2,
            padding=False,
            extension=False,
            csrc_count=0,
            marker=False,  # FIXME: should this be set? if so when? how?
            payload_type=self._profile,
        )

        while not self._closing:
            pre_send_time_ns: int = time.perf_counter_ns()

            packet: Optional[RTPPacket] = self._send_stream.read_packet(packet_data)
            if packet is not None:
                with self._send_stats.track(packet):
                    self._socket.sendto(packet.serialize(), self._remote_addr)

            send_time: float = (time.perf_counter_ns() - pre_send_time_ns) / 1e9
            packet_duration: float = packet and packet.duration or 0.0
            sleep_time: float = max(0.0, max(1 / 96_000, packet_duration) - send_time)
            time.sleep(sleep_time * self._send_delay_factor)

    def read(self, size: int = RTPStreamBuffer.DEFAULT_SIZE) -> bytes:
        """
        Read raw (encoded) data from the incoming RTP stream.
        If no data is available, will return an empty bytes object.

        :param size: The maximum number of bytes to read.
        """
        return self._recv_stream.read(size)

    def write(self, data: bytes) -> int:
        """
        Write raw (encoded) data to the outgoing RTP stream.
        Returns the number of bytes written.

        :param data: The encoded data to write.
        """
        return self._send_stream.write(data)
