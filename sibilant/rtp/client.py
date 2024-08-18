"""RTP client implementation."""

from __future__ import annotations

import enum
import errno
import logging
import random
import socket
import threading
import time
from collections import deque
from io import RawIOBase
from types import MappingProxyType, TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    Collection,
    Mapping,
)

import numpy as np
from typing_extensions import Buffer, Self

from sibilant.constants import DEFAULT_RTP_PORT_RANGE, SUPPORTED_RTP_PROFILES
from sibilant.exceptions import (
    RTPBrokenStreamError,
    RTPMismatchedStreamError,
    RTPParseError,
    RTPUnhandledPayload,
    RTPUnsupportedVersion,
)

from .packet import (
    DTMFEvent,
    RTPMediaFormat,
    RTPMediaProfiles,
    RTPMediaType,
    RTPPacket,
    RTPPacketsStats,
)


if TYPE_CHECKING:
    from numpy.typing import NDArray


_logger = logging.getLogger(__name__)


class RTPStreamBuffer(RawIOBase):
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

    # TODO: maybe rename modes to send/recv instead of r/w?
    #       otherwise, since they're doing completely different things,
    #       maybe we should split this class into two (+ a base class)?
    def __init__(
        self,
        mode: str,
        ssrc: int | None = None,
        profile: RTPMediaProfiles | None = None,
        initial_sequence: int | None = None,
        initial_timestamp: int | None = None,
        max_pending: int = 10,
        lost_filler: bytes = b"\x00",
    ):
        if mode not in {"r", "w"}:
            raise ValueError("`mode` must be either 'r' or 'w'")

        # FIXME: implement tracking multiplexed streams (this class needs to be reworked, stream tracking decoupled from socket)

        # FIXME: use 0s for initial values
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
        if profile is None and mode == "r":
            raise ValueError("`profile` must be specified in mode='r'")

        self._mode: str = mode
        self._max_pending: int = max_pending
        self._lost_filler: bytes = lost_filler
        self._fill_size: int = self.DEFAULT_SIZE

        self.ssrc: int | None = ssrc
        self._profile: RTPMediaProfiles | None = profile
        self.sequence: int = initial_sequence
        self.timestamp: int = initial_timestamp
        self._buffer: deque[bytes] = deque()
        self._pending: deque[RTPPacket] = deque()
        self._buf_lock: threading.RLock = threading.RLock()

        # TODO: Move or merge these into RTPPacketsStats?
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
        """The mode of the buffer, either 'r' or 'w'."""
        return self._mode

    @property
    def profile(self) -> RTPMediaProfiles | None:
        """The RTP profile of the buffer, if any."""
        return self._profile

    @property
    def pending_count(self) -> int:
        """The number of packets pending to be written to the buffer."""
        return len(self._pending)

    @property
    def max_pending(self) -> int:
        """The max number of packets allowed to be pending, before considering the stream broken."""
        return self._max_pending

    @property
    def seen_count(self) -> int:
        """The total number of packets seen by the buffer, regardless of their handling."""
        return self._seen_count

    @property
    def out_of_order_count(self) -> int:
        """The number of packets received out of order, whether recovered or not."""
        return self._out_of_order_count

    @property
    def drop_count(self) -> int:
        """The number of packets dropped, usually re-transmitted or duplicate ones."""
        return self._drop_count

    @property
    def lost_count(self) -> int:
        """The number of packets lost, usually out of order ones that are too old to recover."""
        return self._lost_count

    @property
    def ok_count(self) -> int:
        """The number of packets successfully written to the buffer."""
        return self._ok_count

    @property
    def buffer_len(self) -> int:
        """The current length of the buffer."""
        return sum(len(b) for b in self._buffer)

    def read(self, size: int = DEFAULT_SIZE) -> bytes:
        """Read up to size bytes from the buffer, if size is -1, read all available bytes."""
        with self._buf_lock:
            size = self.buffer_len if size == -1 else min(size, self.buffer_len)

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

    def read_audio(self, size: int = DEFAULT_SIZE) -> NDArray[np.float32]:
        """
        Read audio data from the buffer, decoded with the appropriate codec,
        into a float32 numpy array in the range [-1, 1].
        The rate is unchanged, so the same as the stream's profile.
        If no data is available, will return an empty numpy array.

        :param size: The maximum number of bytes to read.
        :raises RTPUnsupportedCodec: If the codec is not supported.
        """
        raw_data: bytes = self.read(size)
        if not raw_data:
            return np.zeros(0, dtype=np.float32)
        if self._profile is None:
            raise ValueError("Stream has no profile set, cannot decode audio")
        if self._profile.media_type != RTPMediaType.AUDIO:
            raise ValueError("Can only read audio from a stream with audio profile")
        return self._profile.decode(raw_data)

    def read_packet(
        self, packet: RTPPacket | Mapping[str, Any], size: int = DEFAULT_SIZE
    ) -> RTPPacket | None:
        """
        Read up to size bytes from the buffer, and return a packet with the given values.
        N.B. payload, payload_type, ssrc, sequence, and timestamp will be overwritten.
        """
        if self._mode != "r":
            raise ValueError("Can only read packets in mode='r'")

        assert self.ssrc is not None

        if self._profile is None:
            raise ValueError("Stream has no profile set, cannot generate packet")

        if not isinstance(packet, (Mapping, RTPPacket)):
            raise TypeError(f"Expected a mapping or RTPPacket, got {type(packet)}")

        with self._buf_lock:
            data = self.read(size)
            if not data:
                return None
            time_span: int = len(
                data
            )  # FIXME: depends on profile, this hack works for PCMA/PCMU
            self.sequence = (self.sequence + 1) % self.SEQUENCE_MAX
            self.timestamp = (self.timestamp + time_span) % self.TIMESTAMP_MAX

        if isinstance(packet, Mapping):
            packet = RTPPacket(
                **packet,
                payload_type=self._profile,
                ssrc=self.ssrc,
                sequence=self.sequence,
                timestamp=self.timestamp,
                payload=data,
            )
        else:
            assert isinstance(packet, RTPPacket)
            packet.payload_type = self._profile
            packet.ssrc = self.ssrc
            packet.sequence = self.sequence
            packet.timestamp = self.timestamp
            packet.payload = data
        return packet

    def write(self, data: bytes | Buffer) -> int:
        """Write data to the buffer, and return the number of bytes written."""
        if isinstance(data, Buffer):
            data = bytes(data)
        with self._buf_lock:
            self._buffer.append(data)
        return len(data)

    def write_audio(self, data: NDArray[np.float32]) -> int:
        """
        Write audio data to the buffer, encoded with the appropriate codec,
        given a float32 numpy array in the range [-1, 1].
        The rate is fed unchanged, so it must match the stream's profile.
        Returns the number of bytes written.

        :param data: The data to write.
        :raises RTPUnsupportedCodec: If the codec is not supported.
        """
        if self._profile is None:
            raise ValueError("Stream has no profile set, cannot encode audio")
        if self._profile.media_type != RTPMediaType.AUDIO:
            raise ValueError("Can only write audio to a stream with audio profile")
        return self.write(self._profile.encode(data))

    def write_packet(self, packet: RTPPacket) -> int:
        """Write a packet to the buffer, and return the number of bytes written."""
        if self._mode != "w":
            raise ValueError("Can only write packets in mode='w'")

        with self._buf_lock:
            if self.ssrc is None:
                self.ssrc = packet.ssrc
                self._profile = packet.payload_type
                self.sequence = packet.sequence - 1

            if self.ssrc != packet.ssrc:
                raise RTPMismatchedStreamError(
                    f"Packet does not match stream SSRC {self.ssrc} != {packet.ssrc}"
                )

            if self._profile != packet.payload_type:
                raise RTPMismatchedStreamError(
                    f"Packet does not match stream profile {self._profile} != {packet.payload_type}"
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


class MediaFlowType(enum.Enum):
    """The types of media flow for a stream (send, receive, both, none)."""

    SENDRECV = "sendrecv"
    SENDONLY = "sendonly"
    RECVONLY = "recvonly"
    INACTIVE = "inactive"


class RTPClient:
    """Implements an RTP client using UDP sockets."""

    def __init__(
        self,
        local_addr: tuple[str, int],
        remote_addr: tuple[str, int] | None,
        media_formats: Collection[RTPMediaFormat | RTPMediaProfiles]
        | Mapping[int, RTPMediaFormat | RTPMediaProfiles],
        *,
        send_delay_factor: float = 1.0,
        pre_bind: bool = True,
    ):
        self._local_addr: tuple[str, int] = local_addr
        self._remote_addr: tuple[str, int] | None = remote_addr

        if not isinstance(media_formats, Mapping):
            media_formats = {
                f.payload_type: f
                for f in media_formats
                if isinstance(f.payload_type, int)
            }
        assert isinstance(media_formats, Mapping)
        self._media_profiles: Mapping[int, RTPMediaProfiles] = {
            payload_type: (
                media_format
                if isinstance(media_format, RTPMediaProfiles)
                and isinstance(media_format.payload_type, int)
                else RTPMediaProfiles.match(payload_type, media_format)  # type: ignore[arg-type]
            )
            for payload_type, media_format in media_formats.items()
        }
        # assert all(  # TODO: investigate intention
        #     isinstance(p.payload_type, int) for p in self._media_profiles.values()
        # )

        # FIXME: should we have separate profiles for sending and receiving?
        # try to find a supported format and use that as RTPMediaProfile for the streams
        self._profile: RTPMediaProfiles
        for profile in self._media_profiles.values():
            # TODO: maybe make sure we don't pick TELEPHONE_EVENT?
            if profile.name in SUPPORTED_RTP_PROFILES:
                self._profile = profile
                break
        else:
            raise RTPUnsupportedVersion(f"No supported RTP profiles in {media_formats}")

        self._send_delay_factor: float = send_delay_factor

        self._recv_streams: dict[int, RTPStreamBuffer] = {}
        self._send_stream: RTPStreamBuffer = self._create_send_stream()

        # FIXME: using two sockets doesn't seem to make a difference, refactor into one?
        self._socket: socket.socket | None = None

        if pre_bind:
            self._socket = self._create_socket()
            assert self._socket.family == socket.AF_INET
            self._local_addr = self._socket.getsockname()

        self._recv_thread: threading.Thread | None = None
        self._send_thread: threading.Thread | None = None
        self._last_send_time_ns: int | None = None

        # TODO: move these to the streams?
        self._recv_stats: RTPPacketsStats = RTPPacketsStats()
        self._send_stats: RTPPacketsStats = RTPPacketsStats()

        self._closing_event: threading.Event = threading.Event()
        self._closing_event.clear()

    @property
    def remote_addr(self) -> tuple[str, int]:
        """The remote address and port to send packets to."""
        assert self._remote_addr is not None
        return self._remote_addr

    @remote_addr.setter
    def remote_addr(self, value: tuple[str, int] | None) -> None:
        if value is not None and value[1] == 0:
            raise ValueError("Remote RTP port must be non-zero")
        self._remote_addr = value

    @property
    def remote_host(self) -> str:
        """The remote host to send packets to."""
        assert self._remote_addr is not None
        return self._remote_addr[0]

    @remote_host.setter
    def remote_host(self, value: str) -> None:
        self.remote_addr = (value, self.remote_port)

    @property
    def remote_port(self) -> int:
        """The remote port to send packets to."""
        assert self._remote_addr is not None
        return self._remote_addr[1]

    @remote_port.setter
    def remote_port(self, value: int) -> None:
        self.remote_addr = (self.remote_host, value)

    @property
    def local_addr(self) -> tuple[str, int]:
        """The local address and port used by the client to bind the socket."""
        return self._local_addr

    @property
    def local_host(self) -> str:
        """The local host used by the client to bind the socket."""
        return self._local_addr[0]

    @property
    def local_port(self) -> int:
        """The local port used by the client to bind the socket."""
        return self._local_addr[1]

    @property
    def profile(self) -> RTPMediaProfiles:
        """The default profile used by the client."""
        return self._profile

    @property
    def media_profiles(self) -> Mapping[int, RTPMediaProfiles]:
        """The media profiles supported by the client."""
        return MappingProxyType(self._media_profiles)

    @property
    def recv_stats(self) -> RTPPacketsStats:
        """The receive stats for the client."""
        return self._recv_stats

    @property
    def send_stats(self) -> RTPPacketsStats:
        """The send stats for the client."""
        return self._send_stats

    @property
    def closed(self) -> bool:
        """Returns True if the client is closed. (i.e. both send and recv threads are stopped)."""
        return (self._recv_thread is None or not self._recv_thread.is_alive()) and (
            self._send_thread is None or not self._send_thread.is_alive()
        )

    def _create_socket(self) -> socket.socket:
        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
        _socket.setblocking(False)

        dynamic_port: bool = self._local_addr[1] == 0
        while True:
            if dynamic_port:
                self._local_addr = (self._local_addr[0], DEFAULT_RTP_PORT_RANGE[0])
            try:
                _socket.bind(self._local_addr)
                break
            except OSError as e:
                if (
                    dynamic_port
                    and e.errno == errno.EADDRINUSE
                    and self._local_addr[1] < DEFAULT_RTP_PORT_RANGE[1]
                ):
                    self._local_addr = (self._local_addr[0], self._local_addr[1] + 2)
                else:
                    raise

        return _socket

    def _create_recv_stream(self) -> RTPStreamBuffer:
        return RTPStreamBuffer(mode="w")

    def _create_send_stream(self) -> RTPStreamBuffer:
        return RTPStreamBuffer(mode="r", profile=self._profile)

    def start(self) -> None:
        """Start the RTP client, creating the socket and threads."""
        if self._recv_thread is not None and self._recv_thread.is_alive():
            raise RuntimeError("RTP client already started")

        if self._remote_addr is None:
            raise RuntimeError("Remote address not set")

        if self._socket is None:
            self._socket = self._create_socket()

        # TODO: name threads
        self._recv_thread = threading.Thread(
            target=self._recv_loop,
            name=f"{self.__class__.__name__}._recv_loop-{id(self)}",
        )
        self._send_thread = threading.Thread(
            target=self._send_loop,
            name=f"{self.__class__.__name__}._send_loop-{id(self)}",
        )

        self._recv_thread.start()
        self._send_thread.start()

    def stop(self) -> None:
        """Stop the RTP client, closing the socket and joining the threads."""
        assert self._recv_thread is not None
        assert self._send_thread is not None
        assert self._socket is not None
        self._closing_event.set()
        self._recv_thread.join()
        self._send_thread.join()
        self._socket.close()

        self._socket = None
        self._recv_thread = None
        self._send_thread = None
        self._closing_event.clear()

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exctype: type[BaseException] | None,
        excinst: BaseException | None,
        exctb: TracebackType | None,
    ) -> None:
        self.stop()

    def _recv_loop(self) -> None:
        """Receives data packets into the input stream buffer, until the client is closed."""
        assert self._socket is not None

        while not self._closing_event.is_set():
            start_time_ns: int = time.perf_counter_ns()

            packet: RTPPacket | None = None
            try:
                data, _addr = self._socket.recvfrom(8192)
            except (socket.timeout, BlockingIOError):
                pass
            else:
                try:
                    packet = self._recv_packet(data)

                except RTPParseError as e:
                    _logger.debug(f"Error parsing RTP packet: {e}")

            end_time_ns: int = time.perf_counter_ns()
            if packet is not None:
                self._recv_stats.add(packet, (end_time_ns - start_time_ns) / 1e9)

            time.sleep(1e-6)

    def _recv_packet(self, data: bytes) -> RTPPacket | None:
        """Parses a received packet and writes it to the input stream buffer."""
        packet: RTPPacket = RTPPacket.parse(data)

        # sanity check and packet pre-parsing
        if packet.payload_type.payload_type not in self._media_profiles:
            raise RTPParseError(f"Unexpected payload type {packet.payload_type}")

        try:
            recvd_packet = self._recv_to_stream(packet)
        except RTPBrokenStreamError as e:
            _logger.debug(str(e))
            # FIXME: decide whether we should do something else here?
            #        somehow raise outside the thread? set some err flag?
            del self._recv_streams[packet.ssrc]
            recvd_packet = self._recv_to_stream(packet)

        # cleanup dead streams  # TODO: check. This assumes all streams share the same sequence
        max_sequence = max(stream.sequence for stream in self._recv_streams.values())
        for ssrc, stream in list(self._recv_streams.items()):
            if stream.sequence < max_sequence - stream.max_pending:
                # broken stream
                _logger.debug(f"RTP stream (SSRC={ssrc}) broken, untracking")
                del self._recv_streams[ssrc]

        return recvd_packet

    def _recv_to_stream(self, packet: RTPPacket) -> RTPPacket | None:
        """Writes a received RTP packet into the appropriate input stream."""
        if packet.ssrc not in self._recv_streams:
            self._recv_streams[packet.ssrc] = self._create_recv_stream()

        recv_stream = self._recv_streams[packet.ssrc]

        if recv_stream.profile is None or packet.payload_type == recv_stream.profile:
            recv_stream.write_packet(packet)
        else:  # FIXME: kinda hacky, should probably happen somewhere else?
            assert isinstance(packet.payload_type.payload_type, int)
            profile = self._media_profiles[packet.payload_type.payload_type]
            if profile.encoding_name == RTPMediaProfiles.TELEPHONE_EVENT.encoding_name:
                self._handle_telephone_event(packet)
                if packet.ssrc == recv_stream.ssrc:
                    recv_stream.sequence = packet.sequence
                    recv_stream.timestamp = packet.timestamp
            else:
                raise RTPUnhandledPayload(
                    f"Unhandled or unexpected payload type {packet.payload_type}"
                )

        return packet

    def _send_loop(self) -> None:
        """Sends pending data in the output stream buffer, until the client is closed."""
        assert self._socket is not None
        assert self._remote_addr is not None

        packet_data = dict(
            version=2,
            padding=False,
            extension=False,
            csrc_count=0,
            marker=False,  # FIXME: should this be set? if so when? how?
        )

        while not self._closing_event.is_set():
            pre_send_time_ns: int = self._last_send_time_ns or time.perf_counter_ns()

            packet: RTPPacket | None = self._send_stream.read_packet(packet_data)
            if packet is not None:
                try:
                    self._socket.sendto(packet.serialize(), self._remote_addr)
                except Exception:
                    _logger.exception(
                        f"Error sending RTP packet to {self._remote_addr}"
                    )
                    raise

            post_send_time_ns: int = time.perf_counter_ns()
            send_time: float = (post_send_time_ns - pre_send_time_ns) / 1e9
            if packet is not None:
                self._send_stats.add(packet, send_time)
            packet_duration: float = packet.duration if packet else 0.0
            sleep_time: float = max(0.0, max(1 / 96_000, packet_duration) - send_time)
            self._last_send_time_ns = post_send_time_ns
            time.sleep(sleep_time * self._send_delay_factor)

    def read(self, size: int = RTPStreamBuffer.DEFAULT_SIZE) -> bytes:
        """
        Read raw (encoded) data from the incoming RTP stream.
        If no data is available, will return an empty bytes object.

        :param size: The maximum number of bytes to read.
        """
        if not self._recv_streams:
            return b""
        if len(self._recv_streams) > 1:
            # FIXME: handle multiplexed streams
            raise NotImplementedError(
                "Reading a single stream from multiple streams is not supported"
            )

        stream = next(iter(self._recv_streams.values()))
        return stream.read(size)

    def _mix_recv_audio_streams(
        self, size: int = RTPStreamBuffer.DEFAULT_SIZE
    ) -> NDArray[np.float32]:
        """If there are multiple active recv streams we need to mix them together."""
        mix_buf: NDArray[np.float32] = np.ndarray([], dtype=np.float32)

        if not self._recv_streams:
            return mix_buf
        elif len(self._recv_streams) == 1:
            stream = next(iter(self._recv_streams.values()))
            return stream.read_audio(size)

        # FIXME: assumes PCMA/PCMU streams, 160 bytes, 20ms packets
        min_offset: int = RTPStreamBuffer.SEQUENCE_MAX * 160
        max_offset: int = 0
        streams_timeline: list[tuple[RTPStreamBuffer, int, int]] = []
        for stream in self._recv_streams.values():
            if (
                stream.pending_count
            ):  # cannot mix streams with pending packets, must wait
                assert mix_buf.size == 0
                return mix_buf
            end_offset = stream.sequence * 160
            start_offset = end_offset - stream.buffer_len
            streams_timeline.append((stream, start_offset, end_offset))
            min_offset = min(min_offset, start_offset)
            max_offset = max(max_offset, end_offset)
            # FIXME: handle sequence wrap-around somehow

        buf_size: int = max(0, min(max_offset - min_offset, size))
        if buf_size < 0:
            _logger.debug(f"RTP mix: buffer size is negative ({buf_size})")
            buf_size = 0
        if not buf_size:
            return mix_buf
        mix_buf = np.zeros(buf_size, dtype=np.float32)
        for stream, start_offset, end_offset in streams_timeline:
            mix_offset = start_offset - min_offset
            read_size = min(buf_size - mix_offset, end_offset - start_offset)
            if read_size > 0:
                mix_buf[mix_offset : mix_offset + read_size] += stream.read_audio(
                    read_size
                )

        return mix_buf

    def read_audio(
        self, size: int = RTPStreamBuffer.DEFAULT_SIZE
    ) -> NDArray[np.float32]:
        """
        Read audio data from the incoming RTP stream, decoded with the appropriate codec,
        into a float32 numpy array in the range [-1, 1].
        The rate is unchanged, so the same as the stream profile.
        If no data is available, will return an empty numpy array.

        :param size: The maximum number of bytes to read.
        :raises RTPUnsupportedCodec: If the codec is not supported.
        """
        return self._mix_recv_audio_streams(size)

    def _handle_telephone_event(self, packet: RTPPacket) -> None:
        """Handles telephone event packets."""
        DTMFEvent.parse(packet.payload)
        # TODO: implement

    def write(self, data: bytes) -> int:
        """
        Write raw (encoded) data to the outgoing RTP stream.
        Returns the number of bytes written.

        :param data: The encoded data to write.
        """
        return self._send_stream.write(data)

    def write_audio(self, data: NDArray[np.float32]) -> int:
        """
        Write audio data to the outgoing RTP stream, encoded with the appropriate codec,
        given a float32 numpy array in the range [-1, 1].
        The rate is fed unchanged, so it must match the stream's profile.
        Returns the number of bytes written.

        :param data: The data to write.
        :raises RTPUnsupportedCodec: If the codec is not supported.
        """
        return self._send_stream.write_audio(data)
