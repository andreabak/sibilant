import random
import threading
import time
from io import RawIOBase
from collections import deque
from typing import IO, Deque, Optional, Mapping, Any, Union

from .packet import RTPPacket
from ..exceptions import RTPBrokenStreamError, RTPMismatchedStreamError


class RTPStreamBuffer(RawIOBase, IO):
    """
    A buffer for RTP packets. It keeps track of data and timestamps offset.
    Use a deque to implement a bytes circular buffer, consuming it once read from.
    Also keeps track of the offset of packets, so that we can handle out of order
    ones, we keep them in a separate pending queue, and attempt to rebuild the stream,
    if they're not too late.
    """

    DEFAULT_SIZE: int = 160
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
                if mode == "w"
                else -self.SEQUENCE_MAX
            )
        if initial_timestamp is None:
            initial_timestamp = (
                int(time.monotonic() * 1000) % self.TIMESTAMP_MAX
                if mode == "w"
                else -self.TIMESTAMP_MAX
            )

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
    ) -> RTPPacket:
        """
        Read up to size bytes from the buffer, and return a packet with the given values.
        N.B. payload, sequence, and timestamp will be overwritten.
        """
        if self._mode != "r":
            raise ValueError("Cannot read packets in mode='w'")

        if not isinstance(packet, (Mapping, RTPPacket)):
            raise TypeError(f"Expected a mapping or RTPPacket, got {type(packet)}")

        with self._buf_lock:
            data = self.read(size)
            self.sequence = (self.sequence + 1) % self.SEQUENCE_MAX
            self.timestamp = (self.timestamp + size) % self.TIMESTAMP_MAX

        if isinstance(packet, Mapping):
            packet = RTPPacket(**packet)
        assert isinstance(packet, RTPPacket)
        packet.payload = data
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
        if self._mode != "r":
            raise ValueError("Cannot write packets in mode='r'")

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
