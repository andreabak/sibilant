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
    Callable,
    Collection,
    Literal,
    Mapping,
    NamedTuple,
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
from sibilant.helpers import db_to_amplitude

from .dtmf import DTMFCode, DTMFEvent, generate_dtmf
from .packet import (
    RTPMediaFormat,
    RTPMediaProfiles,
    RTPMediaType,
    RTPPacket,
    RTPPacketsStats,
)


if TYPE_CHECKING:
    from numpy.typing import NDArray


_logger = logging.getLogger(__name__)


class TimedBufferChunk(NamedTuple):
    """
    A chunk of raw bytes data, with a timestamp representing its end time.

    N.B. the timestamp has no particular reference, and is meaningful only if used
    in a specific context (e.g. RTP stream).
    """

    data: bytes
    timestamp: int


class TimedAudioChunk(NamedTuple):
    """
    A chunk of audio frames, with a timestamp representing its end time.

    N.B. the timestamp has no particular reference, and is meaningful only if used
    in a specific context (e.g. RTP stream).
    """

    data: NDArray[np.float32]
    timestamp: int


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
    DONE_EVENT_DISCARD_TS_DELTA: int = DEFAULT_SIZE * 12

    # TODO: maybe rename modes to send/recv instead of r/w?
    #       otherwise, since they're doing completely different things,
    #       maybe we should split this class into two (+ a base class)?
    def __init__(  # noqa: PLR0913
        self,
        mode: Literal["r", "w"],
        *,
        ssrc: int | None = None,
        profile: RTPMediaProfiles | None = None,
        initial_sequence: int | None = None,
        initial_timestamp: int | None = None,
        event_profile: RTPMediaProfiles | None = None,
        event_profiles: Mapping[int, RTPMediaProfiles] | None = None,
        dtmf_max_duration: float = 0.15,
        dtmf_volume_gain: float = -3.0,
        dtmf_volume_default: float = -10.0,
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
        self._timed_buffer: deque[TimedBufferChunk] = deque()
        self._last_read_timestamp: int | None = None
        self._last_write_timestamp: int | None = None
        self._pending: deque[RTPPacket] = deque()
        self._buf_lock: threading.RLock = threading.RLock()

        self._event_profile: RTPMediaProfiles | None = event_profile
        self._event_profiles: dict[int, RTPMediaProfiles] = dict(event_profiles or ())
        self._events_codes_pending: dict[int, DTMFCode] = {}
        self._events_start_timestamp: dict[int, int] = {}
        self._events_active: dict[int, DTMFEvent] = {}
        self._events_done: dict[int, DTMFEvent] = {}
        self.dtmf_max_duration: float = dtmf_max_duration
        self.dtmf_volume_gain: float = dtmf_volume_gain
        self.dtmf_volume_default: float = dtmf_volume_default

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
        self._gen_count: int = 0
        """Generated packets count: packets created from the buffer."""

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
        return sum(len(i.data) for i in self._timed_buffer)

    def read_timed(self, size: int = DEFAULT_SIZE) -> TimedBufferChunk | None:
        """
        Read up to ``size`` contiguous timed chunks from the buffer,
        if size is -1, read all available contiguous chunks.

        Will not return chunks that are not time-contiguous.
        """
        with self._buf_lock:
            size = self.buffer_len if size == -1 else min(size, self.buffer_len)

            data = b""
            while size > 0:
                item = self._timed_buffer.popleft()
                chunk_size = len(item.data)
                # FIXME: hack that works for PCMU/PCMA, as timestamp unit == 1 sample == 1 byte
                is_contiguous = self._last_read_timestamp is None or (
                    self._last_read_timestamp + chunk_size == item.timestamp
                )
                if data and not is_contiguous:  # break on non-contiguous chunk
                    self._timed_buffer.appendleft(item)
                    break
                if chunk_size <= size:
                    data += item.data
                    self._last_read_timestamp = item.timestamp
                    size -= chunk_size
                else:
                    data += item.data[:size]
                    # FIXME: PCMU/PCMA timestamp hack
                    self._last_read_timestamp = item.timestamp - size
                    self._timed_buffer.appendleft(
                        TimedBufferChunk(
                            data=item.data[size:], timestamp=item.timestamp
                        )
                    )
                    size = 0

            if not data:
                return None
            else:
                assert self._last_read_timestamp is not None
                return TimedBufferChunk(data=data, timestamp=self._last_read_timestamp)

    def read_timed_audio(self, size: int = DEFAULT_SIZE) -> TimedAudioChunk | None:
        """
        Read timed contiguous audio data from the buffer,
        decoded with the appropriate codec,
        into a chunk wiht float32 numpy array in the range [-1, 1] with its end timestamp.
        The rate is unchanged, so the same as the stream's profile.
        If no data is available, will return None.

        :param size: The maximum number of bytes to read.
        :raises RTPUnsupportedCodec: If the codec is not supported.
        """
        chunk = self.read_timed(size)
        if not chunk:
            return None
        if self._profile is None:
            raise ValueError("Stream has no profile set, cannot decode audio")
        if self._profile.media_type != RTPMediaType.AUDIO:
            raise ValueError("Can only read audio from a stream with audio profile")
        decoded = self._profile.decode(chunk.data)
        return TimedAudioChunk(data=decoded, timestamp=chunk.timestamp)

    def read(self, size: int = DEFAULT_SIZE) -> bytes:
        """
        Read up to ``size`` contiguous bytes from the buffer,
        if size is -1, read all available contiguous bytes.

        Will not return data that's not time-contiguous.
        """
        chunk = self.read_timed(size)
        return chunk.data if chunk else b""

    def read_audio(self, size: int = DEFAULT_SIZE) -> NDArray[np.float32]:
        """
        Read audio data from the buffer, decoded with the appropriate codec,
        into a float32 numpy array in the range [-1, 1].
        The rate is unchanged, so the same as the stream's profile.
        If no data is available, will return an empty numpy array.

        :param size: The maximum number of bytes to read.
        :raises RTPUnsupportedCodec: If the codec is not supported.
        """
        timed_audio = self.read_timed_audio(size)
        if not timed_audio:
            return np.zeros(0, dtype=np.float32)
        if self._profile is None:
            raise ValueError("Stream has no profile set, cannot decode audio")
        if self._profile.media_type != RTPMediaType.AUDIO:
            raise ValueError("Can only read audio from a stream with audio profile")
        return timed_audio.data

    def _generate_packet(
        self,
        defaults: Mapping[str, Any],
        data: bytes,
        *,
        timestamp: int | None = None,
        ts_delta: int | None = None,
        **overrides: Any,
    ) -> RTPPacket:
        if ts_delta is None:
            # FIXME: depends on profile, this hack works for PCMA/PCMU
            ts_delta = len(data)
        if timestamp and ts_delta:
            raise RuntimeError("Cannot specify both timestamp and ts_delta")
        if timestamp is None:
            timestamp = self.timestamp
        self.sequence = (self.sequence + 1) % self.SEQUENCE_MAX
        self.timestamp = (timestamp + ts_delta) % self.TIMESTAMP_MAX
        values = dict(
            defaults,
            payload_type=self._profile,
            ssrc=self.ssrc,
            sequence=self.sequence,
            timestamp=self.timestamp,
            payload=data,
        )
        values.update(overrides)
        packet = RTPPacket(**values)
        self._gen_count += 1
        return packet

    def _generate_next_dtmf_packets(
        self, defaults: Mapping[str, Any], duration_increase: int
    ) -> list[RTPPacket]:
        assert (
            self._event_profile is not None
        ), "can't generate DTMF without an event profile"
        assert (
            self._events_active or self._events_codes_pending
        ), "no dtmf active or pending"

        packets_to_send = []
        # get the first active or pending event if multiple
        timestamp, last_dtmf_or_code = min(
            {**self._events_active, **self._events_codes_pending}.items()
        )

        if isinstance(last_dtmf_or_code, DTMFCode):
            assert timestamp in self._events_codes_pending
            self._events_codes_pending.pop(timestamp)
            last_dtmf_code = last_dtmf_or_code
            last_dtmf = DTMFEvent(
                event_code=last_dtmf_code,
                end_of_event=False,
                volume=int(self.dtmf_volume_default),
                duration=0,
            )
            packets_to_send.append(
                self._generate_packet(
                    defaults,
                    last_dtmf.serialize(),
                    timestamp=timestamp,
                    ts_delta=0,
                    payload_type=self._event_profile,
                    marker=True,
                    _duration_override=0.0,
                )
            )
        else:
            assert isinstance(last_dtmf_or_code, DTMFEvent)
            last_dtmf = last_dtmf_or_code

        new_duration = last_dtmf.duration + duration_increase
        new_duration_secs = new_duration / self._event_profile.clock_rate
        end_of_event = new_duration_secs > self.dtmf_max_duration
        dtmf = DTMFEvent(
            event_code=last_dtmf.event_code,
            end_of_event=end_of_event,
            volume=last_dtmf.volume,
            duration=new_duration,
        )

        if not end_of_event:
            self._events_active[timestamp] = dtmf
        else:
            self._events_active.pop(timestamp, None)
            self._events_done[timestamp] = dtmf
            self.timestamp += dtmf.duration
        packets_to_send.extend(
            self._generate_packet(
                defaults,
                dtmf.serialize(),
                timestamp=timestamp,
                ts_delta=0,
                payload_type=self._event_profile,
                _duration_override=duration_increase / self._event_profile.clock_rate,
            )
            for _ in range(3 if end_of_event else 1)
        )
        return packets_to_send

    def read_packets(
        self, defaults: Mapping[str, Any], size: int = DEFAULT_SIZE
    ) -> list[RTPPacket]:
        """
        Read up to size bytes from the buffer, and return a packet with the given values.
        N.B. payload, payload_type, ssrc, sequence, and timestamp will be overwritten.
        """
        if self._mode != "r":
            raise ValueError("Can only read packets in mode='r'")

        assert self.ssrc is not None

        if self._profile is None:
            raise ValueError("Stream has no profile set, cannot generate packet")

        with self._buf_lock:
            chunk = self.read_timed(size)
            if not chunk:
                return []

        self._discard_old_events()
        if self._events_codes_pending or self._events_active:
            # audio data will be discarded
            return self._generate_next_dtmf_packets(defaults, len(chunk.data))
        else:
            return [
                self._generate_packet(
                    defaults, chunk.data, timestamp=chunk.timestamp, ts_delta=0
                )
            ]

    def write_timed(self, data: bytes | Buffer, timestamp: int) -> int:
        """
        Write timed data to the buffer, and return the number of bytes written.

        The timestamp value must represent the time at the end of the data.
        """
        if isinstance(data, Buffer):
            data = bytes(data)
        with self._buf_lock:
            self._timed_buffer.append(TimedBufferChunk(data=data, timestamp=timestamp))
            self._last_write_timestamp = timestamp
        return len(data)

    def write_timed_audio(self, data: NDArray[np.float32], timestamp: int) -> int:
        """
        Write timed audio data to the buffer, encoded with the appropriate codec,
        given a float32 numpy array in the range [-1, 1].
        The rate is fed unchanged, so it must match the stream's profile.
        Returns the number of bytes written.

        :param data: The data to write.
        :param timestamp: The end timestamp of the data to write.
        :raises RTPUnsupportedCodec: If the codec is not supported.
        """
        if self._profile is None:
            raise ValueError("Stream has no profile set, cannot encode audio")
        if self._profile.media_type != RTPMediaType.AUDIO:
            raise ValueError("Can only write audio to a stream with audio profile")
        return self.write_timed(self._profile.encode(data), timestamp)

    def write(self, data: bytes | Buffer) -> int:
        """Write data to the buffer, and return the number of bytes written."""
        # FIXME: depends on profile, this hack works for PCMA/PCMU
        if isinstance(data, Buffer):
            data = bytes(data)
        timestamp = (self._last_write_timestamp or self.timestamp) + len(data)
        return self.write_timed(data, timestamp)

    def _write_event(self, packet: RTPPacket) -> int:
        assert isinstance(packet.payload_type.payload_type, int)
        event_profile = self._event_profiles[packet.payload_type.payload_type]

        timestamp = packet.timestamp
        dtmf = DTMFEvent.parse(packet.payload)

        last_dtmf: DTMFEvent | None = self._events_active.get(
            timestamp, self._events_done.get(timestamp)
        )
        if not dtmf.end_of_event:
            self._events_active[timestamp] = dtmf
        else:
            self._events_active.pop(timestamp, None)
            self._events_done[timestamp] = dtmf
        if last_dtmf is None:
            # the time of the first dtmf packet will be the end of the first packet duration
            self._events_start_timestamp[timestamp] = packet.timestamp - dtmf.duration

        assert timestamp in self._events_start_timestamp
        start_timestamp = self._events_start_timestamp[timestamp]
        last_dtmf_duration = last_dtmf.duration if last_dtmf is not None else 0
        generate_tone_length: int = dtmf.duration - last_dtmf_duration
        if generate_tone_length > 0:
            rate = event_profile.clock_rate
            gain = db_to_amplitude(self.dtmf_volume_gain) * db_to_amplitude(
                dtmf.volume or self.dtmf_volume_default
            )
            tone_audio = gain * generate_dtmf(
                dtmf.event_code,
                rate=rate,
                length=generate_tone_length,
                offset=last_dtmf_duration,
            )
            if self._profile is None:
                raise ValueError("Stream has no profile set, cannot encode audio")
            return self.write_timed(
                self._profile.encode(tone_audio),
                timestamp=start_timestamp + dtmf.duration,
            )
        return 0

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
            packet_is_event: bool = (
                packet.payload_type.payload_type in self._event_profiles
            )

            if self.ssrc is None:
                self.ssrc = packet.ssrc
                self.sequence = packet.sequence - 1
                if self._profile is None and not packet_is_event:
                    self._profile = packet.payload_type

            if self.ssrc != packet.ssrc:
                raise RTPMismatchedStreamError(
                    f"Packet does not match stream SSRC {self.ssrc} != {packet.ssrc}"
                )

            if not packet_is_event and self._profile != packet.payload_type:
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
                    new_packet_is_event: bool = (
                        new_packet.payload_type.payload_type in self._event_profiles
                    )
                    if new_packet_is_event:
                        written += self._write_event(new_packet)
                    else:
                        written += self.write_timed(
                            new_packet.payload, new_packet.timestamp
                        )
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
                        # FIXME: depends on profile, this hack works for PCMA/PCMU
                        written += self.write_timed(
                            self._lost_filler * self._fill_size,
                            self.timestamp + self._fill_size,
                        )
                        self.sequence += 1  # let the loop figure this out
                        self._lost_count += 1
                    # otherwise, we have lost too many packets, raise an error
                    else:
                        raise RTPBrokenStreamError("Too many lost packets")

                # otherwise, we're missing just a few packets, don't do anything for now
                else:
                    break

        self._discard_old_events()

        return written

    def write_event_packet(self, packet: RTPPacket) -> bool:
        """Write a telephone event packet to the buffer. Return True if it's a newly seen event."""
        assert packet.payload_type.payload_type in self._event_profiles
        is_new_event = packet.timestamp not in (
            self._events_active.keys() | self._events_done.keys()
        )
        self.write_packet(packet)
        return is_new_event

    def generate_dtmf(self, code: DTMFCode) -> None:
        """Schedule generation of a DTMF tone as next packets on the stream."""
        if self._mode != "r":
            raise ValueError("Can only generate DTMF in mode='r'")
        if self._event_profile is None:
            raise ValueError("Stream has no event profile set, cannot generate DTMF")
        self._events_codes_pending[self.timestamp + self.DEFAULT_SIZE] = code

    def _discard_old_events(self) -> None:
        if not self._events_active and not self._events_done:
            return
        timestamps_to_drop: set[int] = {
            timestamp
            for timestamp in self._events_active.keys() | self._events_done.keys()
            if self.timestamp - timestamp
            > (self.DONE_EVENT_DISCARD_TS_DELTA + self.dtmf_max_duration)
        }
        for timestamp in timestamps_to_drop:
            self._events_active.pop(timestamp, None)
            self._events_done.pop(timestamp, None)
            self._events_start_timestamp.pop(timestamp, None)

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
        dtmf_events_callback: Callable[[DTMFCode], None] | None = None,
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

        self.dtmf_events_callback: Callable[[DTMFCode], None] | None = (
            dtmf_events_callback
        )

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
    def event_profiles(self) -> Mapping[int, RTPMediaProfiles]:
        """The media profiles that represent telephone events associated with the client."""
        return {
            payload_type: profile
            for payload_type, profile in self._media_profiles.items()
            if profile.encoding_name == RTPMediaProfiles.TELEPHONE_EVENT.encoding_name
        }

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

        attempt: int = 0
        random_port: bool = self._local_addr[1] == 0
        while True:
            if random_port:
                self._local_addr = (
                    self._local_addr[0],
                    random.randint(*DEFAULT_RTP_PORT_RANGE) // 2 * 2,
                )
            try:
                _socket.bind(self._local_addr)
                break
            except OSError as e:
                if random_port and e.errno == errno.EADDRINUSE:
                    if attempt >= 100:
                        raise ConnectionError(
                            "Failed to bind to RTP port "
                            f"(randomly picked in range {DEFAULT_RTP_PORT_RANGE!r}) "
                            f"after {attempt} attempts"
                        ) from e
                    attempt += 1
                else:
                    raise

        return _socket

    def _create_recv_stream(self) -> RTPStreamBuffer:
        return RTPStreamBuffer(mode="w", event_profiles=self.event_profiles)

    def _create_send_stream(self) -> RTPStreamBuffer:
        return RTPStreamBuffer(
            mode="r",
            event_profile=next(iter(self.event_profiles.values())),
            profile=self._profile,
        )

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
                is_new_event = recv_stream.write_event_packet(packet)
                if is_new_event:
                    self._handle_telephone_event(packet)
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

            packets_max_duration: float = 0.0
            packet: RTPPacket | None = None
            packets: list[RTPPacket] = self._send_stream.read_packets(packet_data)
            for packet in packets:
                try:
                    self._socket.sendto(packet.serialize(), self._remote_addr)
                except Exception:
                    _logger.exception(
                        f"Error sending RTP packet to {self._remote_addr}"
                    )
                    raise
                packets_max_duration = max(packets_max_duration, packet.duration)

            post_send_time_ns: int = time.perf_counter_ns()
            send_time: float = (post_send_time_ns - pre_send_time_ns) / 1e9
            if packet is not None:  # count only the last packet
                self._send_stats.add(packet, send_time)
            sleep_time: float = max(
                0.0, max(1 / 96_000, packets_max_duration) - send_time
            )
            self._last_send_time_ns = post_send_time_ns
            time.sleep(sleep_time * self._send_delay_factor)

    def _get_read_stream(self) -> RTPStreamBuffer | None:
        if not self._recv_streams:
            return None
        if len(self._recv_streams) > 1:
            # FIXME: handle multiplexed streams
            raise NotImplementedError(
                "Reading a single stream from multiple streams is not supported"
            )
        return next(iter(self._recv_streams.values()))

    def read_timed(
        self, size: int = RTPStreamBuffer.DEFAULT_SIZE
    ) -> TimedBufferChunk | None:
        """
        Read contiguous timed raw (encoded) data chunks from the incoming RTP stream.
        If no data is available, will return None.

        :param size: The maximum number of bytes to read.
        """
        stream = self._get_read_stream()
        return stream.read_timed(size) if stream is not None else None

    def read_timed_audio(
        self, size: int = RTPStreamBuffer.DEFAULT_SIZE
    ) -> TimedAudioChunk | None:
        """
        Read contiguous audio data from the incoming RTP stream,
        decoded with the appropriate codec,
        into a chunk wiht float32 numpy array in the range [-1, 1] with its end timestamp.
        The rate is unchanged, so the same as the stream profile.
        If no data is available, will return an empty numpy array.

        :param size: The maximum number of bytes to read.
        :raises RTPUnsupportedCodec: If the codec is not supported.
        """
        if not self._recv_streams:
            return None
        elif len(self._recv_streams) == 1:
            stream = self._get_read_stream()
            return stream.read_timed_audio(size) if stream is not None else None
        else:
            raise NotImplementedError(
                "Reading timed audio from multiple incoming streams is not yet implemented."
            )

    def read(self, size: int = RTPStreamBuffer.DEFAULT_SIZE) -> bytes:
        """
        Read raw (encoded) data from the incoming RTP stream.
        If no data is available, will return an empty bytes object.

        :param size: The maximum number of bytes to read.
        """
        stream = self._get_read_stream()
        return stream.read(size) if stream is not None else b""

    def _mix_recv_audio_streams(
        self, size: int = RTPStreamBuffer.DEFAULT_SIZE
    ) -> NDArray[np.float32]:
        """If there are multiple active recv streams we need to mix them together."""
        mix_buf: NDArray[np.float32] = np.ndarray((0,), dtype=np.float32)

        if not self._recv_streams:
            return mix_buf
        elif len(self._recv_streams) == 1:
            stream = self._get_read_stream()
            return stream.read_audio(size) if stream is not None else mix_buf

        # FIXME: rewrite the following code, it should be using timestamps
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
        """Handle telephone event packets."""
        if self.dtmf_events_callback is not None:
            dtmf = DTMFEvent.parse(packet.payload)
            self.dtmf_events_callback(dtmf.event_code)

    def write_timed(self, data: bytes, timestamp: int) -> int:
        """
        Write timed raw (encoded) data to the outgoing RTP stream.
        Returns the number of bytes written.

        :param data: The encoded data to write.
        :param timestamp: The time at the end of the data.
        """
        return self._send_stream.write_timed(data, timestamp)

    def write_timed_audio(self, data: NDArray[np.float32], timestamp: int) -> int:
        """
        Write timed audio data to the outgoing RTP stream, encoded with the appropriate codec,
        given a float32 numpy array in the range [-1, 1].
        The rate is fed unchanged, so it must match the stream's profile.
        Returns the number of bytes written.

        :param data: The data to write.
        :param timestamp: The time at the end of the data.
        :raises RTPUnsupportedCodec: If the codec is not supported.
        """
        return self._send_stream.write_timed_audio(data, timestamp)

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

    def write_dtmf(self, code: DTMFCode) -> None:
        """Write a DTMF code to the send stream."""
        self._send_stream.generate_dtmf(code)
