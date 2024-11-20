"""Classes for RTP packets and related utilities."""

from __future__ import annotations

import enum
import time
from contextlib import contextmanager
from dataclasses import field as dataclass_field, replace as dataclass_replace
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Iterator, cast

from cbitstruct import CompiledFormat
from typing_extensions import Self

from sibilant.codecs import Codec, PCMACodec, PCMUCodec
from sibilant.constants import SUPPORTED_RTP_VERSIONS
from sibilant.exceptions import RTPUnsupportedCodec, RTPUnsupportedVersion
from sibilant.helpers import (
    FieldsEnum,
    FieldsEnumDatatype,
    ParseableSerializableRaw,
    slots_dataclass,
)


if TYPE_CHECKING:
    import numpy as np
    from numpy.typing import NDArray


class RTPMediaType(enum.Enum):
    """The media types of RTP media format."""

    AUDIO = "audio"
    VIDEO = "video"
    AUDIO_VIDEO = "audio,video"


@slots_dataclass
class RTPMediaFormat(FieldsEnumDatatype):
    """Represents an RTP media format type."""

    payload_type: int | str
    media_type: RTPMediaType
    encoding_name: str
    clock_rate: int
    channels: int | None = None
    format_specific_parameters: str | None = None

    codec_type: type[Codec] | None = None
    codec: Codec | None = None

    def __post_init__(self) -> None:
        if self.codec is None and self.codec_type is not None:
            self.codec = self.codec_type()
        elif self.codec_type is None:
            self.codec_type = type(self.codec) if self.codec is not None else None

    @property
    def enum_value(self) -> Any:  # noqa: D102
        return self.payload_type

    @property
    def mimetype(self) -> str:  # TODO: is this correct?
        """The mimetype of the media format."""
        return f"{self.media_type.value}/{self.encoding_name}".lower()

    def encode(self, data: NDArray[np.float32]) -> bytes:
        """Encode float32 audio in the [-1, 1] range to bytes."""
        if self.codec is None:
            raise RTPUnsupportedCodec(f"No codec set for this media format: {self!r}")
        return self.codec.encode(data)

    def decode(self, data: bytes) -> NDArray[np.float32]:
        """Decode bytes to float32 audio in the [-1, 1] range."""
        if self.codec is None:
            raise RTPUnsupportedCodec(f"No codec set for this media format: {self!r}")
        return self.codec.decode(data)


UNKNOWN_FORMAT = RTPMediaFormat("unknown", RTPMediaType.AUDIO_VIDEO, "unknown", 0)

# TODO: implement enum matching on multiple fields (i.e. composite _value_), using a separate cls var


class RTPMediaProfiles(FieldsEnum):
    """The known RTP media profiles."""

    __wrapped_type__ = RTPMediaFormat
    __allow_unknown__ = True

    # FIXME: should this be int only? (same in RTPMediaFormat)
    payload_type: int | str
    media_type: RTPMediaType
    encoding_name: str
    clock_rate: int
    channels: int | None
    format_specific_parameters: str | None
    codec_type: type[Codec] | None
    codec: Codec | None

    mimetype: str
    encode: Callable[[NDArray[np.float32]], bytes]
    decode: Callable[[bytes], NDArray[np.float32]]

    @classmethod
    def match(
        cls,
        payload_type: int | str | None = None,
        media_format: RTPMediaFormat | None = None,
    ) -> RTPMediaProfiles:
        """
        Tries to match a media format to a profile.
        Will try to match the payload type first, then the media format,
        then try to match the encoding name as payload type.
        In case no match is found, the unknown profile is returned.

        :param payload_type: The payload type to match.
        :param media_format: The media format to match.
        :return: The matched or unknown profile.
        """
        payload_type_raw: int | str
        if payload_type is not None:
            payload_type_raw = payload_type
        elif media_format is not None:
            payload_type_raw = media_format.payload_type
        else:
            raise ValueError("One of `payload_type` or `media_format` must be provided")

        media_profile: RTPMediaProfiles | None = None
        try:
            media_profile = RTPMediaProfiles(payload_type_raw)

        except (TypeError, ValueError):
            if isinstance(payload_type_raw, str):
                for known_media_profile in RTPMediaProfiles:
                    if known_media_profile.encoding_name == payload_type_raw:
                        media_profile = known_media_profile
                        break

        if media_profile is None:
            media_profile = RTPMediaProfiles(
                media_format
                or dataclass_replace(UNKNOWN_FORMAT, payload_type=payload_type_raw)
            )
        assert media_profile is not None
        return media_profile

    @property
    def fmt(self) -> RTPMediaFormat:
        """The wrapped media format."""
        return cast(RTPMediaFormat, self._wrapped_value_)

    # TODO: add custom _missing_ make it so we match profiles where some fields are None by default, but actual packet specifies something

    # audio
    PCMU = RTPMediaFormat(0, RTPMediaType.AUDIO, "PCMU", 8000, 1, codec_type=PCMUCodec)
    GSM = RTPMediaFormat(3, RTPMediaType.AUDIO, "GSM", 8000, 1)
    G723 = RTPMediaFormat(4, RTPMediaType.AUDIO, "G723", 8000, 1)
    DVI4_8000 = RTPMediaFormat(5, RTPMediaType.AUDIO, "DVI4", 8000, 1)
    DVI4_16000 = RTPMediaFormat(6, RTPMediaType.AUDIO, "DVI4", 16000, 1)
    LPC = RTPMediaFormat(7, RTPMediaType.AUDIO, "LPC", 8000, 1)
    PCMA = RTPMediaFormat(8, RTPMediaType.AUDIO, "PCMA", 8000, 1, codec_type=PCMACodec)
    G722 = RTPMediaFormat(9, RTPMediaType.AUDIO, "G722", 8000, 1)
    L16_2 = RTPMediaFormat(10, RTPMediaType.AUDIO, "L16", 44100, 2)
    L16 = RTPMediaFormat(11, RTPMediaType.AUDIO, "L16", 44100, 1)
    QCELP = RTPMediaFormat(12, RTPMediaType.AUDIO, "QCELP", 8000, 1)
    CN = RTPMediaFormat(13, RTPMediaType.AUDIO, "CN", 8000, 1)
    MPA = RTPMediaFormat(14, RTPMediaType.AUDIO, "MPA", 90000, None)
    G728 = RTPMediaFormat(15, RTPMediaType.AUDIO, "G728", 8000, 1)
    DVI4_11025 = RTPMediaFormat(16, RTPMediaType.AUDIO, "DVI4", 11025, 1)
    DVI4_22050 = RTPMediaFormat(17, RTPMediaType.AUDIO, "DVI4", 22050, 1)
    G729 = RTPMediaFormat(18, RTPMediaType.AUDIO, "G729", 8000, 1)
    # video
    CELLB = RTPMediaFormat(25, RTPMediaType.VIDEO, "CELLB", 90000, None)
    JPEG = RTPMediaFormat(26, RTPMediaType.VIDEO, "JPEG", 90000, None)
    NV = RTPMediaFormat(28, RTPMediaType.VIDEO, "nv", 90000, None)
    H261 = RTPMediaFormat(31, RTPMediaType.VIDEO, "H261", 90000, None)
    MPV = RTPMediaFormat(32, RTPMediaType.VIDEO, "MPV", 90000, None)
    MP2T = RTPMediaFormat(33, RTPMediaType.AUDIO_VIDEO, "MP2T", 90000, None)
    H263 = RTPMediaFormat(34, RTPMediaType.VIDEO, "H263", 90000, None)
    # misc
    TELEPHONE_EVENT = RTPMediaFormat(
        "telephone-event", RTPMediaType.AUDIO, "telephone-event", 8000, None
    )


@slots_dataclass
class RTPPacket(ParseableSerializableRaw):
    """Implements RTP packets as defined in :rfc:`3550#section-5.1`."""

    # header
    version: int
    padding: bool
    extension: bool
    csrc_count: int
    marker: bool
    payload_type: RTPMediaProfiles
    sequence: int
    timestamp: int
    ssrc: int
    csrc: list[int] = dataclass_field(default_factory=list)
    ext_id: int = 0
    ext_len: int = 0
    ext_data: bytes = b""
    # data
    payload: bytes = b""

    _duration_override: float | None = None

    _format_u64: ClassVar[CompiledFormat] = CompiledFormat("u2b1b1u4b1u7u16u32u32")
    _ext_header_u32: ClassVar[CompiledFormat] = CompiledFormat("u16u16")

    @classmethod
    def calc_header_len(cls, csrc_count: int, extension: bool, ext_len: int) -> int:  # noqa: FBT001
        """Calculate the length of the header in bytes."""
        extension_len: int = (
            cls._ext_header_u32.calcsize() // 8 + ext_len * 4 if extension else 0
        )
        return (
            cast(int, cls._format_u64.calcsize()) // 8 + csrc_count * 4 + extension_len
        )

    @property
    def duration(self) -> float:
        """Duration of the packet in seconds. Supports only PCMU and PCMA."""
        if self._duration_override is not None:
            return self._duration_override
        if self.payload_type in {RTPMediaProfiles.PCMU, RTPMediaProfiles.PCMA}:
            return len(self.payload) / self.payload_type.clock_rate
        raise NotImplementedError

    @classmethod
    def parse(cls, data: bytes) -> Self:  # noqa: PLR0914, D102
        (
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type_raw,
            sequence,
            timestamp,
            ssrc,
        ) = cls._format_u64.unpack(data)

        if version not in SUPPORTED_RTP_VERSIONS:
            raise RTPUnsupportedVersion(f"Unsupported RTP version: {version}")

        payload_type: RTPMediaProfiles = RTPMediaProfiles.match(payload_type_raw)

        csrc = []
        csrc_offset = cls._format_u64.calcsize() // 8
        if csrc_count:
            csrc_data = data[csrc_offset : csrc_offset + csrc_count * 4]
            csrc = [
                int.from_bytes(csrc_data[i : i + 4], "big")
                for i in range(0, len(csrc_data), 4)
            ]
        ext_id, ext_len, ext_data = 0, 0, b""
        if extension:
            ext_offset = csrc_offset + csrc_count * 4
            ext_header_len = cls._ext_header_u32.calcsize() // 8
            ext_header_raw = data[ext_offset : ext_offset + ext_header_len]
            ext_id, ext_len = cls._ext_header_u32.unpack(ext_header_raw)
            ext_data_offset = ext_offset + ext_header_len
            ext_data = data[ext_data_offset : ext_data_offset + ext_len * 4]

        payload_offset = cls.calc_header_len(csrc_count, extension, ext_len)
        payload = data[payload_offset:]

        return cls(
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence,
            timestamp,
            ssrc,
            csrc,
            ext_id,
            ext_len,
            ext_data,
            payload,
        )

    def serialize(self) -> bytes:  # noqa: D102
        header_data: bytes = cast(
            bytes,
            self._format_u64.pack(
                self.version,
                self.padding,
                self.extension,
                self.csrc_count,
                self.marker,
                self.payload_type.value,
                self.sequence,
                self.timestamp,
                self.ssrc,
            ),
        )
        if self.csrc_count:
            header_data += b"".join(int.to_bytes(csrc, 4, "big") for csrc in self.csrc)
        if self.extension:
            header_data += self._ext_header_u32.pack(self.ext_id, self.ext_len)
            header_data += self.ext_data
        return header_data + self.payload

    @property
    def header_len(self) -> int:
        """Length of the header in bytes."""
        return self.calc_header_len(self.csrc_count, self.extension, self.ext_len)

    def __len__(self) -> int:
        return self.header_len + len(self.payload)


class RTPPacketsStats:
    """An analytics utility class that collects statistics about RTP packets."""

    def __init__(self) -> None:
        self.count: int = 0
        self.bytes: int = 0
        self.duration: float = 0
        self.time: float = 0.0
        self.unimplemented: int = 0

    def add(self, packet: RTPPacket, elapsed: float) -> None:
        """Add a packet to the stats."""
        try:
            duration = packet.duration
        except NotImplementedError:
            self.unimplemented += 1
            return
        self.count += 1
        self.time += elapsed
        self.bytes += len(packet.payload)
        self.duration += duration

    @contextmanager
    def track(self, packet: RTPPacket) -> Iterator[Self]:
        """A context manager to track the time taken to process a packet."""
        start_time: int = time.perf_counter_ns()
        yield self
        end_time: int = time.perf_counter_ns()
        self.add(packet, (end_time - start_time) / 1e9)

    @property
    def count_per_sec(self) -> float:
        """Number of packets processed per second."""
        return self.count / self.time if self.time else 0

    @property
    def bytes_per_sec(self) -> float:
        """Number of bytes processed per second."""
        return self.bytes / self.time if self.time else 0

    @property
    def realtime_factor(self) -> float:
        """Realtime factor, i.e. how much faster than realtime the processing was."""
        return self.duration / self.time if self.time else 0

    def format(self) -> str:
        """Format the stats as a string."""
        return (
            f"{self.count} packets, {self.bytes_per_sec / (1024**2):,.2f} MB/s, "
            f"{self.count_per_sec:,.2f} packets/s, {self.realtime_factor:,.2f}x realtime"
        )

    def __bool__(self) -> bool:
        return self.time > 0

    def __add__(self, other: object) -> RTPPacketsStats:
        if not isinstance(other, RTPPacketsStats):
            return NotImplemented

        new = RTPPacketsStats()
        new.count = self.count + other.count
        new.bytes = self.bytes + other.bytes
        new.duration = self.duration + other.duration
        new.time = self.time + other.time
        new.unimplemented = self.unimplemented + other.unimplemented
        return new

    def __iadd__(self, other: object) -> Self:
        if not isinstance(other, RTPPacketsStats):
            return NotImplemented

        self.count += other.count
        self.bytes += other.bytes
        self.duration += other.duration
        self.time += other.time
        self.unimplemented += other.unimplemented
        return self
