from __future__ import annotations

import enum
import time
from contextlib import contextmanager
from dataclasses import replace as dataclass_replace, field as dataclass_field
from typing import (
    Union,
    Optional,
    TYPE_CHECKING,
    Any,
    ClassVar,
    List,
    Iterator,
    Type,
    Callable,
)


try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

import numpy as np
from cbitstruct import CompiledFormat

from ..codecs import Codec, PCMUCodec, PCMACodec
from ..constants import SUPPORTED_RTP_VERSIONS
from ..helpers import FieldsEnum, dataclass, FieldsEnumDatatype
from ..exceptions import RTPUnsupportedCodec, RTPUnsupportedVersion

if TYPE_CHECKING:
    from dataclasses import dataclass


class RTPMediaType(enum.Enum):
    AUDIO = "audio"
    VIDEO = "video"
    AUDIO_VIDEO = "audio,video"


@dataclass(slots=True)
class RTPMediaFormat(FieldsEnumDatatype):
    payload_type: Union[int, str]
    media_type: RTPMediaType
    encoding_name: str
    clock_rate: int
    channels: Optional[int] = None
    format_specific_parameters: Optional[str] = None

    codec_type: Optional[Type[Codec]] = None
    codec: Optional[Codec] = None

    def __post_init__(self):
        if self.codec is None and self.codec_type is not None:
            self.codec = self.codec_type()
        elif self.codec_type is None:
            self.codec_type = type(self.codec)

    @property
    def enum_value(self) -> Any:
        return self.payload_type

    @property
    def mimetype(self) -> str:  # TODO: is this correct?
        return f"{self.media_type.value}/{self.encoding_name}".lower()

    def encode(self, data: np.ndarray) -> bytes:
        """Encode float32 audio in the [-1, 1] range to bytes."""
        if self.codec is None:
            raise RTPUnsupportedCodec(f"No codec set for this media format: {self!r}")
        return self.codec.encode(data)

    def decode(self, data: bytes) -> np.ndarray:
        """Decode bytes to float32 audio in the [-1, 1] range."""
        if self.codec is None:
            raise RTPUnsupportedCodec(f"No codec set for this media format: {self!r}")
        return self.codec.decode(data)


UNKNOWN_FORMAT = RTPMediaFormat("unknown", RTPMediaType.AUDIO_VIDEO, "unknown", 0)

# TODO: implement enum matching on multiple fields (i.e. composite _value_), using a separate cls var


class RTPMediaProfiles(FieldsEnum):
    __wrapped_type__ = RTPMediaFormat
    __allow_unknown__ = True

    # FIXME: should this be int only? (same in RTPMediaFormat)
    payload_type: Union[int, str]
    media_type: RTPMediaType
    encoding_name: str
    clock_rate: int
    channels: Optional[int]
    format_specific_parameters: Optional[str]
    codec_type: Optional[Type[Codec]]
    codec: Optional[Codec]

    mimetype: str
    encode: Callable[[np.ndarray], bytes]
    decode: Callable[[bytes], np.ndarray]

    @classmethod
    def match(
        cls,
        payload_type: Union[int, str, None] = None,
        media_format: Optional[RTPMediaFormat] = None,
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
        if payload_type is None and media_format is None:
            raise ValueError("One of `payload_type` or `media_format` must be provided")

        payload_type_raw = (
            payload_type if payload_type is not None else media_format.payload_type
        )

        media_profile: Optional[RTPMediaProfiles] = None
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
        return self._wrapped_value_

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


@dataclass(slots=True)
class RTPPacket:
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
    csrc: List[int] = dataclass_field(default_factory=list)
    ext_id: int = 0
    ext_len: int = 0
    ext_data: bytes = b""
    # data
    payload: bytes = b""

    _format_u64: ClassVar[CompiledFormat] = CompiledFormat("u2b1b1u4b1u7u16u32u32")
    _ext_header_u32: ClassVar[CompiledFormat] = CompiledFormat("u16u16")

    @classmethod
    def calc_header_len(cls, csrc_count: int, extension: bool, ext_len: int) -> int:
        extension_len: int = (
            cls._ext_header_u32.calcsize() // 8 + ext_len * 4 if extension else 0
        )
        return cls._format_u64.calcsize() // 8 + csrc_count * 4 + extension_len

    @property
    def duration(self) -> float:
        """Duration of the packet in seconds. Supports only PCMU and PCMA."""
        if self.payload_type in (RTPMediaProfiles.PCMU, RTPMediaProfiles.PCMA):
            return len(self.payload) / self.payload_type.clock_rate
        raise NotImplementedError

    @classmethod
    def parse(cls, data: bytes) -> Self:
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

    def serialize(self) -> bytes:
        header_data = self._format_u64.pack(
            self.version,
            self.padding,
            self.extension,
            self.csrc_count,
            self.marker,
            self.payload_type.value,
            self.sequence,
            self.timestamp,
            self.ssrc,
        )
        if self.csrc_count:
            header_data += b"".join(int.to_bytes(csrc, 4, "big") for csrc in self.csrc)
        if self.extension:
            header_data += self._ext_header_u32.pack(self.ext_id, self.ext_len)
            header_data += self.ext_data
        return header_data + self.payload

    @property
    def header_len(self) -> int:
        return self.calc_header_len(self.csrc_count, self.extension, self.ext_len)

    def __len__(self) -> int:
        return self.header_len + len(self.payload)


class RTPPacketsStats:
    def __init__(self):
        self.count: int = 0
        self.bytes: int = 0
        self.duration: int = 0
        self.time: float = 0.0
        self.unimplemented: int = 0

    def add(self, packet: RTPPacket, elapsed: float):
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
        start_time: int = time.perf_counter_ns()
        yield self
        end_time: int = time.perf_counter_ns()
        self.add(packet, (end_time - start_time) / 1e9)

    @property
    def count_per_sec(self) -> float:
        return (self.time and (self.count / self.time)) or 0

    @property
    def bytes_per_sec(self) -> float:
        return (self.time and (self.bytes / self.time)) or 0

    @property
    def realtime_factor(self) -> float:
        return (self.time and (self.duration / self.time)) or 0

    def format(self) -> str:
        return (
            f"{self.count} packets, {self.bytes_per_sec/(1024**2):,.2f} MB/s, "
            f"{self.count_per_sec:,.2f} packets/s, {self.realtime_factor:,.2f}x realtime"
        )

    def __bool__(self) -> bool:
        return self.time > 0

    def __add__(self, other) -> RTPPacketsStats:
        if not isinstance(other, RTPPacketsStats):
            return NotImplemented

        new = RTPPacketsStats()
        new.count = self.count + other.count
        new.bytes = self.bytes + other.bytes
        new.duration = self.duration + other.duration
        new.time = self.time + other.time
        new.unimplemented = self.unimplemented + other.unimplemented
        return new

    def __iadd__(self, other) -> Self:
        if not isinstance(other, RTPPacketsStats):
            return NotImplemented

        self.count += other.count
        self.bytes += other.bytes
        self.duration += other.duration
        self.time += other.time
        self.unimplemented += other.unimplemented
        return self


class DTMFEventCode(enum.IntEnum):
    DIGIT_0 = 0
    DIGIT_1 = 1
    DIGIT_2 = 2
    DIGIT_3 = 3
    DIGIT_4 = 4
    DIGIT_5 = 5
    DIGIT_6 = 6
    DIGIT_7 = 7
    DIGIT_8 = 8
    DIGIT_9 = 9
    STAR = 10
    ASTERISK = STAR
    POUND = 11
    HASH = POUND
    A = 12
    B = 13
    C = 14
    D = 15


@dataclass(slots=True)
class DTMFEvent:
    """Represents a DTMF event as defined in RFC 4733."""

    event_code: DTMFEventCode
    end_of_event: bool
    volume: int
    duration: int

    _format_u32: ClassVar[CompiledFormat] = CompiledFormat("u8b1b1u6u16")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        event_raw, end_of_event, r, volume_raw, duration = cls._format_u32.unpack(data)
        event_code = DTMFEventCode(event_raw)
        assert r == 0
        volume = -volume_raw
        return cls(event_code, end_of_event, volume, duration)

    def serialize(self) -> bytes:
        return self._format_u32.pack(
            self.event_code.value, self.end_of_event, 0, -self.volume, self.duration
        )
