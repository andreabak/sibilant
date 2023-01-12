from __future__ import annotations

import enum
import time
from contextlib import contextmanager
from dataclasses import replace as dataclass_replace, field as dataclass_field
from typing import Union, Optional, TYPE_CHECKING, Any, ClassVar, List, Iterator

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

from cbitstruct import CompiledFormat

from ..helpers import FieldsEnum, dataclass, FieldsEnumDatatype

if TYPE_CHECKING:
    from dataclasses import dataclass


class RTPMediaType(enum.Flag):
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

    @property
    def mimetype(self) -> str:  # TODO: is this correct?
        return f"{self.media_type.value}/{self.encoding_name}".lower()

    @property
    def enum_value(self) -> Any:
        return self.payload_type


UNKNOWN_FORMAT = RTPMediaFormat("unknown", RTPMediaType.AUDIO_VIDEO, "unknown", 0)

# TODO: implement enum matching on multiple fields (i.e. composite _value_), using a separate cls var


class RTPMediaProfiles(FieldsEnum):
    __wrapped_type__ = RTPMediaFormat
    __allow_unknown__ = True

    payload_type: Union[int, str]
    media_type: RTPMediaType
    encoding_name: str
    clock_rate: int
    channels: Optional[int]
    format_specific_parameters: Optional[str]

    # TODO: add custom _missing_ make it so we match profiles where some fields are None by default, but actual packet specifies something

    # audio
    PCMU = RTPMediaFormat(0, RTPMediaType.AUDIO, "PCMU", 8000, 1)
    GSM = RTPMediaFormat(3, RTPMediaType.AUDIO, "GSM", 8000, 1)
    G723 = RTPMediaFormat(4, RTPMediaType.AUDIO, "G723", 8000, 1)
    DVI4_8000 = RTPMediaFormat(5, RTPMediaType.AUDIO, "DVI4", 8000, 1)
    DVI4_16000 = RTPMediaFormat(6, RTPMediaType.AUDIO, "DVI4", 16000, 1)
    LPC = RTPMediaFormat(7, RTPMediaType.AUDIO, "LPC", 8000, 1)
    PCMA = RTPMediaFormat(8, RTPMediaType.AUDIO, "PCMA", 8000, 1)
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
        # check if payload_type_raw is a known profile
        try:
            payload_type = RTPMediaProfiles(payload_type_raw)
        except (TypeError, ValueError):
            payload_type = RTPMediaProfiles(
                dataclass_replace(UNKNOWN_FORMAT, payload_type=payload_type_raw)
            )

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
