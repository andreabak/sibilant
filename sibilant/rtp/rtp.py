from __future__ import annotations

import enum
from dataclasses import replace as dataclass_replace
from typing import Union, Optional, TYPE_CHECKING, Any, ClassVar, List

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

from cbitstruct import CompiledFormat

from ..helpers import FieldsEnum, dataclass, FieldsEnumDatatype
from ..exceptions import RTPParseException

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
class RTPHeader:
    version: int
    padding: bool
    extension: bool
    csrc_count: int
    marker: bool
    payload_type: RTPMediaProfiles
    sequence_number: int
    timestamp: int
    ssrc: int
    csrc: List[int]
    ext_id: Optional[int] = None
    ext_len: Optional[int] = None
    ext_data: Optional[bytes] = None

    _format_u64: ClassVar[CompiledFormat] = CompiledFormat("u2b1b1u4b1u7u16u32u32")
    _ext_header_u32: ClassVar[CompiledFormat] = CompiledFormat("u16u16")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        (
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type_raw,
            sequence_number,
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
        ext_id, ext_len, ext_data = None, None, None
        if extension:
            extension_offset = csrc_offset + csrc_count * 4
            ext_data = data[extension_offset:]
            ext_id, ext_len = cls._ext_header_u32.unpack(ext_data)
            ext_data = ext_data[cls._ext_header_u32.calcsize() // 8 :]
            if len(ext_data) != ext_len * 4:
                raise RTPParseException(
                    f"Expected {ext_len * 4} bytes of extension data, got {len(ext_data)}"
                )

        return cls(
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc,
            ext_id,
            ext_len,
            ext_data,
        )

    def serialize(self) -> bytes:
        data = self._format_u64.pack(
            self.version,
            self.padding,
            self.extension,
            self.csrc_count,
            self.marker,
            self.payload_type,
            self.sequence_number,
            self.timestamp,
            self.ssrc,
        )
        if self.csrc_count:
            data += b"".join(int.to_bytes(csrc, 4, "big") for csrc in self.csrc)
        if self.extension:
            data += self._ext_header_u32.pack(self.ext_id, self.ext_len)
            data += self.ext_data
        return data

    def __len__(self) -> int:
        extension_len: int = (
            self._ext_header_u32.calcsize() // 8 + len(self.ext_data)
            if self.extension
            else 0
        )
        return self._format_u64.calcsize() // 8 + self.csrc_count * 4 + extension_len


@dataclass(slots=True)
class RTPPacket:
    header: RTPHeader
    payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> Self:
        header = RTPHeader.parse(data)
        payload = data[len(header) :]
        return cls(header, payload)

    def serialize(self) -> bytes:
        return self.header.serialize() + self.payload
