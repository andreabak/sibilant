from __future__ import annotations

from abc import ABC
from dataclasses import field as dataclass_field
from typing import Dict, Optional, List, TYPE_CHECKING
from typing_extensions import Self

from ..exceptions import SDPParseError
from ..helpers import dataclass, IntValueMixin
from ..rtp import RTPMediaType, RTPMediaFormat, MediaFlowType
from .common import (
    SDPField,
    SDPInformationField,
    SDPConnectionField,
    SDPBandwidthField,
    SDPEncryptionField,
    SDPAttribute,
    UnknownAttribute,
    RecvOnlyFlag,
    SendRecvFlag,
    SendOnlyFlag,
    InactiveFlag,
    SDPAttributeField,
    MediaFlowAttribute,
    SDPSection,
    ValueAttribute,
)

if TYPE_CHECKING:
    from dataclasses import dataclass


__all__ = [
    "SDPMediaFields",
    "SDPMediaMedia",
    "SDPMediaTitle",
    "SDPMediaConnection",
    "SDPMediaBandwidth",
    "SDPMediaEncryption",
    "SDPMediaAttribute",
    "UnknownMediaAttribute",
    "RecvOnlyMediaFlag",
    "SendRecvMediaFlag",
    "SendOnlyMediaFlag",
    "InactiveMediaFlag",
    "PTimeAttribute",
    "MaxPTimeAttribute",
    "RTPMapAttribute",
    "FMTPAttribute",
    "SDPMediaAttributeField",
    "get_media_flow_attribute",
    "get_media_flow_type",
    "SDPMedia",
]


@dataclass
class SDPMediaFields(SDPField, ABC, registry=True, registry_attr="_type"):
    ...


@dataclass(slots=True)
class SDPMediaMedia(SDPMediaFields):
    """
    SDP media field, defined in :rfc:`4566#section-5.14`.

    Spec::
        m=<media> <port> <proto> <fmt> ...
        m=<media> <port>/<number of ports> <proto> <fmt> ...
    """

    _type = "m"
    _description = "media name and transport address"

    media: str
    port: int
    number_of_ports: Optional[int]
    protocol: str
    formats: List[int]

    def __post_init__(self):
        if self.port % 2 != 0:
            raise SDPParseError(f"Port number must be even (got {self.port})")

    @property
    def rtcp_port(self) -> int:
        return self.port + 1

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        media, ports_spec, protocol, *formats = raw_value.split(" ")
        port, number_of_ports = (
            int(x) if x is not None else None
            for x in (
                ports_spec.split("/") if "/" in ports_spec else (ports_spec, None)
            )
        )
        return cls(
            media=media,
            port=port,
            number_of_ports=number_of_ports,
            protocol=protocol,
            formats=[int(x) for x in formats],
        )

    def serialize(self) -> str:
        formats_joined: str = " ".join(str(x) for x in self.formats)
        return f"{self.media} {self.port} {self.protocol} {formats_joined}"


@dataclass(slots=True)
class SDPMediaTitle(SDPInformationField, SDPMediaFields):
    """
    SDP media title field, defined in :rfc:`4566#section-5.4

    Spec::
        i=<media title>
    """

    _description = "media title"


@dataclass(slots=True)
class SDPMediaConnection(SDPConnectionField, SDPMediaFields):
    """
    SDP media connection field, defined in :rfc:`4566#section-5.7`.

    Spec::
        c=<nettype> <addrtype> <connection-address>
    """

    _description = "connection information -- optional if included at session-level"


@dataclass(slots=True)
class SDPMediaBandwidth(SDPBandwidthField, SDPMediaFields):
    """
    SDP media bandwidth field, defined in :rfc:`4566#section-5.8`.

    Spec::
        b=<bwtype>:<bandwidth>
    """

    _description = "zero or more bandwidth information lines"


@dataclass(slots=True)
class SDPMediaEncryption(SDPEncryptionField, SDPMediaFields):
    """
    SDP media encryption field, defined in :rfc:`4566#section-5.12`.

    Spec::
        k=<method>
        k=<method>:<encryption key>
    """

    _description = "encryption key"


@dataclass
class SDPMediaAttribute(SDPAttribute, ABC, registry=True, registry_attr="_name"):
    ...


@dataclass(slots=True)
class UnknownMediaAttribute(UnknownAttribute, SDPMediaAttribute):
    ...


@dataclass(slots=True)
class RecvOnlyMediaFlag(RecvOnlyFlag, SDPMediaAttribute):
    ...


@dataclass(slots=True)
class SendRecvMediaFlag(SendRecvFlag, SDPMediaAttribute):
    ...


@dataclass(slots=True)
class SendOnlyMediaFlag(SendOnlyFlag, SDPMediaAttribute):
    ...


@dataclass(slots=True)
class InactiveMediaFlag(InactiveFlag, SDPMediaAttribute):
    ...


@dataclass(slots=True)
class PTimeAttribute(IntValueMixin, ValueAttribute, SDPMediaAttribute):
    _name = "ptime"


@dataclass(slots=True)
class MaxPTimeAttribute(IntValueMixin, ValueAttribute, SDPMediaAttribute):
    _name = "maxptime"


@dataclass(slots=True)
class RTPMapAttribute(SDPMediaAttribute):
    """
    SDP media attribute for RTP map, defined in :rfc:`4566#section-6`.

    Spec::
        rtpmap:<payload type> <encoding name>/<clock rate>[/<encoding parameters>]
    """

    _name = "rtpmap"
    _is_flag = False

    payload_type: int
    encoding_name: str
    clock_rate: int
    encoding_parameters: Optional[str] = None

    @classmethod
    def from_raw_value(cls, name: str, raw_value: Optional[str]) -> Self:
        # encoding parameters are optional
        payload_type, encoding = raw_value.split(" ", maxsplit=1)
        encoding_name, clock_rate, *more = encoding.split("/", maxsplit=2)
        encoding_parameters = more[0] if more else None
        return cls(
            payload_type=int(payload_type),
            encoding_name=encoding_name,
            clock_rate=int(clock_rate),
            encoding_parameters=encoding_parameters,
        )

    def serialize(self) -> str:
        data = f"{self.payload_type} {self.encoding_name}/{self.clock_rate}"
        if self.encoding_parameters is not None:
            data += f"/{self.encoding_parameters}"
        return data


@dataclass(slots=True)
class FMTPAttribute(SDPMediaAttribute):
    """
    SDP media attribute for RTP format parameters, defined in :rfc:`4566#section-6`.

    Spec::
        fmtp:<format> <format specific parameters>
    """

    _name = "fmtp"
    _is_flag = False

    format: int
    format_specific_parameters: str

    @classmethod
    def from_raw_value(cls, name: str, raw_value: Optional[str]) -> Self:
        format_, format_specific_parameters = raw_value.split(" ", maxsplit=1)
        return cls(
            format=int(format_),
            format_specific_parameters=format_specific_parameters,
        )

    def serialize(self) -> str:
        return f"{self.format} {self.format_specific_parameters}"


@dataclass(slots=True)
class SDPMediaAttributeField(SDPAttributeField, SDPMediaFields):
    """
    SDP media attribute field, defined in :rfc:`4566#section-5.13`.

    Spec::
        a=<attribute>
        a=<attribute>:<value>
    """

    _attribute_cls = SDPMediaAttribute

    _description = "zero or more media attribute lines"


def get_media_flow_attribute(flow_type: MediaFlowType) -> SDPMediaAttribute:
    return {
        flow_type.SENDRECV: SendRecvMediaFlag,
        flow_type.SENDONLY: SendOnlyMediaFlag,
        flow_type.RECVONLY: RecvOnlyMediaFlag,
        flow_type.INACTIVE: InactiveMediaFlag,
    }[flow_type]()


def get_media_flow_type(
    attributes: List[SDPAttributeField],
) -> Optional[MediaFlowType]:
    media_flow_type: Optional[MediaFlowType] = None
    for attribute_field in attributes:
        if isinstance(attribute_field.attribute, MediaFlowAttribute):
            if media_flow_type is not None:
                raise SDPParseError("Multiple media flow attributes in session")
            media_flow_type = MediaFlowType(attribute_field.attribute.name)
    return media_flow_type


@dataclass(slots=True)
class SDPMedia(SDPSection):
    _fields_base = SDPMediaFields
    _start_field = SDPMediaMedia

    media: SDPMediaMedia
    title: Optional[SDPMediaTitle] = None
    connection: Optional[SDPMediaConnection] = None
    bandwidth: Optional[SDPMediaBandwidth] = None
    encryption: Optional[SDPMediaEncryption] = None
    attributes: List[SDPMediaAttributeField] = dataclass_field(default_factory=list)

    _media_formats: List[RTPMediaFormat] = dataclass_field(default_factory=list)

    def __post_init__(self):
        # make sure number of ports within media and connection match
        if (
            self.connection
            and self.media.number_of_ports != self.connection.number_of_addresses
        ):
            raise SDPParseError(
                "Number of ports in media and connection fields do not match"
            )

        self._media_formats = self._build_media_formats()

    @property
    def media_flow_type(self) -> Optional[MediaFlowType]:
        return get_media_flow_type(self.attributes)

    # FIXME: media formats can be out-of date if something in the class changes. generate on the fly?
    @property
    def media_formats(self) -> List[RTPMediaFormat]:
        return self._media_formats

    def _build_media_formats(self) -> List[RTPMediaFormat]:
        formats: List[RTPMediaFormat] = []
        if self.media.protocol in ("RTP/AVP", "RTP/SAVP"):
            # collect rtpmap and fmtp attributes with the same id as the media formats
            known_formats = {int(f) for f in self.media.formats}
            rtpmap_map: Dict[int, RTPMapAttribute] = {}
            fmtp_map: Dict[int, FMTPAttribute] = {}
            for attribute_field in self.attributes:
                attribute = attribute_field.attribute
                if isinstance(attribute, RTPMapAttribute):
                    if attribute.payload_type not in known_formats:
                        raise SDPParseError(  # TODO: maybe just warn?
                            f"rtpmap attribute refers to unknown format (known: {known_formats}): {attribute.payload_type}"
                        )
                    rtpmap_map[attribute.payload_type] = attribute
                elif isinstance(attribute, FMTPAttribute):
                    if attribute.format not in known_formats:
                        raise SDPParseError(  # TODO: maybe just warn?
                            f"fmtp attribute refers to unknown format (known: {known_formats}): {attribute.format}"
                        )
                    fmtp_map[attribute.format] = attribute

            if unmatched_specific_params := fmtp_map.keys() - rtpmap_map.keys():
                raise SDPParseError(
                    f"fmtp attribute refers to unknown format: {unmatched_specific_params}"
                )

            rtpmap: RTPMapAttribute
            for rtpmap in rtpmap_map.values():
                fmtp: Optional[FMTPAttribute] = fmtp_map.get(rtpmap.payload_type)
                channels: Optional[int] = None
                try:
                    channels = int(rtpmap.encoding_parameters)
                except (ValueError, TypeError):
                    pass
                formats.append(
                    RTPMediaFormat(
                        payload_type=rtpmap.payload_type,
                        media_type=RTPMediaType(self.media.media),
                        encoding_name=rtpmap.encoding_name,
                        clock_rate=rtpmap.clock_rate,
                        channels=channels,
                        format_specific_parameters=fmtp.format_specific_parameters
                        if fmtp
                        else None,
                    )
                )

        return formats
