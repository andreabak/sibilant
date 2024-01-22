"""SDP media section and related fields definitions and implementations."""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field as dataclass_field
from typing import Sequence

from typing_extensions import Self, override

from sibilant.exceptions import SDPParseError
from sibilant.helpers import IntValueMixin, slots_dataclass
from sibilant.rtp import MediaFlowType, RTPMediaFormat, RTPMediaType

from .common import (
    InactiveFlag,
    MediaFlowAttribute,
    RecvOnlyFlag,
    SDPAttribute,
    SDPAttributeField,
    SDPBandwidthField,
    SDPConnectionField,
    SDPEncryptionField,
    SDPField,
    SDPInformationField,
    SDPSection,
    SendOnlyFlag,
    SendRecvFlag,
    UnknownAttribute,
    ValueAttribute,
)


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
    """Base class for SDP media description fields."""


@slots_dataclass
class SDPMediaMedia(SDPMediaFields):
    """
    SDP media field, defined in :rfc:`8866#section-5.14`.

    Spec::
        m=<media> <port> <proto> <fmt> ...
        m=<media> <port>/<number of ports> <proto> <fmt> ...
    """

    _type = "m"
    _description = "media name and transport address"

    media: str
    port: int
    number_of_ports: int | None
    protocol: str
    formats: list[int]

    def __post_init__(self) -> None:
        if self.port % 2 != 0:
            raise SDPParseError(f"Port number must be even (got {self.port})")

    @property
    def rtcp_port(self) -> int:
        """RTCP port, which is the media port + 1."""
        return self.port + 1

    @classmethod
    @override
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        media, ports_spec, protocol, *formats = raw_value.split(" ")
        port, number_of_ports = (
            int(x) if x is not None else None
            for x in (
                ports_spec.split("/") if "/" in ports_spec else (ports_spec, None)
            )
        )
        if not isinstance(port, int):
            raise SDPParseError(f"Invalid ports in media attribute: {ports_spec}")
        return cls(
            media=media,
            port=port,
            number_of_ports=number_of_ports,
            protocol=protocol,
            formats=[int(x) for x in formats],
        )

    def serialize(self) -> str:  # noqa: D102
        formats_joined: str = " ".join(str(x) for x in self.formats)
        return f"{self.media} {self.port} {self.protocol} {formats_joined}"


@slots_dataclass
class SDPMediaTitle(SDPInformationField, SDPMediaFields):
    """
    SDP media title field, defined in :rfc:`8866#section-5.4.

    Spec::
        i=<media title>
    """

    _description = "media title"


@slots_dataclass
class SDPMediaConnection(SDPConnectionField, SDPMediaFields):
    """
    SDP media connection field, defined in :rfc:`8866#section-5.7`.

    Spec::
        c=<nettype> <addrtype> <connection-address>
    """

    _description = "connection information -- optional if included at session-level"


@slots_dataclass
class SDPMediaBandwidth(SDPBandwidthField, SDPMediaFields):
    """
    SDP media bandwidth field, defined in :rfc:`8866#section-5.8`.

    Spec::
        b=<bwtype>:<bandwidth>
    """

    _description = "zero or more bandwidth information lines"


@slots_dataclass
class SDPMediaEncryption(SDPEncryptionField, SDPMediaFields):
    """
    SDP media encryption field, defined in :rfc:`8866#section-5.12`.

    Spec::
        k=<method>
        k=<method>:<encryption key>
    """

    _description = "encryption key"


@dataclass
class SDPMediaAttribute(SDPAttribute, ABC, registry=True, registry_attr="_name"):
    """Base class for SDP media attributes."""


@slots_dataclass
class UnknownMediaAttribute(UnknownAttribute, SDPMediaAttribute):
    """Catch-all class for unsupported SDP media attributes."""


@slots_dataclass
class RecvOnlyMediaFlag(RecvOnlyFlag, SDPMediaAttribute):
    """
    SDP media attribute for recvonly media flow, defined in :rfc:`8866#section-6.7.1`.

    spec::
        recvonly
    """


@slots_dataclass
class SendRecvMediaFlag(SendRecvFlag, SDPMediaAttribute):
    """
    SDP media attribute for sendrecv media flow, defined in :rfc:`8866#section-6.7.2`.

    spec::
        sendrecv
    """


@slots_dataclass
class SendOnlyMediaFlag(SendOnlyFlag, SDPMediaAttribute):
    """
    SDP media attribute for sendonly media flow, defined in :rfc:`8866#section-6.7.3`.

    spec::
        sendonly
    """


@slots_dataclass
class InactiveMediaFlag(InactiveFlag, SDPMediaAttribute):
    """
    SDP media attribute for inactive media flow, defined in :rfc:`8866#section-6.7.4`.

    spec::
        inactive
    """


@slots_dataclass
class PTimeAttribute(IntValueMixin, ValueAttribute, SDPMediaAttribute):
    """
    SDP media attribute for ptime, defined in :rfc:`8866#section-6.4`.

    Spec::
        ptime:<value>
    """

    _name = "ptime"


@slots_dataclass
class MaxPTimeAttribute(IntValueMixin, ValueAttribute, SDPMediaAttribute):
    """
    SDP media attribute for maxptime, defined in :rfc:`8866#section-6.5`.

    Spec::
        maxptime:<value>
    """

    _name = "maxptime"


@slots_dataclass
class RTPMapAttribute(SDPMediaAttribute):
    """
    SDP media attribute for RTP map, defined in :rfc:`8866#section-6.6`.

    Spec::
        rtpmap:<payload type> <encoding name>/<clock rate>[/<encoding parameters>]
    """

    _name = "rtpmap"
    _is_flag = False

    payload_type: int
    encoding_name: str
    clock_rate: int
    encoding_parameters: str | None = None

    @classmethod
    def from_raw_value(cls, name: str, raw_value: str | None) -> Self:  # noqa: D102
        # encoding parameters are optional
        if raw_value is None:
            raise SDPParseError("rtpmap attribute requires a value")
        payload_type, encoding = raw_value.split(" ", maxsplit=1)
        encoding_name, clock_rate, *more = encoding.split("/", maxsplit=2)
        encoding_parameters = more[0] if more else None
        return cls(
            payload_type=int(payload_type),
            encoding_name=encoding_name,
            clock_rate=int(clock_rate),
            encoding_parameters=encoding_parameters,
        )

    def serialize(self) -> str:  # noqa: D102
        data = f"{self.payload_type} {self.encoding_name}/{self.clock_rate}"
        if self.encoding_parameters is not None:
            data += f"/{self.encoding_parameters}"
        return data


@slots_dataclass
class FMTPAttribute(SDPMediaAttribute):
    """
    SDP media attribute for RTP format parameters, defined in :rfc:`8866#section-6.15`.

    Spec::
        fmtp:<format> <format specific parameters>
    """

    _name = "fmtp"
    _is_flag = False

    format: int
    format_specific_parameters: str

    @classmethod
    def from_raw_value(cls, name: str, raw_value: str | None) -> Self:  # noqa: D102
        if raw_value is None:
            raise SDPParseError("fmtp attribute requires a value")
        format_, format_specific_parameters = raw_value.split(" ", maxsplit=1)
        return cls(
            format=int(format_),
            format_specific_parameters=format_specific_parameters,
        )

    def serialize(self) -> str:  # noqa: D102
        return f"{self.format} {self.format_specific_parameters}"


@slots_dataclass
class SDPMediaAttributeField(SDPAttributeField, SDPMediaFields):
    """
    SDP media attribute field, defined in :rfc:`8866#section-5.13`.

    Spec::
        a=<attribute>
        a=<attribute>:<value>
    """

    _attribute_cls = SDPMediaAttribute

    _description = "zero or more media attribute lines"


def get_media_flow_attribute(flow_type: MediaFlowType) -> SDPMediaAttribute:
    """Return the SDP media attribute class for the given media flow type."""
    return {  # type: ignore[return-value]
        flow_type.SENDRECV: SendRecvMediaFlag,
        flow_type.SENDONLY: SendOnlyMediaFlag,
        flow_type.RECVONLY: RecvOnlyMediaFlag,
        flow_type.INACTIVE: InactiveMediaFlag,
    }[flow_type]()  # type: ignore[index]


def get_media_flow_type(
    attributes: Sequence[SDPAttributeField],
) -> MediaFlowType | None:
    """Return the media flow type from the given media attributes."""
    media_flow_type: MediaFlowType | None = None
    for attribute_field in attributes:
        if isinstance(attribute_field.attribute, MediaFlowAttribute):
            if media_flow_type is not None:
                raise SDPParseError("Multiple media flow attributes in session")
            media_flow_type = MediaFlowType(attribute_field.attribute.name)
    return media_flow_type


@slots_dataclass
class SDPMedia(SDPSection):
    """SDP section for media description fields, defined in :rfc:`8866#section-5.14`."""

    _fields_base = SDPMediaFields
    _start_field = SDPMediaMedia

    media: SDPMediaMedia
    title: SDPMediaTitle | None = None
    connection: SDPMediaConnection | None = None
    bandwidth: SDPMediaBandwidth | None = None
    encryption: SDPMediaEncryption | None = None
    attributes: list[SDPMediaAttributeField] = dataclass_field(default_factory=list)

    _media_formats: list[RTPMediaFormat] = dataclass_field(default_factory=list)

    def __post_init__(self) -> None:
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
    def media_flow_type(self) -> MediaFlowType | None:
        """Media flow type, extracted from the media attributes."""
        return get_media_flow_type(self.attributes)

    # FIXME: media formats can be out-of date if something in the class changes. generate on the fly?
    @property
    def media_formats(self) -> list[RTPMediaFormat]:
        """List of media formats, extracted from the media attributes."""
        return self._media_formats

    def _build_media_formats(self) -> list[RTPMediaFormat]:
        formats: list[RTPMediaFormat] = []
        if self.media.protocol in {"RTP/AVP", "RTP/SAVP"}:
            # collect rtpmap and fmtp attributes with the same id as the media formats
            known_formats = {int(f) for f in self.media.formats}
            rtpmap_map: dict[int, RTPMapAttribute] = {}
            fmtp_map: dict[int, FMTPAttribute] = {}
            for attribute_field in self.attributes:
                attribute = attribute_field.attribute
                if isinstance(attribute, RTPMapAttribute):
                    if attribute.payload_type not in known_formats:
                        raise SDPParseError(  # TODO: maybe just warn?
                            f"rtpmap attribute refers to unknown format (known: {known_formats}): "
                            f"{attribute.payload_type}"
                        )
                    rtpmap_map[attribute.payload_type] = attribute
                elif isinstance(attribute, FMTPAttribute):
                    if attribute.format not in known_formats:
                        raise SDPParseError(  # TODO: maybe just warn?
                            f"fmtp attribute refers to unknown format (known: {known_formats}): "
                            f"{attribute.format}"
                        )
                    fmtp_map[attribute.format] = attribute

            if unmatched_specific_params := fmtp_map.keys() - rtpmap_map.keys():
                raise SDPParseError(
                    f"fmtp attribute refers to unknown format: {unmatched_specific_params}"
                )

            rtpmap: RTPMapAttribute
            for rtpmap in rtpmap_map.values():
                fmtp: FMTPAttribute | None = fmtp_map.get(rtpmap.payload_type)
                channels: int | None = None
                try:  # noqa: SIM105
                    channels = int(rtpmap.encoding_parameters)  # type: ignore[arg-type]
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
