"""SDP session section and fields definitions and implementations."""

from __future__ import annotations

import logging
from abc import ABC
from dataclasses import dataclass, field as dataclass_field
from typing import TYPE_CHECKING, Any, MutableMapping

from typing_extensions import Self, override

from sibilant.constants import SUPPORTED_SDP_VERSIONS
from sibilant.exceptions import SDPParseError
from sibilant.helpers import FieldsParserSerializer, StrValueMixin, slots_dataclass

from .common import (
    InactiveFlag,
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
)
from .media import SDPMedia, get_media_flow_type
from .time import SDPTime  # noqa


if TYPE_CHECKING:
    from sibilant.rtp import MediaFlowType


__all__ = [
    "SDPSessionFields",
    "SDPSessionVersion",
    "SDPSessionOrigin",
    "SDPSessionName",
    "SDPSessionInformation",
    "SDPSessionURI",
    "SDPSessionEmail",
    "SDPSessionPhone",
    "SDPSessionConnection",
    "SDPSessionBandwidth",
    "SDPSessionTimezoneAdjustment",
    "SDPSessionTimezone",
    "SDPSessionEncryption",
    "SDPSessionAttribute",
    "UnknownSessionAttribute",
    "RecvOnlySessionFlag",
    "SendRecvSessionFlag",
    "SendOnlySessionFlag",
    "InactiveSessionFlag",
    "SDPSessionAttributeField",
    "SDPSession",
]


_logger = logging.getLogger(__name__)


@dataclass
class SDPSessionFields(SDPField, ABC, registry=True, registry_attr="_type"):
    """Base class for SDP session description fields."""


@slots_dataclass
class SDPSessionVersion(StrValueMixin, SDPSessionFields):
    """
    SDP version field, defined in :rfc:`8866#section-5.1`.

    Spec::
        v=0.
    """

    _type = "v"
    _description = "protocol version"

    def __post_init__(self) -> None:
        if self.value not in SUPPORTED_SDP_VERSIONS:
            raise SDPParseError(f"Unsupported SDP version {self.value}")


@slots_dataclass
class SDPSessionOrigin(SDPSessionFields):
    """
    SDP origin field, defined in :rfc:`8866#section-5.2`.

    Spec::
        o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
    """

    _type = "o"
    _description = "originator and session identifier"

    username: str
    sess_id: str
    sess_version: str
    nettype: str
    addrtype: str
    unicast_address: str

    @classmethod
    @override
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        (
            username,
            sess_id,
            sess_version,
            nettype,
            addrtype,
            unicast_address,
        ) = raw_value.split(" ")
        return cls(
            username=username,
            sess_id=sess_id,
            sess_version=sess_version,
            nettype=nettype,
            addrtype=addrtype,
            unicast_address=unicast_address,
        )

    def serialize(self) -> str:  # noqa: D102
        return " ".join((
            str(self.username),
            str(self.sess_id),
            str(self.sess_version),
            str(self.nettype),
            str(self.addrtype),
            str(self.unicast_address),
        ))


@slots_dataclass
class SDPSessionName(StrValueMixin, SDPSessionFields):
    """
    SDP session name field, defined in :rfc:`8866#section-5.3`.

    Spec::
        s=<session name>
    """

    _type = "s"
    _description = "session name"

    @property
    def session_name(self) -> str:
        """The session name."""
        return self.value


@slots_dataclass
class SDPSessionInformation(SDPInformationField, SDPSessionFields):
    """
    SDP session information field, defined in :rfc:`8866#section-5.4`.

    Spec::
        i=<session description>
    """

    _description = "session information"


@slots_dataclass
class SDPSessionURI(StrValueMixin, SDPSessionFields):
    """
    SDP session URI field, defined in :rfc:`8866#section-5.5`.

    Spec::
        u=<uri>
    """

    _type = "u"
    _description = "URI of description"

    @property
    def uri(self) -> str:
        """The URI."""
        return self.value


@slots_dataclass
class SDPSessionEmail(StrValueMixin, SDPSessionFields):
    """
    SDP session email field, defined in :rfc:`8866#section-5.6`.

    Spec::
        e=<email-address>
    """

    _type = "e"
    _description = "email address"

    @property
    def email_address(self) -> str:
        """The email address."""
        return self.value


@slots_dataclass
class SDPSessionPhone(StrValueMixin, SDPSessionFields):
    """
    SDP session phone field, defined in :rfc:`8866#section-5.6`.

    Spec::
        p=<phone-number>
    """

    _type = "p"
    _description = "phone number"

    @property
    def phone_number(self) -> str:
        """The phone number."""
        return self.value


@slots_dataclass
class SDPSessionConnection(SDPConnectionField, SDPSessionFields):
    """
    SDP session connection field, defined in :rfc:`8866#section-5.7`.

    Spec::
        c=<nettype> <addrtype> <connection-address>
    """

    _description = "connection information -- not required if included in all media"


@slots_dataclass
class SDPSessionBandwidth(SDPBandwidthField, SDPSessionFields):
    """
    SDP session bandwidth field, defined in :rfc:`8866#section-5.8`.

    Spec::
        b=<bwtype>:<bandwidth>
    """

    _description = "zero or more bandwidth information lines"


@slots_dataclass
class SDPSessionTimezoneAdjustment(FieldsParserSerializer):
    """
    SDP session timezone adjustments, as part of definition in :rfc:`8866#section-5.11`.

    Spec::
        <adjustment time> <offset>
    """

    adjustment_time: int
    offset: str

    @classmethod
    def from_raw_value(cls, raw_value: str) -> Self:  # noqa: D102
        return cls(**cls.parse_raw_value(raw_value))

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> dict[str, Any]:  # noqa: D102
        adjustment_time, offset = raw_value.split(" ")
        return dict(adjustment_time=int(adjustment_time), offset=offset)

    def serialize(self) -> str:  # noqa: D102
        return f"{self.adjustment_time} {self.offset}"

    def __str__(self) -> str:
        return self.serialize()


@slots_dataclass
class SDPSessionTimezone(SDPSessionFields, FieldsParserSerializer):
    """
    SDP session timezone field, defined in :rfc:`8866#section-5.11`.

    Spec::
        z=<adjustment time> <offset> <adjustment time> <offset> ....
    """

    _type = "z"
    _description = "time zone adjustments"

    adjustments: list[SDPSessionTimezoneAdjustment]

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> dict[str, Any]:  # noqa: D102
        split_values = raw_value.split(" ")
        if len(split_values) % 2 != 0:
            raise SDPParseError(
                f"Number of values in timezone field is not even (got {len(split_values)}): "
                f"{raw_value}"
            )
        adjustments = [
            SDPSessionTimezoneAdjustment.from_raw_value(f"{adjustment_time} {offset}")
            for adjustment_time, offset in zip(split_values[::2], split_values[1::2])
        ]
        return dict(adjustments=adjustments)

    def serialize(self) -> str:  # noqa: D102
        return " ".join(str(adjustment) for adjustment in self.adjustments)


@slots_dataclass
class SDPSessionEncryption(SDPEncryptionField, SDPSessionFields):
    """
    SDP session encryption field, defined in :rfc:`8866#section-5.12`.

    Spec::
        k=<method>
        k=<method>:<encryption key>
    """

    _description = "encryption key"


@dataclass
class SDPSessionAttribute(SDPAttribute, ABC, registry=True, registry_attr="_name"):
    """Base class for SDP session attributes."""


@slots_dataclass
class UnknownSessionAttribute(UnknownAttribute, SDPSessionAttribute):
    """Catch-all class for unsupported SDP session attributes."""


@slots_dataclass
class RecvOnlySessionFlag(RecvOnlyFlag, SDPSessionAttribute):
    """
    SDP session attribute for recvonly media flow, defined in :rfc:`8866#section-6.7.1`.

    spec::
        recvonly
    """


@slots_dataclass
class SendRecvSessionFlag(SendRecvFlag, SDPSessionAttribute):
    """
    SDP session attribute for sendrecv media flow, defined in :rfc:`8866#section-6.7.2`.

    spec::
        sendrecv
    """


@slots_dataclass
class SendOnlySessionFlag(SendOnlyFlag, SDPSessionAttribute):
    """
    SDP session attribute for sendonly media flow, defined in :rfc:`8866#section-6.7.3`.

    spec::
        sendonly
    """


@slots_dataclass
class InactiveSessionFlag(InactiveFlag, SDPSessionAttribute):
    """
    SDP session attribute for inactive media flow, defined in :rfc:`8866#section-6.7.4`.

    spec::
        inactive
    """


@slots_dataclass
class SDPSessionAttributeField(SDPAttributeField, SDPSessionFields):
    """
    SDP session attribute field, defined in :rfc:`8866#section-5.13`.

    Spec::
        a=<attribute>
        a=<attribute>:<value>
    """

    _attribute_cls = SDPSessionAttribute

    _description = "zero or more session attribute lines"


# TODO: RFC 8866 requires that the order of fields is exactly as defined in the spec. Add tests.


@dataclass
class SDPSession(SDPSection):
    """SDP section for session description fields, defined in :rfc:`8866#section-5`."""

    _fields_base = SDPSessionFields
    _start_field = SDPSessionVersion

    version: SDPSessionVersion
    origin: SDPSessionOrigin
    name: SDPSessionName
    information: SDPSessionInformation | None = None
    uri: SDPSessionURI | None = None
    email: SDPSessionEmail | None = None
    phone: SDPSessionPhone | None = None
    connection: SDPSessionConnection | None = None
    bandwidth: SDPSessionBandwidth | None = None
    time: list[SDPTime] = dataclass_field(default_factory=list)
    timezone: SDPSessionTimezone | None = None
    encryption: SDPSessionEncryption | None = None
    attributes: list[SDPSessionAttributeField] = dataclass_field(default_factory=list)
    media: list[SDPMedia] = dataclass_field(default_factory=list)

    def __post_init__(self) -> None:
        if not len(self.time):
            raise ValueError("SDP session must have at least one time field")

    @property
    def mimetype(self) -> str:
        """The mimetype of the SDP session data. Always ``application/sdp``."""
        return "application/sdp"

    @property
    def media_flow_type(self) -> MediaFlowType | None:
        """The media flow type of the session, if any."""
        return get_media_flow_type(self.attributes)

    @classmethod
    def _line_preprocess(cls, line: str, fields: MutableMapping[str, Any]) -> str:
        if fields.get("media"):
            raise SDPParseError(f"Session field {line} found after media field")
        return super()._line_preprocess(line, fields)

    @property
    def connection_address(self) -> tuple[str, int] | None:
        """The advertised connection address and port to be used for media streams, if any."""
        addresses: list[tuple[str, int]] = [
            (connection.address, media.media.port)
            for media in self.media
            if (connection := media.connection or self.connection)
        ]
        if not addresses:
            return None
        if len(addresses) > 1:
            # TODO: implement allowing to filter by supported media types
            _logger.warning(
                "Multiple connection addresses found in SDP session, returning first one"
            )
        return addresses[0]
