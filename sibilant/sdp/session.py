from __future__ import annotations

import logging
from abc import ABC
from dataclasses import field as dataclass_field
from typing import Dict, Optional, List, Any, MutableMapping, TYPE_CHECKING, Tuple

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

from ..rtp import MediaFlowType
from ..constants import SUPPORTED_SDP_VERSIONS
from ..exceptions import SDPParseError
from ..helpers import StrValueMixin, dataclass
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
    SDPSection,
)
from .media import SDPMedia, get_media_flow_type
from .time import SDPTime

if TYPE_CHECKING:
    from dataclasses import dataclass


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


@dataclass(slots=True)
class SDPSessionFields(SDPField, ABC, registry=True, registry_attr="_type"):
    ...


@dataclass(slots=True)
class SDPSessionVersion(StrValueMixin, SDPSessionFields):
    """
    SDP version field, defined in :rfc:`4566#section-5.1`.

    Spec::
        v=0
    """

    _type = "v"
    _description = "protocol version"

    def __post_init__(self):
        if self.value not in SUPPORTED_SDP_VERSIONS:
            raise SDPParseError(f"Unsupported SDP version {self.value}")


@dataclass(slots=True)
class SDPSessionOrigin(SDPSessionFields):
    """
    SDP origin field, defined in :rfc:`4566#section-5.2`

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

    def serialize(self) -> str:
        return " ".join(
            (
                self.username,
                self.sess_id,
                self.sess_version,
                self.nettype,
                self.addrtype,
                self.unicast_address,
            )
        )


@dataclass(slots=True)
class SDPSessionName(StrValueMixin, SDPSessionFields):
    """
    SDP session name field, defined in :rfc:`4566#section-5.3`.

    Spec::
        s=<session name>
    """

    _type = "s"
    _description = "session name"

    @property
    def session_name(self) -> str:
        return self.value


@dataclass(slots=True)
class SDPSessionInformation(SDPInformationField, SDPSessionFields):
    """
    SDP session information field, defined in :rfc:`4566#section-5.4`.

    Spec::
        i=<session description>
    """

    _description = "session information"


@dataclass(slots=True)
class SDPSessionURI(StrValueMixin, SDPSessionFields):
    """
    SDP session URI field, defined in :rfc:`4566#section-5.5`.

    Spec::
        u=<uri>
    """

    _type = "u"
    _description = "URI of description"

    @property
    def uri(self) -> str:
        return self.value


@dataclass(slots=True)
class SDPSessionEmail(StrValueMixin, SDPSessionFields):
    """
    SDP session email field, defined in :rfc:`4566#section-5.6`.

    Spec::
        e=<email-address>
    """

    _type = "e"
    _description = "email address"

    @property
    def email_address(self) -> str:
        return self.value


@dataclass(slots=True)
class SDPSessionPhone(StrValueMixin, SDPSessionFields):
    """
    SDP session phone field, defined in :rfc:`4566#section-5.6`.

    Spec::
        p=<phone-number>
    """

    _type = "p"
    _description = "phone number"

    @property
    def phone_number(self) -> str:
        return self.value


@dataclass(slots=True)
class SDPSessionConnection(SDPConnectionField, SDPSessionFields):
    """
    SDP session connection field, defined in :rfc:`4566#section-5.7`.

    Spec::
        c=<nettype> <addrtype> <connection-address>
    """

    _description = "connection information -- not required if included in all media"


@dataclass(slots=True)
class SDPSessionBandwidth(SDPBandwidthField, SDPSessionFields):
    """
    SDP session bandwidth field, defined in :rfc:`4566#section-5.8`.

    Spec::
        b=<bwtype>:<bandwidth>
    """

    _description = "zero or more bandwidth information lines"


@dataclass(slots=True)
class SDPSessionTimezoneAdjustment:
    """
    SDP session timezone adjustments, as part of definition in :rfc:`4566#section-5.11`.

    Spec::
        <adjustment time> <offset>
    """

    adjustment_time: int
    offset: str

    @classmethod
    def from_raw_value(cls, raw_value: str) -> Self:
        return cls(**cls.parse_raw_value(raw_value))

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> Dict[str, Any]:
        adjustment_time, offset = raw_value.split(" ")
        return dict(adjustment_time=int(adjustment_time), offset=offset)

    def serialize(self) -> str:
        return f"{self.adjustment_time} {self.offset}"

    def __str__(self):
        return self.serialize()


@dataclass(slots=True)
class SDPSessionTimezone(SDPSessionFields):
    """
    SDP session timezone field, defined in :rfc:`4566#section-5.11`.

    Spec::
        z=<adjustment time> <offset> <adjustment time> <offset> ....
    """

    _type = "z"
    _description = "time zone adjustments"

    adjustments: List[SDPSessionTimezoneAdjustment]

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> Dict[str, Any]:
        split_values = raw_value.split(" ")
        if len(split_values) % 2 != 0:
            raise SDPParseError(
                f"Number of values in timezone field is not even (got {len(split_values)}): {raw_value}"
            )
        adjustments = [
            SDPSessionTimezoneAdjustment.from_raw_value(
                " ".join((adjustment_time, offset))
            )
            for adjustment_time, offset in zip(split_values[::2], split_values[1::2])
        ]
        return dict(adjustments=adjustments)

    def serialize(self) -> str:
        return " ".join(str(adjustment) for adjustment in self.adjustments)


@dataclass(slots=True)
class SDPSessionEncryption(SDPEncryptionField, SDPSessionFields):
    """
    SDP session encryption field, defined in :rfc:`4566#section-5.12`.

    Spec::
        k=<method>
        k=<method>:<encryption key>
    """

    _description = "encryption key"


@dataclass(slots=True)
class SDPSessionAttribute(SDPAttribute, ABC, registry=True, registry_attr="_name"):
    ...


@dataclass(slots=True)
class UnknownSessionAttribute(UnknownAttribute, SDPSessionAttribute):
    ...


@dataclass(slots=True)
class RecvOnlySessionFlag(RecvOnlyFlag, SDPSessionAttribute):
    ...


@dataclass(slots=True)
class SendRecvSessionFlag(SendRecvFlag, SDPSessionAttribute):
    ...


@dataclass(slots=True)
class SendOnlySessionFlag(SendOnlyFlag, SDPSessionAttribute):
    ...


@dataclass(slots=True)
class InactiveSessionFlag(InactiveFlag, SDPSessionAttribute):
    ...


@dataclass(slots=True)
class SDPSessionAttributeField(SDPAttributeField, SDPSessionFields):
    """
    SDP session attribute field, defined in :rfc:`4566#section-5.13`.

    Spec::
        a=<attribute>
        a=<attribute>:<value>
    """

    _attribute_cls = SDPSessionAttribute

    _description = "zero or more session attribute lines"


@dataclass(slots=True)
class SDPSession(SDPSection):
    _fields_base = SDPSessionFields
    _start_field = SDPSessionVersion

    version: SDPSessionVersion
    origin: SDPSessionOrigin
    name: SDPSessionName
    information: Optional[SDPSessionInformation] = None
    uri: Optional[SDPSessionURI] = None
    email: Optional[SDPSessionEmail] = None
    phone: Optional[SDPSessionPhone] = None
    connection: Optional[SDPSessionConnection] = None
    bandwidth: Optional[SDPSessionBandwidth] = None
    time: List[SDPTime] = dataclass_field(default_factory=list)
    timezone: Optional[SDPSessionTimezone] = None
    encryption: Optional[SDPSessionEncryption] = None
    attributes: List[SDPSessionAttributeField] = dataclass_field(default_factory=list)
    media: List[SDPMedia] = dataclass_field(default_factory=list)

    def __post_init__(self):
        if not len(self.time):
            raise ValueError("SDP session must have at least one time field")

    @property
    def mimetype(self) -> str:
        return "application/sdp"

    @property
    def media_flow_type(self) -> Optional[MediaFlowType]:
        return get_media_flow_type(self.attributes)

    @classmethod
    def _line_preprocess(cls, line: str, fields: MutableMapping[str, Any]) -> str:
        if fields.get("media"):
            raise SDPParseError(f"Session field {line} found after media field")
        return super()._line_preprocess(line, fields)

    @property
    def connection_address(self) -> Optional[Tuple[str, int]]:
        addresses: List[Tuple[str, int]] = [
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
