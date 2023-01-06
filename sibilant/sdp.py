"""Session Description Protocol (SDP) protocol implementation."""
from __future__ import annotations

import enum
import re
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import field as dataclass_field, fields as dataclass_fields, Field, InitVar
from typing import (
    ClassVar,
    Dict,
    Optional,
    List,
    Any,
    Deque,
    Type,
    Union,
    MutableMapping,
    get_type_hints,
    get_origin,
    Tuple,
)

from .constants import SUPPORTED_SDP_VERSIONS

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

from .exceptions import SDPParseError, SDPUnknownFieldError
from .helpers import Registry, StrValueMixin, DEFAULT, dataclass, try_unpack_optional_type


@dataclass(slots=True)
class SDPField(Registry[str, "SDPField"], ABC):
    _type: ClassVar[str]
    _description: ClassVar[str]

    raw_value: str

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # make sure type is set and register the class into known types
        if ABC not in cls.__bases__ and not getattr(cls, "_description", None):
            raise ValueError(f"SDPField class {cls} must have a _description attribute")

    @property
    def type(self) -> str:
        return self._type

    @classmethod
    def parse(cls, raw_data: str) -> Self:
        field_type, raw_value = raw_data.strip().split("=", 1)

        try:
            field_cls = cls.__registry_get_class_for__(field_type)
        except KeyError:
            raise SDPUnknownFieldError(f"Unknown SDP field type {field_type}")

        return field_cls.from_raw_value(field_type=field_type, raw_value=raw_value)

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        """
        Parse the raw value of the field into a field object.

        :param field_type: the field type
        :param raw_value: the raw value of the field
        :return: the field object
        """
        if hasattr(cls, "parse_raw_value"):
            return cls(**cls.parse_raw_value(raw_value), raw_value=raw_value)
        raise NotImplementedError

    @abstractmethod
    def serialize(self) -> str:
        """
        Serialize the field value to a string.

        :return: The serialized field value string.
        """

    def __str__(self) -> str:
        return f"{self.type}={self.serialize()}"


@dataclass(slots=True)
class SDPAttribute(Registry[Union[str, type(DEFAULT)], "SDPAttribute"], ABC):
    _name: ClassVar[Union[str, type(DEFAULT)]]
    _is_flag: ClassVar[Optional[bool]] = None

    raw_value: Any

    @property
    def name(self) -> str:
        return self._name

    @property
    def value(self) -> Any:
        return self.raw_value

    @property
    def is_flag(self) -> bool:
        return self.value is None

    @classmethod
    def parse(cls, raw_data: str) -> Self:
        name, raw_value = raw_data.split(":", 1) if ":" in raw_data else (raw_data, None)

        if cls._is_flag is not None:
            if cls._is_flag and raw_value is not None:
                raise SDPParseError(f"Attribute {name} is a flag, but got a value: {raw_data}")
            if not cls._is_flag and raw_value is None:
                raise SDPParseError(f"Attribute {name} is not a flag, but got no value: {raw_data}")

        registry_name: str = name.lower()
        is_known_attribute: bool = registry_name in cls.__registry__
        if not is_known_attribute and DEFAULT not in cls.__registry__:
            raise TypeError(f"Unknown SDP attribute {name}, and no default attribute class is defined")
        attr_cls: Type[SDPAttribute] = cls.__registry_get_class_for__(registry_name if is_known_attribute else DEFAULT)

        return attr_cls.from_raw_value(name, raw_value)

    @classmethod
    @abstractmethod
    def from_raw_value(cls, name: str, raw_value: Optional[str]) -> Self:
        """
        Parse a raw value into an instance of this attribute class.

        :param name: the name of the attribute parsed from raw data
        :param raw_value: the raw value of the attribute parsed from raw data
        :return:
        """

    @abstractmethod
    def serialize(self) -> str:
        """Serialize the attribute value to a string."""

    def __str__(self):
        """Serialize the whole attribute to a string."""
        return f"{self.name}:{self.serialize()}" if not self.is_flag else self.name


@dataclass(slots=True)
class FlagAttribute(SDPAttribute, ABC):
    _is_flag: ClassVar[bool] = True

    @classmethod
    def from_raw_value(cls, name: str, raw_value: Optional[str]) -> Self:
        return cls(raw_value=None)

    def serialize(self) -> str:
        raise ValueError("Flag attributes have no value to serialize")


@dataclass(slots=True)
class UnknownAttribute(SDPAttribute, ABC):
    _name = DEFAULT

    attribute: str

    @property
    def name(self) -> str:
        return self.attribute

    @classmethod
    def from_raw_value(cls, name: str, raw_value: Optional[str]) -> Self:
        return cls(attribute=name, raw_value=raw_value)

    def serialize(self) -> str:
        if self.raw_value is None:
            raise ValueError("Cannot an attribute value without a value (flag)")
        return self.raw_value


class MediaFlowAttribute(FlagAttribute, ABC):
    _is_flag = True


@dataclass(slots=True)
class RecvOnlyFlag(MediaFlowAttribute, ABC):
    _name = "recvonly"


@dataclass(slots=True)
class SendRecvFlag(MediaFlowAttribute, ABC):
    _name = "sendrecv"


@dataclass(slots=True)
class SendOnlyFlag(MediaFlowAttribute, ABC):
    _name = "sendonly"


@dataclass(slots=True)
class InactiveFlag(MediaFlowAttribute, ABC):
    _name = "inactive"


@dataclass(slots=True)
class SDPInformationField(StrValueMixin, SDPField, ABC):
    """
    SDP session information field, defined in :rfc:`4566#section-5.4`.

    Spec::
        i=<session description>
    """

    _type = "i"

    @property
    def session_description(self) -> str:
        return self.value


@dataclass(slots=True)
class SDPConnectionField(SDPField, ABC):
    """
    SDP session connection field, defined in :rfc:`4566#section-5.7`.

    Spec::
        c=<nettype> <addrtype> <connection-address>
    """

    _type = "c"

    nettype: str
    addrtype: str
    address: str
    ttl: Optional[int] = None
    number_of_addresses: Optional[int] = None

    @property
    def connection_address(self) -> str:
        parts = [self.address]
        if self.ttl is not None:
            parts.append(str(self.ttl))
        if self.number_of_addresses is not None:
            parts.append(str(self.number_of_addresses))
        return "/".join(parts)

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        nettype, addrtype, connection_address = raw_value.split(" ")
        # parse the connection address. Keep in mind IPv6 don't have TTL, so the second part might be the number of addresses
        address, *rest = connection_address.split("/")
        ttl = number_of_addresses = None
        if rest:
            if addrtype == "IP6":
                if len(rest) >= 1:
                    raise SDPParseError(f"Invalid connection address {connection_address}")
                number_of_addresses = int(rest[0])
            else:
                if len(rest) >= 2:
                    raise SDPParseError(f"Invalid connection address {connection_address}")
                ttl = int(rest[0])
                if len(rest) == 2:
                    number_of_addresses = int(rest[1])
        return cls(
            nettype=nettype,
            addrtype=addrtype,
            address=address,
            ttl=ttl,
            number_of_addresses=number_of_addresses,
            raw_value=raw_value,
        )

    def serialize(self) -> str:
        return " ".join((self.nettype, self.addrtype, self.connection_address))


@dataclass(slots=True)
class SDPBandwidthField(SDPField, ABC):
    """
    SDP session bandwidth field, defined in :rfc:`4566#section-5.8`.

    Spec::
        b=<bwtype>:<bandwidth>
    """

    _type = "b"

    bwtype: str
    bandwidth: int

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        bwtype, bandwidth = raw_value.split(":")
        return cls(bwtype=bwtype, bandwidth=int(bandwidth), raw_value=raw_value)

    def serialize(self) -> str:
        return f"{self.bwtype}:{self.bandwidth}"


@dataclass(slots=True)
class SDPEncryptionField(SDPField, ABC):
    """
    SDP session encryption field, defined in :rfc:`4566#section-5.12`.

    Spec::
        k=<method>
        k=<method>:<encryption key>
    """

    _type = "k"

    method: str
    key: Optional[str] = None

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        method: str
        key: Optional[str]
        method, key = raw_value.split(":") if ":" in raw_value else (raw_value, None)
        return cls(method=method, key=key, raw_value=raw_value)

    def serialize(self) -> str:
        return f"{self.method}:{self.key}" if self.key else self.method


@dataclass(slots=True)
class SDPAttributeField(SDPField, ABC):
    _type = "a"
    _attribute_cls: ClassVar[Type[SDPAttribute]]

    attribute: SDPAttribute

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        if not hasattr(cls, "_attribute_cls"):
            raise TypeError(f"Attribute field class {cls} must have an attribute class defined")

    @property
    def name(self) -> str:
        return self.attribute.name

    @property
    def value(self) -> Any:
        return self.attribute.value

    @property
    def is_flag(self) -> bool:
        return self.attribute.is_flag

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        return cls(attribute=cls._attribute_cls.parse(raw_value), raw_value=raw_value)

    def serialize(self) -> str:
        return str(self.attribute)


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
        username, sess_id, sess_version, nettype, addrtype, unicast_address = raw_value.split(" ")
        return cls(
            username=username,
            sess_id=sess_id,
            sess_version=sess_version,
            nettype=nettype,
            addrtype=addrtype,
            unicast_address=unicast_address,
            raw_value=raw_value,
        )

    def serialize(self) -> str:
        return " ".join(
            (self.username, self.sess_id, self.sess_version, self.nettype, self.addrtype, self.unicast_address)
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
            SDPSessionTimezoneAdjustment.from_raw_value(" ".join((adjustment_time, offset)))
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
class SDPTimeFields(SDPField, ABC, registry=True, registry_attr="_type"):
    ...


@dataclass(slots=True)
class SDPTimeTime(SDPTimeFields):
    """
    SDP time field, defined in :rfc:`4566#section-5.9`.

    Spec::
        t=<start-time> <stop-time>
    """

    _type = "t"
    _description = "time the session is active"

    start_time: int
    stop_time: int

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        start_time, stop_time = raw_value.split(" ")
        return cls(start_time=int(start_time), stop_time=int(stop_time), raw_value=raw_value)

    def serialize(self) -> str:
        return f"{self.start_time} {self.stop_time}"


@dataclass(slots=True)
class SDPTimeRepeat(SDPTimeFields):
    """
    SDP time repeat field, defined in :rfc:`4566#section-5.10`.

    Spec::
        r=<repeat interval> <active duration> <offsets from start-time>
    """

    _type = "r"
    _description = "zero or more repeat times"

    interval: int
    duration: int
    offsets: List[int]

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        # parse the raw value. N.B. offset could be strings to denote days, hours, minutes, seconds, so they need to be converted to ints
        def parse_time(time_str: str) -> int:
            if isinstance(time_str, int):
                return time_str
            multipliers = {"d": 86400, "h": 3600, "m": 60, "s": 1}
            match = re.match(rf"(-?\d+)([{''.join(multipliers)}])", time_str)
            if not match:
                raise SDPParseError(f'Invalid time string "{time_str}" in repeat field: {raw_value}')
            time, unit = match.groups()
            return int(time) * multipliers[unit]

        interval, duration, *offsets = raw_value.split(" ")
        return cls(
            interval=parse_time(interval),
            duration=parse_time(duration),
            offsets=[parse_time(offset) for offset in offsets],
            raw_value=raw_value,
        )

    def serialize(self) -> str:
        if self.raw_value:
            return self.raw_value  # FIXME would this require freezing?
        return f"{self.interval} {self.duration} {' '.join(str(offset) for offset in self.offsets)}"


@dataclass(slots=True)
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
    formats: List[str]

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
            for x in (ports_spec.split("/") if "/" in ports_spec else (ports_spec, None))
        )
        return cls(
            media=media,
            port=port,
            number_of_ports=number_of_ports,
            protocol=protocol,
            formats=formats,
            raw_value=raw_value,
        )

    def serialize(self) -> str:
        return f"{self.media} {self.port} {self.protocol} {' '.join(self.formats)}"


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


@dataclass(slots=True)
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
            raw_value=raw_value,
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
            raw_value=raw_value,
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


@dataclass(slots=True)
class SDPSection(ABC):
    _fields_base: ClassVar[Type[SDPField]]
    _start_field: ClassVar[Type[SDPField]]

    # mapping of {sdptype: (field_name, field_type, wrapped_type), ...}
    _sdp_fields_map: ClassVar[Dict[str, Tuple[str, Any, type]]]
    _subsections_map: ClassVar[Dict[str, Type[SDPSection]]]

    @classmethod
    def _reveal_wrapped_type(cls, field_type: Any) -> Type:
        if isinstance(field_type, str) and field_type in globals():
            field_type = globals()[field_type]
        if get_origin(field_type) in (list, List):
            field_type = field_type.__args__[0]
        field_type = try_unpack_optional_type(field_type)
        if isinstance(field_type, type):
            return field_type
        raise TypeError(f"Unknown field type {field_type}")

    @classmethod
    def _init_fields_map(cls) -> None:
        cls._sdp_fields_map = {}
        cls._subsections_map = {}
        # check annotations
        for field_name, field_type in get_type_hints(cls, globals(), locals()).items():
            # skip ClassVar and InitVar fields
            if get_origin(field_type) in (ClassVar, InitVar):
                continue
            wrapped_type: Type = cls._reveal_wrapped_type(field_type)
            sdp_type: Optional[str] = None
            if issubclass(wrapped_type, SDPField):
                sdp_type = getattr(wrapped_type, "_type")
            elif issubclass(wrapped_type, SDPSection):
                # noinspection PyProtectedMember
                sdp_type = getattr(wrapped_type, "_start_field")._type
                cls._subsections_map[sdp_type] = wrapped_type
            elif not issubclass(wrapped_type, SDPField):
                continue
            if sdp_type is None:
                raise TypeError(f"Unknown field type {wrapped_type}")
            cls._sdp_fields_map[sdp_type] = field_name, field_type, wrapped_type

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        if not hasattr(cls, "_fields_base"):
            raise TypeError(f"SDPSection subclass {cls} must define _fields_base")

        if not hasattr(cls, "_start_field"):
            raise TypeError(f"SDPSection subclass {cls} must define _start_field")

        cls._init_fields_map()

    @classmethod
    def _line_preprocess(cls, line: str, fields: MutableMapping[str, Any]) -> str:
        return line

    @classmethod
    def from_lines(cls, lines: Deque[str], is_subsection=False) -> Self:
        fields: Dict[str, Any] = {}
        while lines:
            line = lines.popleft()
            value: Optional[Union[SDPField, SDPSection]] = None
            sdp_type: Optional[str] = None
            for sdp_type, subsection_type in cls._subsections_map.items():
                if line.startswith(sdp_type + "="):
                    lines.appendleft(line)
                    value = subsection_type.from_lines(lines, is_subsection=True)
                    break
            else:
                line = cls._line_preprocess(line, fields)
                try:
                    value = cls._fields_base.parse(line)  # could raise SDPParseError
                except SDPUnknownFieldError:
                    if is_subsection:
                        lines.appendleft(line)
                        break
                else:
                    assert isinstance(value, SDPField)
                    sdp_type = value.type

            assert sdp_type is not None
            assert value is not None
            field_name, field_type, _ = cls._sdp_fields_map[sdp_type]
            if get_origin(field_type) in (list, List):
                fields.setdefault(field_name, []).append(value)
            else:
                if field_name in fields:
                    raise SDPParseError(f"Duplicate field {field_name}")
                fields[field_name] = value

        # noinspection PyArgumentList
        return cls(**fields)

    @classmethod
    def parse(cls, raw_value: bytes) -> Self:
        """Parse an SDP session from a string"""
        sdp_lines = raw_value.decode("utf-8").split("\r\n")

        to_process_lines: Deque[str] = deque(stripped_line for line in sdp_lines if (stripped_line := line.strip()))
        return cls.from_lines(to_process_lines)

    def serialize(self) -> bytes:
        """Serialize the SDP section to a string"""
        return str(self).encode("utf-8")

    def __str__(self) -> str:
        """Serialize the SDP section to a string"""
        serialized_fields = []
        for field_name, field_type, _ in self._sdp_fields_map.values():
            value = getattr(self, field_name)
            if value is None:
                continue
            if get_origin(field_type) in (list, List):
                serialized_fields.extend(map(str, value))
            else:
                serialized_fields.append(str(value))

        return "\r\n".join(serialized_fields)


# N.B. definition order is important, because we build the fields map in __init_subclass__


@dataclass(slots=True)
class SDPTime(SDPSection):
    _fields_base = SDPTimeFields
    _start_field = SDPTimeTime

    time: SDPTimeTime
    repeat: Optional[SDPTimeRepeat] = None


class SDPMediaFlowType(enum.Enum):
    SENDRECV = "sendrecv"
    SENDONLY = "sendonly"
    RECVONLY = "recvonly"
    INACTIVE = "inactive"


def get_media_flow_type(attributes: List[SDPAttributeField]) -> Optional[SDPMediaFlowType]:
    media_flow_type: Optional[SDPMediaFlowType] = None
    for attribute_field in attributes:
        if isinstance(attribute_field.attribute, MediaFlowAttribute):
            if media_flow_type is not None:
                raise SDPParseError("Multiple media flow attributes in session")
            media_flow_type = SDPMediaFlowType(attribute_field.attribute.name)
    return media_flow_type


class RTPMediaType(enum.Enum):
    AUDIO = "audio"
    VIDEO = "video"


@dataclass(slots=True)
class RTPMediaFormat:  # TODO: or is it SDP? What even is this?
    payload_type: Union[int, str]
    media_type: RTPMediaType
    encoding_name: str
    clock_rate: int
    channels: Optional[int] = None
    format_specific_parameters: Optional[str] = None

    @property
    def mimetype(self) -> str:  # TODO: is this correct?
        return f"{self.media_type.value}/{self.encoding_name}".lower()


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
        if self.connection and self.media.number_of_ports != self.connection.number_of_addresses:
            raise SDPParseError("Number of ports in media and connection fields do not match")

        self._media_formats = self._build_media_formats()

    @property
    def media_flow_type(self) -> Optional[SDPMediaFlowType]:
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
                raise SDPParseError(f"fmtp attribute refers to unknown format: {unmatched_specific_params}")

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
                        format_specific_parameters=fmtp.format_specific_parameters if fmtp else None,
                    )
                )

        return formats


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
    def media_flow_type(self) -> Optional[SDPMediaFlowType]:
        return get_media_flow_type(self.attributes)

    @classmethod
    def _line_preprocess(cls, line: str, fields: MutableMapping[str, Any]) -> str:
        if fields.get("media"):
            raise SDPParseError(f"Session field {line} found after media field")
        return super()._line_preprocess(line, fields)
