from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import InitVar
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
    TYPE_CHECKING,
)
from typing_extensions import Self

from ..exceptions import SDPParseError, SDPUnknownFieldError
from ..helpers import (
    Registry,
    StrValueMixin,
    DEFAULT,
    dataclass,
    try_unpack_optional_type,
)

if TYPE_CHECKING:
    from dataclasses import dataclass


__all__ = [
    "SDPField",
    "SDPAttribute",
    "FlagAttribute",
    "UnknownAttribute",
    "MediaFlowAttribute",
    "RecvOnlyFlag",
    "SendRecvFlag",
    "SendOnlyFlag",
    "InactiveFlag",
    "SDPInformationField",
    "SDPConnectionField",
    "SDPBandwidthField",
    "SDPEncryptionField",
    "SDPAttributeField",
    "SDPSection",
]


@dataclass
class SDPField(Registry[str, "SDPField"], ABC):
    _type: ClassVar[str]
    _description: ClassVar[str]

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
            return cls(**cls.parse_raw_value(raw_value))
        raise NotImplementedError

    @abstractmethod
    def serialize(self) -> str:
        """
        Serialize the field value to a string.

        :return: The serialized field value string.
        """

    def __str__(self) -> str:
        return f"{self.type}={self.serialize()}"


@dataclass
class SDPAttribute(Registry[Union[str, type(DEFAULT)], "SDPAttribute"], ABC):
    _name: ClassVar[Union[str, type(DEFAULT)]]
    _is_flag: ClassVar[Optional[bool]] = None

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_flag(self) -> bool:
        return bool(self._is_flag)

    @classmethod
    def parse(cls, raw_data: str) -> Self:
        name, raw_value = (
            raw_data.split(":", 1) if ":" in raw_data else (raw_data, None)
        )

        if cls._is_flag is not None:
            if cls._is_flag and raw_value is not None:
                raise SDPParseError(
                    f"Attribute {name} is a flag, but got a value: {raw_data}"
                )
            if not cls._is_flag and raw_value is None:
                raise SDPParseError(
                    f"Attribute {name} is not a flag, but got no value: {raw_data}"
                )

        registry_name: str = name.lower()
        is_known_attribute: bool = registry_name in cls.__registry__
        if not is_known_attribute and DEFAULT not in cls.__registry__:
            raise TypeError(
                f"Unknown SDP attribute {name}, and no default attribute class is defined"
            )
        attr_cls: Type[SDPAttribute] = cls.__registry_get_class_for__(
            registry_name if is_known_attribute else DEFAULT
        )

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


@dataclass
class FlagAttribute(SDPAttribute, ABC):
    _is_flag: ClassVar[bool] = True

    @classmethod
    def from_raw_value(cls, name: str, raw_value: Optional[str]) -> Self:
        return cls()

    def serialize(self) -> str:
        raise ValueError("Flag attributes have no value to serialize")


@dataclass
class ValueAttribute(SDPAttribute, ABC):
    value: Any

    @classmethod
    def from_raw_value(cls, name: str, raw_value: Optional[str]) -> Self:
        return cls(value=raw_value)


@dataclass
class UnknownAttribute(StrValueMixin, SDPAttribute, ABC):
    _name = DEFAULT

    attribute: str

    @property
    def name(self) -> str:
        return self.attribute

    @classmethod
    def from_raw_value(cls, name: str, raw_value: Optional[str]) -> Self:
        return cls(attribute=name, value=raw_value)


class MediaFlowAttribute(FlagAttribute, ABC):
    _is_flag = True


@dataclass
class RecvOnlyFlag(MediaFlowAttribute, ABC):
    _name = "recvonly"


@dataclass
class SendRecvFlag(MediaFlowAttribute, ABC):
    _name = "sendrecv"


@dataclass
class SendOnlyFlag(MediaFlowAttribute, ABC):
    _name = "sendonly"


@dataclass
class InactiveFlag(MediaFlowAttribute, ABC):
    _name = "inactive"


@dataclass
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


@dataclass
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
                    raise SDPParseError(
                        f"Invalid connection address {connection_address}"
                    )
                number_of_addresses = int(rest[0])
            else:
                if len(rest) >= 2:
                    raise SDPParseError(
                        f"Invalid connection address {connection_address}"
                    )
                ttl = int(rest[0])
                if len(rest) == 2:
                    number_of_addresses = int(rest[1])
        return cls(
            nettype=nettype,
            addrtype=addrtype,
            address=address,
            ttl=ttl,
            number_of_addresses=number_of_addresses,
        )

    def serialize(self) -> str:
        return " ".join((self.nettype, self.addrtype, self.connection_address))


@dataclass
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
        return cls(bwtype=bwtype, bandwidth=int(bandwidth))

    def serialize(self) -> str:
        return f"{self.bwtype}:{self.bandwidth}"


@dataclass
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
        return cls(method=method, key=key)

    def serialize(self) -> str:
        return f"{self.method}:{self.key}" if self.key else self.method


@dataclass
class SDPAttributeField(SDPField, ABC):
    _type = "a"
    _attribute_cls: ClassVar[Type[SDPAttribute]]

    attribute: SDPAttribute

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        if not hasattr(cls, "_attribute_cls"):
            raise TypeError(
                f"Attribute field class {cls} must have an attribute class defined"
            )

    @property
    def name(self) -> str:
        return self.attribute.name

    @property
    def is_flag(self) -> bool:
        return self.attribute.is_flag

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        return cls(attribute=cls._attribute_cls.parse(raw_value))

    def serialize(self) -> str:
        return str(self.attribute)


@dataclass
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
        for field_name, field_type in get_type_hints(cls).items():
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

        to_process_lines: Deque[str] = deque(
            stripped_line for line in sdp_lines if (stripped_line := line.strip())
        )
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
