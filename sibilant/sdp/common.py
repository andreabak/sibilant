"""Common base classes for SDP sections, fields and attributes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import InitVar, dataclass
from typing import (
    Any,
    ClassVar,
    List,
    MutableMapping,
    Union,
    cast,
    get_origin,
    get_type_hints,
)

from typing_extensions import Self, override

from sibilant.exceptions import SDPParseError, SDPUnknownFieldError
from sibilant.helpers import (
    DEFAULT,
    DefaultType,
    FieldsParser,
    OptionalStrValueMixin,
    ParseableSerializable,
    ParseableSerializableRaw,
    Registry,
    StrValueMixin,
    try_unpack_optional_type,
)


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
class SDPField(Registry[str, "SDPField"], ParseableSerializable, ABC):
    """Abstract base dataclass for SDP fields."""

    _type: ClassVar[str]
    _description: ClassVar[str]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

        # make sure type is set and register the class into known types
        if ABC not in cls.__bases__ and not getattr(cls, "_description", None):
            raise ValueError(f"SDPField class {cls} must have a _description attribute")

    @property
    def type(self) -> str:
        """The type of the field."""
        return self._type

    @classmethod
    def parse(cls, raw_data: str) -> Self:  # noqa: D102
        field_type, raw_value = raw_data.strip().split("=", 1)

        try:
            field_cls = cls.__registry_get_class_for__(field_type)
        except KeyError:
            raise SDPUnknownFieldError(f"Unknown SDP field type {field_type}")  # noqa: B904

        return cast(
            Self, field_cls.from_raw_value(field_type=field_type, raw_value=raw_value)
        )

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        """
        Parse the raw value of the field into a field object.

        :param field_type: the field type
        :param raw_value: the raw value of the field
        :return: the field object.
        """
        if isinstance(cls, FieldsParser):
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
class SDPAttribute(
    Registry[Union[str, DefaultType], "SDPAttribute"], ParseableSerializable, ABC
):
    """Abstract base dataclass for SDP attributes."""

    _name: ClassVar[str | DefaultType]
    _is_flag: ClassVar[bool | None] = None

    @property
    def name(self) -> str:
        """The name of the attribute."""
        if self._name is DEFAULT:
            raise SyntaxError(
                f"Class {self.__class__} must override name() property when using _name = DEFAULT"
            )
        assert isinstance(self._name, str)
        return self._name

    @property
    def is_flag(self) -> bool:
        """Whether the attribute is a flag or not."""
        return bool(self._is_flag)

    @classmethod
    def parse(cls, raw_data: str) -> Self:  # noqa: D102
        name: str
        raw_value: str | None
        name, raw_value = (
            raw_data.split(":", 1) if ":" in raw_data else (raw_data, None)  # type: ignore[assignment]
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
        attr_cls: type[SDPAttribute] = cls.__registry_get_class_for__(
            registry_name if is_known_attribute else DEFAULT
        )

        return cast(Self, attr_cls.from_raw_value(name, raw_value))

    @classmethod
    @abstractmethod
    def from_raw_value(cls, name: str, raw_value: str | None) -> Self:
        """
        Parse a raw value into an instance of this attribute class.

        :param name: the name of the attribute parsed from raw data
        :param raw_value: the raw value of the attribute parsed from raw data
        :return:
        """

    @abstractmethod
    def serialize(self) -> str:
        """Serialize the attribute value to a string."""

    def __str__(self) -> str:
        """Serialize the whole attribute to a string."""
        return f"{self.name}:{self.serialize()}" if not self.is_flag else self.name


@dataclass
class FlagAttribute(SDPAttribute, ABC):
    """Abstract base dataclass for SDP flag attributes."""

    _is_flag: ClassVar[bool] = True

    @classmethod
    def from_raw_value(cls, name: str, raw_value: str | None) -> Self:  # noqa: D102
        return cls()

    def serialize(self) -> str:  # noqa: D102
        raise ValueError("Flag attributes have no value to serialize")


@dataclass
class ValueAttribute(SDPAttribute, ABC):
    """Abstract base dataclass for SDP value attributes."""

    value: Any

    @classmethod
    def from_raw_value(cls, name: str, raw_value: str | None) -> Self:
        return cls(value=raw_value)


@dataclass
class UnknownAttribute(OptionalStrValueMixin, SDPAttribute, ABC):
    """Abstract base dataclass for parsing unsupported SDP attributes."""

    _name = DEFAULT

    attribute: str

    @property
    def name(self) -> str:
        """The name of the attribute."""
        return self.attribute

    @classmethod
    def from_raw_value(cls, name: str, raw_value: str | None) -> Self:  # noqa: D102
        return cls(attribute=name, value=raw_value)


class MediaFlowAttribute(FlagAttribute, ABC):
    """Abstract base dataclass for SDP media flow attributes, defined in :rfc:`8866#section-6.7`."""

    _is_flag = True


@dataclass
class RecvOnlyFlag(MediaFlowAttribute, ABC):
    """SDP media flow attribute for recvonly, defined in :rfc:`8866#section-6.7.1`."""

    _name = "recvonly"


@dataclass
class SendRecvFlag(MediaFlowAttribute, ABC):
    """SDP media flow attribute for sendrecv, defined in :rfc:`8866#section-6.7.2`."""

    _name = "sendrecv"


@dataclass
class SendOnlyFlag(MediaFlowAttribute, ABC):
    """SDP media flow attribute for sendonly, defined in :rfc:`8866#section-6.7.3`."""

    _name = "sendonly"


@dataclass
class InactiveFlag(MediaFlowAttribute, ABC):
    """SDP media flow attribute for inactive, defined in :rfc:`8866#section-6.7.4`."""

    _name = "inactive"


@dataclass
class SDPInformationField(StrValueMixin, SDPField, ABC):
    """
    SDP session information field, defined in :rfc:`8866#section-5.4`.

    Spec::
        i=<session description>
    """

    _type = "i"

    @property
    def session_description(self) -> str:
        """The session description."""
        return self.value


@dataclass
class SDPConnectionField(SDPField, ABC):
    """
    SDP session connection field, defined in :rfc:`8866#section-5.7`.

    Spec::
        c=<nettype> <addrtype> <connection-address>
    """

    _type = "c"

    nettype: str
    addrtype: str
    address: str
    ttl: int | None = None
    number_of_addresses: int | None = None

    @property
    def connection_address(self) -> str:
        """The connection address as string, with optional TTL and number of addresses."""
        parts = [self.address]
        if self.ttl is not None:
            parts.append(str(self.ttl))
        if self.number_of_addresses is not None:
            parts.append(str(self.number_of_addresses))
        return "/".join(parts)

    @classmethod
    @override
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        nettype, addrtype, connection_address = raw_value.split(" ")
        # parse the connection address. Keep in mind IPv6 don't have TTL,
        # so the second part might be the number of addresses
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

    def serialize(self) -> str:  # noqa: D102
        return " ".join((self.nettype, self.addrtype, self.connection_address))  # noqa: FLY002


@dataclass
class SDPBandwidthField(SDPField, ABC):
    """
    SDP session bandwidth field, defined in :rfc:`8866#section-5.8`.

    Spec::
        b=<bwtype>:<bandwidth>
    """

    _type = "b"

    bwtype: str
    bandwidth: int

    @classmethod
    @override
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        bwtype, bandwidth = raw_value.split(":")
        return cls(bwtype=bwtype, bandwidth=int(bandwidth))

    def serialize(self) -> str:  # noqa: D102
        return f"{self.bwtype}:{self.bandwidth}"


@dataclass
class SDPEncryptionField(SDPField, ABC):
    """
    SDP session encryption field, defined in :rfc:`8866#section-5.12`.

    Spec::
        k=<method>
        k=<method>:<encryption key>
    """

    _type = "k"

    method: str
    key: str | None = None

    @classmethod
    @override
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        method: str
        key: str | None
        method, key = raw_value.split(":") if ":" in raw_value else (raw_value, None)  # type: ignore[assignment]
        return cls(method=method, key=key)

    def serialize(self) -> str:  # noqa: D102
        return f"{self.method}:{self.key}" if self.key else self.method


@dataclass
class SDPAttributeField(SDPField, ABC):
    """Abstract base dataclass for SDP attribute fields."""

    _type = "a"
    _attribute_cls: ClassVar[type[SDPAttribute]]

    attribute: SDPAttribute

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

        if not hasattr(cls, "_attribute_cls"):
            raise TypeError(
                f"Attribute field class {cls} must have an attribute class defined"
            )

    @property
    def name(self) -> str:
        """The name of the attribute."""
        return self.attribute.name

    @property
    def is_flag(self) -> bool:
        """Whether the attribute is a flag or not."""
        return self.attribute.is_flag

    @classmethod
    @override
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        return cls(attribute=cls._attribute_cls.parse(raw_value))

    def serialize(self) -> str:  # noqa: D102
        return str(self.attribute)


@dataclass
class SDPSection(ParseableSerializableRaw, ABC):
    """Abstract base dataclass for SDP sections."""

    _fields_base: ClassVar[type[SDPField]]
    _start_field: ClassVar[type[SDPField]]

    # mapping of {sdptype: (field_name, field_type, wrapped_type), ...}
    _sdp_fields_map: ClassVar[dict[str, tuple[str, Any, type]]]
    _subsections_map: ClassVar[dict[str, type[SDPSection]]]

    @classmethod
    def _reveal_wrapped_type(cls, field_type: Any) -> type:
        if isinstance(field_type, str) and field_type in globals():
            field_type = globals()[field_type]
        if get_origin(field_type) in {list, List}:
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
            if get_origin(field_type) in {ClassVar, InitVar}:
                continue
            wrapped_type: type = cls._reveal_wrapped_type(field_type)
            sdp_type: str | None = None
            if issubclass(wrapped_type, SDPField):
                sdp_type = wrapped_type._type  # noqa: SLF001
            elif issubclass(wrapped_type, SDPSection):
                # noinspection PyProtectedMember
                sdp_type = wrapped_type._start_field._type  # noqa: SLF001
                cls._subsections_map[sdp_type] = wrapped_type
            elif not issubclass(wrapped_type, SDPField):
                continue
            if sdp_type is None:
                raise TypeError(f"Unknown field type {wrapped_type}")
            cls._sdp_fields_map[sdp_type] = field_name, field_type, wrapped_type

    def __init_subclass__(cls, **kwargs: Any) -> None:
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
    def from_lines(cls, lines: deque[str], *, is_subsection: bool = False) -> Self:
        """
        Parse an SDP section from a list of lines.

        :param lines: the lines to parse.
        :param is_subsection: whether the section is a subsection of another section.
        :return: the parsed SDP section.
        """
        fields: dict[str, Any] = {}
        while lines:
            line = lines.popleft()
            value: SDPField | SDPSection | None = None
            sdp_type: str | None = None
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
            if get_origin(field_type) in {list, List}:
                fields.setdefault(field_name, []).append(value)
            else:
                if field_name in fields:
                    raise SDPParseError(f"Duplicate field {field_name}")
                fields[field_name] = value

        # noinspection PyArgumentList
        return cls(**fields)

    @classmethod
    def parse(cls, raw_value: bytes) -> Self:
        """Parse an SDP session from a string."""
        sdp_lines = raw_value.decode("utf-8").split("\r\n")

        to_process_lines: deque[str] = deque(
            stripped_line for line in sdp_lines if (stripped_line := line.strip())
        )
        return cls.from_lines(to_process_lines)

    def serialize(self) -> bytes:
        """Serialize the SDP section to a string."""
        return str(self).encode("utf-8")

    def __str__(self) -> str:
        """Serialize the SDP section to a string."""
        serialized_fields: list[str] = []
        for field_name, field_type, _ in self._sdp_fields_map.values():
            value = getattr(self, field_name)
            if value is None:
                continue
            if get_origin(field_type) in {list, List}:
                serialized_fields.extend(map(str, value))
            else:
                serialized_fields.append(str(value))

        return "\r\n".join(serialized_fields)
