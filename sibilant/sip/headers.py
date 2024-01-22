"""SIP headers classes."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import field as dataclass_field, fields as dataclass_fields
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Mapping,
    TypeVar,
    Union,
    cast,
)

from typing_extensions import Self, override

from sibilant.exceptions import SIPParseError
from sibilant.helpers import (
    DEFAULT,
    CaseInsensitiveDict,
    DefaultType,
    IntValueMixin,
    ListValueMixin,
    ParseableSerializable,
    Registry,
    StrValueMixin,
    SupportsStr,
    slots_dataclass,
)
from sibilant.structures import SIPAddress


if TYPE_CHECKING:
    from .messages import SIPMethod


__all__ = [
    "Header",
    "StrHeader",
    "UnknownHeader",
    "IntHeader",
    "ListHeader",
    "MultipleValuesHeader",
    "ViaEntry",
    "ViaHeader",
    "FromToHeader",
    "FromHeader",
    "ToHeader",
    "Contact",
    "ContactHeader",
    "RouteHeader",
    "RecordRouteHeader",
    "CallIDHeader",
    "CSeqHeader",
    "AllowHeader",
    "SupportedHeader",
    "ExpiresHeader",
    "ContentTypeHeader",
    "ContentLengthHeader",
    "MaxForwardsHeader",
    "UserAgentHeader",
    "AuthorizationHeader",
    "WWWAuthenticateHeader",
    "ProxyAuthorizationHeader",
    "ProxyAuthenticateHeader",
    "Headers",
]


_H = TypeVar("_H", bound="Header")


class Header(
    Registry[Union[str, DefaultType], "Header"],
    ABC,
    registry=True,
    registry_attr="_name",
):
    """Abstract base dataclass for SIP headers."""

    _name: ClassVar[str | DefaultType]

    @property
    def name(self) -> str:
        """The name of the header."""
        if self._name is DEFAULT:
            raise SyntaxError(
                f"Class {self.__class__} must override name() property when using _name = DEFAULT"
            )
        assert isinstance(self._name, str)
        return self._name

    @property
    def raw_value(self) -> str:
        """The raw value of the header."""
        return self.serialize()

    @classmethod
    def parse(
        cls, header: str, values: str | list[str], previous_headers: Headers
    ) -> Self:
        """
        Parse a raw header into a header object, picking the correct class.

        :param header: the header name
        :param values: the raw values of the header
        :param previous_headers: the previous headers that have been already parsed
        :return: the new header object.
        """
        known_header: bool = header in cls.__registry__
        if not known_header and DEFAULT not in cls.__registry__:
            raise TypeError(
                f"Unknown header {header}, and no default header class is defined"
            )
        header_cls: type[Header] = cls.__registry_get_class_for__(
            header if known_header else DEFAULT
        )
        if isinstance(values, str):
            values = [values]
        assert values, "At least one value must be present"
        if len(values) > 1:
            if not issubclass(header_cls, MultipleValuesHeader):
                raise SIPParseError(
                    f"Multiple values for header {header}, but header is not a MultipleValuesHeader"
                )
            value = ListHeader._separator.join(values)  # noqa: SLF001
        else:
            value = values[0]
        return cast(Self, header_cls.from_raw_value(header, value, previous_headers))

    @classmethod
    @abstractmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        """
        Parse the header value from a string.

        :param header: the header name
        :param value: The raw header value string.
        :param previous_headers: The previous headers in the message.
        :return: The parsed header.
        """

    @abstractmethod
    def serialize(self) -> str:
        """Serialize the header value to a string."""

    def __str__(self) -> str:
        """Serialize the entire header to a string."""
        return f"{self.name}: {self.serialize()}"


@slots_dataclass
class StrHeader(StrValueMixin, Header, ABC):
    """Abstract base dataclass for headers with a single string value."""

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:  # noqa: D102
        return cls(**cls.parse_raw_value(value))


@slots_dataclass
class UnknownHeader(StrHeader):
    """Catch-all dataclass for unsupported SIP headers."""

    _name = DEFAULT

    header: str

    @property
    @override
    def name(self) -> str:
        return self.header

    @classmethod
    @override
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        return cls(header=header, value=value)


@slots_dataclass
class IntHeader(IntValueMixin, Header, ABC):
    """Abstract base dataclass for headers with a single integer value."""

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:  # noqa: D102
        return cls(**cls.parse_raw_value(value))


_ST = TypeVar("_ST", bound=Union[SupportsStr, ParseableSerializable])


class ListHeader(ListValueMixin[_ST], Header, ABC):
    """Abstract base dataclass for headers with a list of values."""

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:  # noqa: D102
        return cls(**cls.parse_raw_value(value))


class MultipleValuesHeader(ListHeader[_ST], ABC):
    """Abstract base dataclass for headers which can appear multiple times."""

    _prefers_separate_lines: ClassVar[bool] = False

    @override
    def __str__(self) -> str:
        if self._prefers_separate_lines:
            return "\r\n".join(f"{self.name}: {v}" for v in self._serialized_values())
        return f"{self.name}: {self.serialize()}"


@slots_dataclass
class ViaEntry(ParseableSerializable):
    """A single Via entry as part of a Via header, as described in :rfc:`3261#section-20.42`."""

    method: str
    address: str
    port: int | None
    branch: str | None = None
    maddr: str | None = None
    received: str | None = None
    ttl: int | None = None
    extension: dict[str, str | None] = dataclass_field(default_factory=dict)

    _order: tuple[str, ...] = ()

    @property
    def rport(self) -> bool | int | None:
        """The rport parameter, if present."""
        if self.extension and "rport" in self.extension:
            return int(self.extension["rport"]) if self.extension["rport"] else True
        return None

    @rport.setter
    def rport(self, value: bool | int | None) -> None:
        if not value:
            self.extension.pop("rport", None)
        elif isinstance(value, bool):
            self.extension["rport"] = None
        else:
            assert isinstance(value, int)
            self.extension["rport"] = str(value)

    @classmethod
    def parse(cls, value: str) -> Self:  # noqa: D102
        method, address, *params = re.split(r"\s+|\s*;\s*", value.strip())

        ip, port_str = address.split(":") if ":" in address else (address, None)
        port = int(port_str) if port_str else None

        order = []
        parsed_params: dict[str, str | int | None] = {}
        extension_params: dict[str, str | None] = {}
        for param in params:
            param_name: str
            param_value: str | int | None
            param_name, param_value = (
                param.split("=", maxsplit=1) if "=" in param else (param, None)
            )
            if param_name == "ttl":
                param_value = int(param_value) if param_value is not None else None
            assert isinstance(param_value, str) or param_value is None
            if param_name in {"branch", "maddr", "received", "ttl"}:
                parsed_params[param_name] = param_value
            else:
                extension_params[param_name] = param_value
            order.append(param_name)

        return cls(
            method=method,
            address=ip,
            port=port,
            **parsed_params,  # type: ignore[arg-type]
            extension=extension_params,
            _order=tuple(order),
        )

    def serialize(self) -> str:  # noqa: D102
        host = f"{self.address}:{self.port}" if self.port else self.address
        params_dict = {
            param_name: param_value
            for param_name in ("branch", "maddr", "received", "ttl")
            if (param_value := getattr(self, param_name)) is not None
        }
        params_dict.update(self.extension or {})
        sorted_params = {**dict.fromkeys(self._order), **params_dict}
        params = [
            f";{param_name}={param_value}"
            if param_value is not None
            else f";{param_name}"
            for param_name, param_value in (sorted_params.items())
        ]
        return f"{self.method} {host}{''.join(params)}"


@slots_dataclass
class ViaHeader(MultipleValuesHeader[ViaEntry]):
    """Via header, as described in :rfc:`3261#section-20.42`."""

    _name = "Via"
    _prefers_separate_lines = True
    _values_type = ViaEntry

    @property
    def first(self) -> ViaEntry:
        """The first via entry in the header."""
        return self.values[0]

    def __post_init__(self) -> None:
        if not self.values:
            raise SIPParseError("Via header must have at least one entry")


@slots_dataclass
class FromToHeader(Header, ABC):
    """Abstract base dataclass for From and To headers."""

    address: SIPAddress
    raw_address: str | None = None
    tag: str | None = None

    def __post_init__(self) -> None:
        if self.raw_address is None:
            self.raw_address = str(self.address)

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:  # noqa: D102
        raw_address, *taginfo = re.split(r"\s*;\s*tag=", value.strip(), maxsplit=1)
        tag = taginfo[0] if taginfo else None
        address = SIPAddress.parse(raw_address)
        return cls(address=address, raw_address=raw_address, tag=tag)

    def serialize(self) -> str:  # noqa: D102
        assert self.raw_address is not None
        if self.tag:
            return f"{self.raw_address};tag={self.tag}"
        return self.raw_address


@slots_dataclass
class FromHeader(FromToHeader):
    """From header, as described in :rfc:`3261#section-20.20`."""

    _name = "From"


@slots_dataclass
class ToHeader(FromToHeader):
    """To header, as described in :rfc:`3261#section-20.39`."""

    _name = "To"


@slots_dataclass
class Contact(ParseableSerializable):
    """A single contact as part of a contact header, as described in :rfc:`3261#section-20.10`."""

    address: SIPAddress
    params: dict[str, str | None] = dataclass_field(default_factory=dict)

    @property
    def q(self) -> float | None:
        """The q parameter, if present."""
        if self.params and isinstance(
            (q_str := self.params.get("q")), (str, int, float)
        ):
            return float(q_str)
        return None

    @q.setter
    def q(self, value: float | None) -> None:
        if self.params is None:
            self.params = {}
        if value is None:
            self.params.pop("q", None)
        else:
            self.params["q"] = str(value)

    @property
    def expires(self) -> int | None:
        """The expires parameter, if present."""
        if self.params and isinstance(
            (expires_str := self.params.get("expires")), (str, int, float)
        ):
            return int(expires_str)
        return None

    @expires.setter
    def expires(self, value: int | None) -> None:
        if self.params is None:
            self.params = {}
        if value is None:
            self.params.pop("expires", None)
        else:
            self.params["expires"] = str(value)

    @classmethod
    def parse(cls, value: str) -> Self:  # noqa: D102
        params: dict[str, str | None] = {}

        force_brackets: bool = "<" in value and ">" in value
        if ";" in value:  # there are parameters, address will be in <...> form.
            address_raw, *params_raw = re.split(r"(?<=>)\s*;\s*", value, maxsplit=1)
            if params_raw:
                for param in re.split(r"\s*;\s*", params_raw[0]):
                    param_name, param_value = param.split("=", maxsplit=1)
                    param_name = param_name.strip()
                    param_value = param_value.strip()
                    params[param_name] = param_value
            force_brackets = True
        else:
            address_raw = value

        address = SIPAddress.parse(address_raw.strip(), force_brackets=force_brackets)
        return cls(address=address, params=params)

    def serialize(self) -> str:  # noqa: D102
        params = [f";{name}={value}" for name, value in self.params.items()]
        return f"{self.address}{''.join(params)}"


@slots_dataclass
class ContactHeader(MultipleValuesHeader[Contact]):
    """
    Contact header, as described in :rfc:`3261#section-20.10`.

    Multiple contacts might be present in a single header, separated by commas.
    """

    _name = "Contact"
    _values_type = Contact

    # TODO: * contact (see RFC?)

    @property
    def contact(self) -> Contact:
        """The first contact in the header."""
        return self.values[0]


@slots_dataclass
class RouteHeader(ContactHeader):
    """Route header, as described in :rfc:`3261#section-20.34`."""

    _name = "Route"


@slots_dataclass
class RecordRouteHeader(RouteHeader):
    """Record-Route header, as described in :rfc:`3261#section-20.30`."""

    _name = "Record-Route"


@slots_dataclass
class CallIDHeader(StrHeader):
    """Call-ID header, as described in :rfc:`3261#section-20.8`."""

    _name = "Call-ID"


@slots_dataclass
class CSeqHeader(Header):
    """CSeq header, as described in :rfc:`3261#section-20.16`."""

    _name = "CSeq"

    sequence: int
    method: SIPMethod

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:  # noqa: D102
        from .messages import SIPMethod  # noqa: PLC0415

        sequence, method_raw = value.split(maxsplit=1)
        method = SIPMethod(method_raw)
        return cls(sequence=int(sequence), method=method)

    def serialize(self) -> str:  # noqa: D102
        return f"{self.sequence} {self.method.name}"


@slots_dataclass
class AllowHeader(MultipleValuesHeader[str]):
    """Allow header, as described in :rfc:`3261#section-20.5`."""

    _name = "Allow"
    _values_type = str


@slots_dataclass
class AcceptHeader(MultipleValuesHeader[str]):
    """Accept header, as described in :rfc:`3261#section-20.1`."""

    _name = "Accept"
    _values_type = str


@slots_dataclass
class SupportedHeader(MultipleValuesHeader[str]):
    """Supported header, as described in :rfc:`3261#section-20.37`."""

    _name = "Supported"
    _values_type = str


@slots_dataclass
class ExpiresHeader(IntHeader):
    """Expires header, as described in :rfc:`3261#section-20.19`."""

    _name = "Expires"


@slots_dataclass
class ContentTypeHeader(StrHeader):
    """Content-Type header, as described in :rfc:`3261#section-20.15`."""

    _name = "Content-Type"


@slots_dataclass
class ContentLengthHeader(IntHeader):
    """Content-Length header, as described in :rfc:`3261#section-20.14`."""

    _name = "Content-Length"


@slots_dataclass
class MaxForwardsHeader(IntHeader):
    """Max-Forwards header, as described in :rfc:`3261#section-20.22`."""

    _name = "Max-Forwards"


@slots_dataclass
class UserAgentHeader(StrHeader):
    """User-Agent header, as described in :rfc:`3261#section-20.41`."""

    _name = "User-Agent"


@slots_dataclass
class AuthorizationHeader(Header):
    """Authorization header, as described in :rfc:`3261#section-20.7`."""

    _name = "Authorization"

    username: str | None = None
    realm: str | None = None
    nonce: str | None = None
    uri: str | None = None
    algorithm: str | None = None
    qop: str | None = None
    nc: str | None = None
    cnonce: str | None = None
    response: str | None = None
    opaque: str | None = None
    stale: bool | None = None
    auth_params: dict[str, str] | None = None

    _order: tuple[str, ...] = ()

    _no_quote_params: ClassVar[set[str]] = {"algorithm", "stale", "qop", "nc"}

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:  # noqa: D102
        scheme, params_str = value.split(maxsplit=1)
        if scheme.lower() != "digest":
            raise SIPParseError(f"Unsupported authorization scheme: {scheme}")
        # split by commas, remove whitespaces, split by equal sign, remove quotes
        # FIXME: quoted values might contain commas!
        params = {
            key: value.strip('"')
            for key, value in (
                param.strip().split("=", maxsplit=1)
                for param in params_str.strip().split(",")
            )
        }
        # TODO: qop can be a comma-separated list of values and might be quoted
        known_param_names = {f.name for f in dataclass_fields(cls)} - {"auth_params"}
        known_params: dict[str, Any] = {
            name: value for name, value in params.items() if name in known_param_names
        }
        if "stale" in known_params:
            known_params["stale"] = known_params["stale"].lower() == "true"
        auth_params = {
            name: value for name, value in params.items() if name not in known_params
        }
        return cls(
            **known_params,
            auth_params=auth_params or None,
            _order=tuple(params),  # type: ignore[arg-type]
        )

    def serialize(self) -> str:  # noqa: D102
        params_dict: dict[str, str] = {}
        for field in dataclass_fields(self):
            if field.name in {"auth_params", "_order"}:
                continue
            value = getattr(self, field.name)
            if value is not None:
                str_value = str(value)
                if isinstance(value, bool):
                    str_value = str_value.upper()
                params_dict[field.name] = str_value
        if self.auth_params:
            # noinspection PyTypeChecker
            params_dict.update(self.auth_params)
        sorted_params = {**dict.fromkeys(self._order), **params_dict}
        params = [
            (name, (f'"{value}"' if name not in self._no_quote_params else str(value)))
            for name, value in sorted_params.items()
        ]
        return f"Digest {', '.join(f'{name}={value}' for name, value in params)}"


@slots_dataclass
class WWWAuthenticateHeader(AuthorizationHeader):
    """WWW-Authenticate header, as described in :rfc:`3261#section-20.44`."""

    _name = "WWW-Authenticate"


@slots_dataclass
class ProxyAuthorizationHeader(AuthorizationHeader):
    """Proxy-Authorization header, as described in :rfc:`3261#section-20.28`."""

    _name = "Proxy-Authorization"


@slots_dataclass
class ProxyAuthenticateHeader(WWWAuthenticateHeader):
    """Proxy-Authenticate header, as described in :rfc:`3261#section-20.27`."""

    _name = "Proxy-Authenticate"


class Headers(CaseInsensitiveDict[_H]):
    """
    A case-insensitive dictionary of SIP headers, with some additional parsing
    and serialization methods to handle raw headers from/to SIP messages.

    The dictionary keys are the header names, and the values are the parsed header objects.

    :param headers: the headers to initialize the dictionary with.
    :param data: additional headers to initialize the dictionary with, as a mapping.
    :param kwargs: additional headers to initialize the dictionary with, as keyword arguments.
    """

    def __init__(
        self, *headers: _H, data: Mapping[str, _H] | None = None, **kwargs: _H
    ):
        if headers:
            data = dict(data) if data else {}
            for header in headers:
                data[header.name] = header

        super().__init__(data, **kwargs)

    @classmethod
    def parse(cls, raw_headers: bytes) -> Self:
        """
        Parse a raw SIP message into a dictionary of headers.

        :param raw_headers: the raw headers
        :return: the parsed headers.
        """
        headers = cls()

        header_lines = raw_headers.decode("utf-8").split("\r\n")
        headers_values = defaultdict(list)
        for line in header_lines:
            header, raw_value = line.split(": ", maxsplit=1)
            headers_values[header].append(raw_value)

        for header, raw_values in headers_values.items():
            headers[header] = cast(_H, Header.parse(header, raw_values, headers))

        return headers

    def serialize(self) -> bytes:
        """
        Serialize the headers to a raw SIP message.

        :return: the raw headers.
        """
        return str(self).encode("utf-8")

    def __str__(self) -> str:
        return "\r\n".join(str(header) for header in self.values())
