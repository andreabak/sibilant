from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import fields as dataclass_fields, field as dataclass_field
from typing import (
    ClassVar,
    Union,
    Dict,
    Type,
    Optional,
    TYPE_CHECKING,
    TypeVar,
    Mapping,
    List,
    Set,
    Tuple,
)

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

from ..helpers import (
    CaseInsensitiveDict,
    StrValueMixin,
    IntValueMixin,
    ListValueMixin,
    Registry,
    DEFAULT,
    dataclass,
)
from ..structures import SIPAddress
from ..exceptions import SIPParseError

if TYPE_CHECKING:
    from .messages import SIPMethod
    from dataclasses import dataclass


__all__ = [
    "Header",
    "StrHeader",
    "UnknownHeader",
    "IntHeader",
    "ListHeader",
    "ViaHeader",
    "FromToHeader",
    "FromHeader",
    "ToHeader",
    "Contact",
    "ContactHeader",
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
    Registry[Union[str, type(DEFAULT)], "Header"],
    ABC,
    registry=True,
    registry_attr="_name",
):
    _name: ClassVar[Union[str, type(DEFAULT)]]

    @property
    def name(self) -> str:
        """The name of the header."""
        return self._name

    @property
    def raw_value(self) -> str:
        """The raw value of the header."""
        return self.serialize()

    @classmethod
    def parse(cls, header: str, value: str, previous_headers: Headers) -> Self:
        """
        Parse a raw header into a header object, picking the correct class.

        :param header: the header name
        :param value: the raw value of the header
        :param previous_headers: the previous headers that have been already parsed
        :return: the new header object
        """
        known_header: bool = header in cls.__registry__
        if not known_header and DEFAULT not in cls.__registry__:
            raise TypeError(
                f"Unknown header {header}, and no default header class is defined"
            )
        header_cls: Type[Header] = cls.__registry_get_class_for__(
            header if known_header else DEFAULT
        )
        return header_cls.from_raw_value(header, value, previous_headers)

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


@dataclass
class StrHeader(StrValueMixin, Header, ABC):
    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        return cls(**cls.parse_raw_value(value))


@dataclass(slots=True)
class UnknownHeader(StrHeader):
    _name = DEFAULT

    header: str

    @property
    def name(self) -> str:
        return self.header

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        return cls(header=header, value=value)


@dataclass
class IntHeader(IntValueMixin, Header, ABC):
    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        return cls(**cls.parse_raw_value(value))


class ListHeader(ListValueMixin, Header, ABC):
    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        return cls(**cls.parse_raw_value(value))


@dataclass(slots=True)
class ViaHeader(Header):
    _name = "Via"

    method: str
    address: str
    port: Optional[int]
    branch: Optional[str] = None
    maddr: Optional[str] = None
    received: Optional[str] = None
    ttl: Optional[int] = None
    extension: Dict[str, Optional[str]] = dataclass_field(default_factory=dict)

    _order: Tuple[str, ...] = ()

    @property
    def rport(self) -> Union[bool, int, None]:
        if self.extension and "rport" in self.extension:
            return int(self.extension["rport"]) if self.extension["rport"] else True
        return None

    @rport.setter
    def rport(self, value: Union[bool, int, None]) -> None:
        if not value:
            self.extension.pop("rport", None)
        elif isinstance(value, bool):
            self.extension["rport"] = None
        else:
            assert isinstance(value, int)
            self.extension["rport"] = str(value)

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        # ignore if there already is a via header
        if "Via" in previous_headers:
            return previous_headers["Via"]

        method, address, *params = re.split(r"\s+|\s*;\s*", value.strip())

        ip, port_str = address.split(":") if ":" in address else (address, None)
        port = int(port_str) if port_str else None

        order = []
        parsed_params = {}
        extension_params = {}
        for param in params:
            param_name: str
            param_value: Optional[str]
            param_name, param_value = (
                param.split("=", maxsplit=1) if "=" in param else (param, None)
            )
            if param_name in ("ttl",):
                param_value = int(param_value) if param_value is not None else None
            if param_name in ("branch", "maddr", "received", "ttl"):
                parsed_params[param_name] = param_value
            else:
                extension_params[param_name] = param_value
            order.append(param_name)

        return cls(
            method=method,
            address=ip,
            port=port,
            **parsed_params,
            extension=extension_params,
            _order=tuple(order),
        )

    def serialize(self) -> str:
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


@dataclass
class FromToHeader(Header, ABC):
    address: SIPAddress
    raw_address: Optional[str] = None
    tag: Optional[str] = None

    def __post_init__(self):
        if self.raw_address is None:
            self.raw_address = str(self.address)

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        raw_address, *taginfo = re.split(r"\s*;\s*tag=", value.strip(), maxsplit=1)
        tag = taginfo[0] if taginfo else None
        address = SIPAddress.parse(raw_address)
        return cls(address=address, raw_address=raw_address, tag=tag)

    def serialize(self) -> str:
        if self.tag:
            return f"{self.raw_address};tag={self.tag}"
        return self.raw_address


@dataclass(slots=True)
class FromHeader(FromToHeader):
    _name = "From"


@dataclass(slots=True)
class ToHeader(FromToHeader):
    _name = "To"


@dataclass(slots=True)
class Contact:
    """
    A single contact as part of a contact header, as described in :rfc:`3261#section-20.10`.
    """

    address: SIPAddress
    params: Dict[str, Optional[str]] = dataclass_field(default_factory=dict)

    @property
    def q(self) -> Optional[float]:
        return float(self.params["q"]) if self.params and "q" in self.params else None

    @q.setter
    def q(self, value: Optional[float]) -> None:
        if self.params is None:
            self.params = {}
        if value is None:
            self.params.pop("q", None)
        else:
            self.params["q"] = str(value)

    @property
    def expires(self) -> Optional[int]:
        return (
            int(self.params["expires"])
            if self.params and "expires" in self.params
            else None
        )

    @expires.setter
    def expires(self, value: Optional[int]) -> None:
        if self.params is None:
            self.params = {}
        if value is None:
            self.params.pop("expires", None)
        else:
            self.params["expires"] = str(value)

    @classmethod
    def parse(cls, value: str) -> Self:
        params: Dict[str, Optional[str]] = {}

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

    def serialize(self) -> str:
        params = [f";{name}={value}" for name, value in self.params.items()]
        return f"{self.address}{''.join(params)}"


@dataclass(slots=True)
class ContactHeader(Header):
    """
    Implements a SIP Contact header as described in :rfc:`3261#section-20.10`.
    Multiple contacts might be present in a single header, separated by commas.
    """

    _name = "Contact"

    contacts: List[Contact]

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        # TODO: check if we might encounter commas that do not represent multiple contacts
        contacts = [Contact.parse(contact) for contact in re.split(r"\s*,\s*", value)]
        return cls(contacts=contacts)

    def serialize(self) -> str:
        return ",".join(contact.serialize() for contact in self.contacts)


@dataclass(slots=True)
class CallIDHeader(StrHeader):
    _name = "Call-ID"


@dataclass(slots=True)
class CSeqHeader(Header):
    _name = "CSeq"

    sequence: int
    method: SIPMethod

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        from .messages import SIPMethod

        sequence, method_raw = value.split(maxsplit=1)
        method = SIPMethod(method_raw)
        return cls(sequence=int(sequence), method=method)

    def serialize(self) -> str:
        return f"{self.sequence} {self.method.name}"


@dataclass(slots=True)
class AllowHeader(ListHeader):
    _name = "Allow"


@dataclass(slots=True)
class AcceptHeader(ListHeader):
    _name = "Accept"


@dataclass(slots=True)
class SupportedHeader(ListHeader):
    _name = "Supported"


@dataclass(slots=True)
class ExpiresHeader(IntHeader):
    _name = "Expires"


@dataclass(slots=True)
class ContentTypeHeader(StrHeader):
    _name = "Content-Type"


@dataclass(slots=True)
class ContentLengthHeader(IntHeader):
    _name = "Content-Length"


@dataclass(slots=True)
class MaxForwardsHeader(IntHeader):
    _name = "Max-Forwards"


@dataclass(slots=True)
class UserAgentHeader(StrHeader):
    _name = "User-Agent"


@dataclass(slots=True)
class AuthorizationHeader(Header):
    _name = "Authorization"

    username: Optional[str] = None
    realm: Optional[str] = None
    nonce: Optional[str] = None
    uri: Optional[str] = None
    algorithm: Optional[str] = None
    qop: Optional[str] = None
    nc: Optional[str] = None
    cnonce: Optional[str] = None
    response: Optional[str] = None
    opaque: Optional[str] = None
    stale: Optional[bool] = None
    auth_params: Optional[Dict[str, str]] = None

    _order: Tuple[str, ...] = ()

    _no_quote_params: ClassVar[Set[str]] = {"algorithm", "stale", "qop", "nc"}

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        scheme, params = value.split(maxsplit=1)
        if scheme.lower() != "digest":
            raise SIPParseError(f"Unsupported authorization scheme: {scheme}")
        # split by commas, remove whitespaces, split by equal sign, remove quotes
        # FIXME: quoted values might contain commas!
        params = {
            key: value.strip('"')
            for key, value in (
                param.strip().split("=", maxsplit=1)
                for param in params.strip().split(",")
            )
        }
        # TODO: qop can be a comma-separated list of values and might be quoted
        known_param_names = {f.name for f in dataclass_fields(cls)} - {"auth_params"}
        known_params = {
            name: value for name, value in params.items() if name in known_param_names
        }
        if "stale" in known_params:
            known_params["stale"] = known_params["stale"].lower() == "true"
        auth_params = {
            name: value for name, value in params.items() if name not in known_params
        }
        return cls(
            **known_params, auth_params=auth_params or None, _order=tuple(params)
        )

    def serialize(self) -> str:
        params_dict: Dict[str, str] = {}
        for field in dataclass_fields(self):
            if field.name in ("auth_params", "_order"):
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


@dataclass(slots=True)
class WWWAuthenticateHeader(AuthorizationHeader):
    _name = "WWW-Authenticate"


@dataclass(slots=True)
class ProxyAuthorizationHeader(AuthorizationHeader):
    _name = "Proxy-Authorization"


@dataclass(slots=True)
class ProxyAuthenticateHeader(WWWAuthenticateHeader):
    _name = "Proxy-Authenticate"


class Headers(CaseInsensitiveDict[_H]):
    def __init__(
        self, *headers: Header, data: Optional[Mapping[str, _H]] = None, **kwargs
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
        :return: the parsed headers
        """
        headers: Headers = cls()

        header_lines = raw_headers.decode("utf-8").split("\r\n")
        for line in header_lines:
            header, raw_value = line.split(": ", maxsplit=1)
            # TODO: better handle, or warn, about duplicate headers
            headers[header] = Header.parse(header, raw_value, headers)

        return headers

    def serialize(self) -> bytes:
        """
        Serialize the headers to a raw SIP message.

        :return: the raw headers
        """
        return str(self).encode("utf-8")

    def __str__(self) -> str:
        return "\r\n".join(str(header) for header in self.values())
