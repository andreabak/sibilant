from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import fields as dataclass_fields
from typing import ClassVar, Union, Dict, Type, Optional, TYPE_CHECKING, TypeVar

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
from ..constants import DEFAULT_SIP_PORT
from ..structures import SIPAddress
from ..exceptions import SIPParseError

if TYPE_CHECKING:
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
    "CSeqHeader",
    "AllowHeader",
    "SupportedHeader",
    "ContentLengthHeader",
    "AuthorizationHeader",
    "WWWAuthenticateHeader",
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


@dataclass(slots=True)
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


@dataclass(slots=True)
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
    port: int
    branch: Optional[str] = None
    maddr: Optional[str] = None
    received: Optional[str] = None
    rport: Optional[int] = None
    ttl: Optional[int] = None
    extension: Optional[Dict[str, Optional[str]]] = None

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        # ignore if there already is a via header
        if "Via" in previous_headers:
            return previous_headers["Via"]

        method, address, *params = re.split(r"\s+|\s*;\s*", value.strip())
        ip, port_str = (
            address.split(":") if ":" in address else (address, str(DEFAULT_SIP_PORT))
        )
        port = int(port_str)
        parsed_params = {}
        extension_params = {}
        for param in params:
            param_name: str
            param_value: Optional[str]
            param_name, param_value = (
                param.split("=", maxsplit=1) if "=" in param else (param, None)
            )
            if param_name in ("rport", "ttl"):
                param_value = int(param_value) if param_value is not None else None
            if param_name in ("branch", "maddr", "received", "rport", "ttl"):
                parsed_params[param_name] = param_value
            else:
                extension_params[param_name] = param_value
        return cls(
            method=method,
            address=ip,
            port=port,
            **parsed_params,
            extension=extension_params or None,
        )

    def serialize(self) -> str:
        params = [
            f"{param_name}={param_value}"
            for param_name in ("branch", "maddr", "received", "rport", "ttl")
            if (param_value := getattr(self, param_name)) is not None
        ]
        if self.extension:
            params.extend(
                f"{param_name}={param_value}"
                for param_name, param_value in self.extension.items()
            )
        return f"{self.method} {self.address}:{self.port} {';'.join(params)}"


@dataclass(slots=True)
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
class CSeqHeader(Header):
    _name = "CSeq"

    sequence: int
    method: str

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        sequence, method = value.split()
        return cls(sequence=int(sequence), method=method)

    def serialize(self) -> str:
        return f"{self.sequence} {self.method}"


@dataclass(slots=True)
class AllowHeader(ListHeader):
    _name = "Allow"


@dataclass(slots=True)
class SupportedHeader(ListHeader):
    _name = "Supported"


@dataclass(slots=True)
class ContentLengthHeader(IntHeader):
    _name = "Content-Length"


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
    auth_params: Optional[Dict[str, str]] = None

    @classmethod
    def from_raw_value(cls, header: str, value: str, previous_headers: Headers) -> Self:
        scheme, params = value.split(maxsplit=1)
        if scheme.lower() != "digest":
            raise SIPParseError(f"Unsupported authorization scheme: {scheme}")
        # split by commas, remove whitespaces, split by equal sign, remove quotes
        params = {
            key: value.strip('"')
            for key, value in (
                param.strip().split("=", maxsplit=1)
                for param in params.strip().split(",")
            )
        }
        known_param_names = {f.name for f in dataclass_fields(cls)} - {"auth_params"}
        known_params = {
            name: value for name, value in params.items() if name in known_param_names
        }
        auth_params = {
            name: value for name, value in params.items() if name not in known_params
        }
        return cls(**known_params, auth_params=auth_params or None)

    def serialize(self) -> str:
        params = []
        for field in dataclass_fields(self):
            if field.name in ("auth_params",):
                continue
            value = getattr(self, field.name)
            if value is not None:
                params.append(f"{field.name}={value}")
        if self.auth_params:
            params.extend(f"{name}={value}" for name, value in self.auth_params.items())
        return f"Digest {', '.join(params)}"


@dataclass(slots=True)
class WWWAuthenticateHeader(AuthorizationHeader):
    _name = "WWW-Authenticate"


class Headers(CaseInsensitiveDict[_H]):
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
