from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern, ClassVar, Match

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

from .exceptions import SIPParseError


ALLOWED_SYMBOLS: str = "-_.!~*'()%"

DISPLAY_NAME_PAT: str = r"(?P<display_name>[\"'][^\"']+[\"']|\S.*?)(?=\s*\<)"
CONTACT_PAT: str = rf"(?P<user>[+\w{ALLOWED_SYMBOLS}]+)(?::(?P<password>[\w{ALLOWED_SYMBOLS}]+))?(?=@)"
HOST_PAT: str = r"(?P<host>(?:\w+\.)*\w+)"
SCHEME_PAT: str = r"(?P<scheme>sips?)(?=:)"
URI_PAT: str = rf"(?P<uri>(?:{SCHEME_PAT}:)?{CONTACT_PAT}@{HOST_PAT})"
ADDRESS_PAT: str = rf"^(?:{DISPLAY_NAME_PAT}\s*)?<{URI_PAT}>|{URI_PAT})$"


@dataclass(slots=True, frozen=True)
class SIPURI:
    """A SIP URI"""

    host: str
    port: Optional[int] = None
    user: Optional[str] = None
    password: Optional[str] = None
    scheme: str = "sip"

    _uri_re: ClassVar[Pattern] = re.compile(URI_PAT)

    @classmethod
    def parse(cls, value: str) -> SIPURI:
        """Parse a SIP URI"""
        match: Optional[Match] = cls._uri_re.match(value)
        if match is None:
            raise SIPParseError(f"Invalid SIP URI: {value}")
        return cls(
            host=match.group("host"),
            port=match.group("port"),
            user=match.group("user"),
            password=match.group("password"),
            scheme=match.group("scheme"),
        )

    def __str__(self) -> str:
        password: str = f":{self.password}" if self.password else ""
        login: str = f"{self.user}{password}@" if self.user else ""
        hostname: str = f"{self.host}:{self.port}" if self.port else self.host
        return f"{self.scheme}:{login}{hostname}"


@dataclass(slots=True, frozen=True)
class SIPAddress:
    """A SIP contact address, with an optional display name and a SIP URI."""

    uri: SIPURI
    display_name: Optional[str] = None

    _address_re: ClassVar[Pattern] = re.compile(ADDRESS_PAT)

    @classmethod
    def parse(cls, value: str) -> Self:
        """Parse a SIP address from a string. Optionally with a display name and phone number."""
        match: Optional[Match] = cls._address_re.match(value)
        uri_raw: str = (match and match.group("uri")) or None
        if not match or not uri_raw:
            raise SIPParseError(f"Invalid SIP address: {value}")
        uri: SIPURI = SIPURI.parse(uri_raw)
        return cls(uri=uri, display_name=match.group("display_name"))

    def __str__(self) -> str:
        """Serialize the SIP address to a string."""
        if self.display_name:
            return f'"{self.display_name}" <{self.uri}>'
        return str(self.uri)
