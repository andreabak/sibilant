from __future__ import annotations

import re
from dataclasses import field as dataclass_field
from typing import Optional, Pattern, ClassVar, Match, Collection, Dict, Mapping, TYPE_CHECKING

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

from frozendict import frozendict

from .exceptions import SIPParseError
from .helpers import dataclass

if TYPE_CHECKING:
    from dataclasses import dataclass


ALLOWED_SYMBOLS: str = r"_.!~*'()%\-"
UW = ALLOWED_SYMBOLS

DISPLAY_NAME_PAT: str = r"(?P<display_name>[\"'][^\"']+[\"']|\S.*?)(?=\s*\<)"
CONTACT_PAT: str = rf"(?P<user>[+\w{UW}]+)(?::(?P<password>[\w{UW}]+))?(?=@)"
HOST_PAT: str = r"(?P<host>(?:\w+\.)*\w+)(?::(?P<port>\d+))?"
SCHEME_PAT: str = r"(?P<scheme>sips?)(?=:)"
PARAMS_PAT: str = rf"(?P<params>(?:;[\w{UW}]+(?:=[\w{UW}]+)?)+)"
HEADERS_PAT: str = rf"(?=\?)(?P<headers>(?:[?&][\w{UW}]+=[\w{UW}]+)+)"
URI_PAT: str = rf"(?P<uri>(?:{SCHEME_PAT}:)?(?:{CONTACT_PAT}@)?{HOST_PAT}(?:{PARAMS_PAT})?(?:{HEADERS_PAT})?)"
ADDRESS_PATS: Collection[str] = [rf"(?:{DISPLAY_NAME_PAT}\s*)?<{URI_PAT}>", URI_PAT]


@dataclass(slots=True, frozen=True)
class SIPURI:
    """A SIP URI"""

    host: str
    port: Optional[int] = None
    user: Optional[str] = None
    password: Optional[str] = None
    scheme: str = "sip"
    params: Mapping[str, Optional[str]] = dataclass_field(default_factory=frozendict)
    headers: Mapping[str, str] = dataclass_field(default_factory=frozendict)

    _uri_re: ClassVar[Pattern] = re.compile(URI_PAT)

    @classmethod
    def parse(cls, value: str) -> SIPURI:
        """Parse a SIP URI"""
        match: Optional[Match] = cls._uri_re.fullmatch(value)
        if match is None:
            raise SIPParseError(f"Invalid SIP URI: {value}")
        params: Dict[str, Optional[str]] = {}
        if params_raw := match.group("params"):
            params = {
                name: value
                for param in params_raw.split(";")
                if param
                for name, value in (param.split("=") if "=" in param else (param, None),)
            }
        headers: Dict[str, str] = {}
        if headers_raw := match.group("headers"):
            headers = {
                name: value
                for header in headers_raw.lstrip("?").split("&")
                if header
                for name, value in header.split("=")
            }
        return cls(
            host=match.group("host"),
            port=match.group("port"),
            user=match.group("user"),
            password=match.group("password"),
            scheme=match.group("scheme"),
            params=frozendict(params),
            headers=frozendict(headers),
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

    @classmethod
    def parse(cls, value: str) -> Self:
        """Parse a SIP address from a string. Optionally with a display name and phone number."""
        match: Optional[Match] = None
        for address_pat in ADDRESS_PATS:
            if match := re.fullmatch(address_pat, value):
                break
        match_groups: Dict[str, str] = (match and match.groupdict()) or {}
        uri_raw: Optional[str] = (match and match_groups.get("uri")) or None
        if not match or not uri_raw:
            raise SIPParseError(f"Invalid SIP address: {value}")
        assert uri_raw is not None
        uri: SIPURI = SIPURI.parse(uri_raw)
        return cls(uri=uri, display_name=match_groups.get("display_name"))

    def __str__(self) -> str:
        """Serialize the SIP address to a string."""
        if self.display_name:
            return f'"{self.display_name}" <{self.uri}>'
        return str(self.uri)
