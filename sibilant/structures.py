from __future__ import annotations

import re
from dataclasses import field as dataclass_field
from typing import Optional, Match, Collection, Dict, Mapping, TYPE_CHECKING

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
IPv4_D_PAT: str = r"(?:1?\d{1,2}|2[0-4]\d|25[0-5])"
IPv4_PAT: str = rf"(?:(?:{IPv4_D_PAT}\.){{3}}{IPv4_D_PAT})"
DNS_LABEL_PAT: str = r"(?:[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?)"
FQDN_PAT: str = rf"(?:(?:{DNS_LABEL_PAT}\.)*{DNS_LABEL_PAT}\.?)"
HOSTNAME_PAT: str = rf"(?P<hostname>{FQDN_PAT}|{IPv4_PAT})"
HOST_PAT: str = rf"(?P<host>{HOSTNAME_PAT})(?::(?P<port>\d+))?"
SCHEME_PAT: str = r"(?P<scheme>sips?)(?=:)"
PARAMS_PAT: str = rf"(?P<params>(?:;[\w{UW}]+(?:=[\w{UW}]+)?)+)"
HEADERS_PAT: str = rf"(?=\?)(?P<headers>(?:[?&][\w{UW}]+=[\w{UW}]+)+)"
URI_PART_PAT: str = (
    rf"(?:{SCHEME_PAT}:)?(?:{CONTACT_PAT}@)?{HOST_PAT}"
    rf"(?:{PARAMS_PAT})?(?:{HEADERS_PAT})?"
)
URI_PATS: Collection[str] = [URI_PART_PAT, rf"<{URI_PART_PAT}>"]
ADDRESS_PATS: Collection[str] = [
    rf"(?:{DISPLAY_NAME_PAT}\s*)?(?P<uri>{p})" for p in URI_PATS
]


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

    @classmethod
    def parse(cls, value: str) -> SIPURI:
        """Parse a SIP URI"""
        match: Optional[Match] = None
        for uri_pat in URI_PATS:
            if match := re.fullmatch(uri_pat, value):
                break
        if match is None:
            raise SIPParseError(f"Invalid SIP URI: {value}")
        params: Dict[str, Optional[str]] = {}
        if params_raw := match.group("params"):
            params = {
                name: value
                for param in params_raw.split(";")
                if param
                for name, value in (
                    param.split("=") if "=" in param else (param, None),
                )
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
        params: str = "".join(f";{name}={value}" for name, value in self.params.items())
        headers: str = "".join(
            f"?{name}={value}" for name, value in self.headers.items()
        )
        return f"{self.scheme}:" + login + hostname + params + headers


@dataclass(slots=True, frozen=True)
class SIPAddress:
    """A SIP contact address, with an optional display name and a SIP URI."""

    uri: SIPURI
    display_name: Optional[str] = None

    force_brackets: bool = False

    @classmethod
    def parse(cls, value: str, force_brackets: Optional[bool] = None) -> Self:
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
        display_name = match_groups.get("display_name")
        if display_name and display_name[0] in ("'", '"'):
            display_name = re.sub(r"^\s*([\"'])(.*?)\1\s*$", r"\2", display_name)
        if force_brackets is None:
            force_brackets = bool(display_name)
        return cls(uri=uri, display_name=display_name, force_brackets=force_brackets)

    def __str__(self) -> str:
        """Serialize the SIP address to a string."""
        result: str = f"<{self.uri}>" if self.force_brackets else str(self.uri)
        if self.display_name:
            result = f'"{self.display_name}" {result}'
        return result
