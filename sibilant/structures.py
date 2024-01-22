"""Common SIP / SDP / RTP structures."""

from __future__ import annotations

import re
from dataclasses import field as dataclass_field
from typing import Collection, Mapping, Match

from frozendict import frozendict
from typing_extensions import Self

from .exceptions import SIPParseError
from .helpers import ParseableSerializable, slots_dataclass


DEFAULT_SCHEME: str = "sip"

UNRESERVED_C: str = r"_.!~*'()%\-"
USER_C: str = rf"[\w{UNRESERVED_C}+\-&$,;?/]"
PWD_C: str = rf"[\w{UNRESERVED_C}+\-&$,]"
PARAM_C: str = rf"[\w{UNRESERVED_C}\[\]/:&+$]"
HEADER_C: str = rf"[\w{UNRESERVED_C}\[\]/:?+$]"

DISPLAY_NAME_PAT: str = r"(?P<display_name>[\"'][^\"']+[\"']|\S.*?)(?=\s*\<)"
CONTACT_PAT: str = rf"(?P<user>{USER_C}+)(?::(?P<password>{PWD_C}+))?(?=@)"
IPv4_D_PAT: str = r"(?:1?\d{1,2}|2[0-4]\d|25[0-5])"
IPv4_PAT: str = rf"(?:(?:{IPv4_D_PAT}\.){{3}}{IPv4_D_PAT})"
# FIXME: IPv6
DNS_LABEL_PAT: str = r"(?i:[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?)"
FQDN_PAT: str = rf"(?:(?:{DNS_LABEL_PAT}\.)*{DNS_LABEL_PAT}\.?)"
HOSTNAME_PAT: str = rf"(?P<hostname>{FQDN_PAT}|{IPv4_PAT})"
HOST_PAT: str = rf"(?P<host>{HOSTNAME_PAT})(?::(?P<port>\d+))?"
SCHEME_PAT: str = r"(?P<scheme>sips?)(?=:)"
PARAMS_PAT: str = rf"(?P<params>(?:;{PARAM_C}+(?:={PARAM_C}+)?)+)"
HEADERS_PAT: str = rf"(?=\?)(?P<headers>(?:[?&]{USER_C}+={USER_C}+)+)"
URI_PART_PAT: str = (
    rf"(?:{SCHEME_PAT}:)?(?:{CONTACT_PAT}@)?{HOST_PAT}"
    rf"(?:{PARAMS_PAT})?(?:{HEADERS_PAT})?"
)
URI_PATS: Collection[str] = [URI_PART_PAT, rf"<{URI_PART_PAT}>"]
ADDRESS_PATS: Collection[str] = [
    rf"(?:{DISPLAY_NAME_PAT}\s*)?(?P<uri>{p})" for p in URI_PATS
]


@slots_dataclass(frozen=True)
class SIPURI(ParseableSerializable):
    """A SIP URI."""

    host: str
    port: int | None = None
    user: str | None = None
    password: str | None = None
    scheme: str = DEFAULT_SCHEME
    params: Mapping[str, str | None] = dataclass_field(default_factory=frozendict)
    headers: Mapping[str, str] = dataclass_field(default_factory=frozendict)

    brackets: bool = False

    @classmethod
    def parse(cls, value: str, *, force_brackets: bool | None = None) -> SIPURI:
        """Parse a SIP URI."""
        match: Match | None = None
        for uri_pat in URI_PATS:
            if match := re.fullmatch(uri_pat, value.strip()):
                break
        if match is None:
            raise SIPParseError(f"Invalid SIP URI: {value}")
        if force_brackets is None:
            brackets = value.strip().startswith("<") and value.strip().endswith(">")
        else:
            brackets = force_brackets
        params: dict[str, str | None] = {}
        if params_raw := match.group("params"):
            params = {
                name: value
                for param in params_raw.split(";")
                if param
                for name, value in (
                    param.split("=") if "=" in param else (param, None),
                )
            }
        headers: dict[str, str] = {}
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
            scheme=match.group("scheme") or DEFAULT_SCHEME,
            params=frozendict(params),
            headers=frozendict(headers),
            brackets=brackets,
        )

    def serialize(self, *, force_brackets: bool | None = None) -> str:
        """Serialize the SIP URI to a string."""
        password: str = f":{self.password}" if self.password else ""
        login: str = f"{self.user}{password}@" if self.user else ""
        hostname: str = f"{self.host}:{self.port}" if self.port else self.host
        params: str = "".join(
            f";{name}={value}" if value is not None else f";{name}"
            for name, value in self.params.items()
        )
        headers: str = "".join(
            f"?{name}={value}" for name, value in self.headers.items()
        )
        brackets: bool = self.brackets if force_brackets is None else force_brackets
        uri: str = f"{self.scheme}:" + login + hostname + params + headers
        if brackets:
            uri = f"<{uri}>"
        return uri

    def __str__(self) -> str:
        return self.serialize()


@slots_dataclass(frozen=True)
class SIPAddress:
    """A SIP contact address, with an optional display name and a SIP URI."""

    uri: SIPURI
    display_name: str | None = None

    @classmethod
    def parse(cls, value: str, *, force_brackets: bool | None = None) -> Self:
        """Parse a SIP address from a string. Optionally with a display name and phone number."""
        match: Match | None = None
        for address_pat in ADDRESS_PATS:
            if match := re.fullmatch(address_pat, value):
                break
        match_groups: dict[str, str] = match.groupdict() if match else {}
        display_name = match_groups.get("display_name")
        if display_name and display_name[0] in {"'", '"'}:
            display_name = re.sub(r"^\s*([\"'])(.*?)\1\s*$", r"\2", display_name)
        uri_raw: str | None = match_groups.get("uri") if match else None
        if not match or not uri_raw:
            raise SIPParseError(f"Invalid SIP address: {value}")
        assert uri_raw is not None
        if force_brackets is None:
            force_brackets = bool(match_groups)
        uri: SIPURI = SIPURI.parse(uri_raw, force_brackets=force_brackets)
        return cls(uri=uri, display_name=display_name)

    def __str__(self) -> str:
        """Serialize the SIP address to a string."""
        if self.display_name:
            return f'"{self.display_name}" {self.uri.serialize(force_brackets=True)}'
        else:
            return str(self.uri)
