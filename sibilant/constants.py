"""Various constants used by the sibilant library."""

from __future__ import annotations

import re as _re
import typing as _typing


SUPPORTED_SIP_VERSIONS: list[str] = ["SIP/2.0"]
SUPPORTED_SDP_VERSIONS: list[str] = ["0"]
SUPPORTED_RTP_VERSIONS: list[int] = [2]
SUPPORTED_RTP_PROFILES: list[str] = ["PCMU", "PCMA", "telephone-event"]

DEFAULT_SIP_PORT: int = 5060
DEFAULT_RTP_PORT_RANGE: tuple[int, int] = (6000, 7000)

PUBLIC_IP_RESOLVERS: list[tuple[str, _typing.Callable[[str], str | None] | None]] = [
    (
        "http://cloudflare.com/cdn-cgi/trace",
        lambda body: (m := _re.search(r"ip=(.+?)(?=\s|[\r\n]|$)", body)) and m.group(1),
    ),
    ("http://ident.me", None),
    ("http://ifconfig.me/ip", None),
    ("http://icanhazip.com/", None),
    (
        "http://checkip.dyndns.org/",
        lambda body: (m := _re.search(r"ip address: ?(.*?)\b", body, flags=_re.I))
        and m.group(1),
    ),
    (
        "https://cloudflare.com/cdn-cgi/trace",
        lambda body: (m := _re.search(r"ip=(.+?)(?=\s|[\r\n]|$)", body)) and m.group(1),
    ),
    ("https://ident.me", None),
    ("https://ifconfig.me/ip", None),
    ("https://icanhazip.com/", None),
]
