"""Various constants used by the sibilant library."""

from __future__ import annotations


SUPPORTED_SIP_VERSIONS: list[str] = ["SIP/2.0"]
SUPPORTED_SDP_VERSIONS: list[str] = ["0"]
SUPPORTED_RTP_VERSIONS: list[int] = [2]
SUPPORTED_RTP_PROFILES: list[str] = ["PCMU", "PCMA", "telephone-event"]

DEFAULT_SIP_PORT: int = 5060
DEFAULT_RTP_PORT_RANGE: tuple[int, int] = (6000, 7000)
