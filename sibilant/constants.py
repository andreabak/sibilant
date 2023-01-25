from typing import List, Tuple


SUPPORTED_SIP_VERSIONS: List[str] = ["SIP/2.0"]
SUPPORTED_SDP_VERSIONS: List[str] = ["0"]
SUPPORTED_RTP_VERSIONS: List[int] = [2]
SUPPORTED_RTP_PROFILES: List[str] = ["PCMU", "PCMA", "telephone-event"]

DEFAULT_SIP_PORT: int = 5060
DEFAULT_RTP_PORT_RANGE: Tuple[int, int] = (6000, 7000)
