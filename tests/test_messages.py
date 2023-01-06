from pathlib import Path
from typing import List

import pytest

from ..messages import SIPRequest, SIPResponse


@pytest.fixture
def sip_flows() -> List[List[bytes]]:
    """A list of SIP flows and their messages in raw bytes, loaded from the sample files."""
    separator_line = b"=" * 80 + b"\r\n"
    flow_separator = separator_line * 3 + b"\r\n"
    msg_separator = separator_line + b"\r\n"
    with open(Path(__file__).parent / "sip_messages.dump", "rb") as fp:
        flows = fp.read().split(flow_separator)
    return [
        [msg for msg in flow.split(msg_separator) if msg]
        for flow in flows
        if flow
    ]


@pytest.fixture
def sip_messages(sip_flows):
    """A list of SIP messages in raw bytes, loaded from the sample files."""
    return [msg for flow in sip_flows for msg in flow]


@pytest.fixture
def sip_requests(sip_messages) -> List[bytes]:
    """A list of SIP requests in raw bytes, loaded from the sample files."""
    # requests first line must end with "SIP/2.0"
    return [message for message in sip_messages if message.split(b"\r\n", maxsplit=1)[0].endswith(b"SIP/2.0")]


@pytest.fixture
def sip_responses(sip_messages) -> List[bytes]:
    """A list of SIP responses in raw bytes, loaded from the sample files."""
    # responses first line must start with "SIP/2.0"
    return [message for message in sip_messages if message.split(b"\r\n", maxsplit=1)[0].startswith(b"SIP/2.0")]


def test_parse_requests(sip_requests):
    """Test that all the sample requests can be parsed."""
    for request_raw in sip_requests:
        request = SIPRequest.parse(request_raw)


def test_parse_responses(sip_responses):
    """Test that all the sample responses can be parsed."""
    for response_raw in sip_responses:
        response = SIPResponse.parse(response_raw)
