import logging
import socket
import threading
import time
from collections import defaultdict, namedtuple
from typing import Mapping, Sequence, Optional

import pytest

from sibilant import rtp
from sibilant.exceptions import SIPException
from sibilant.sip import (
    SIPRequest,
    SIPResponse,
    SIPMessage,
    AbstractVoIPPhone,
    SIPClient,
    SIPCall,
    SIPMethod,
    SIPStatus,
    Headers,
)
from .conftest import MockServer, Dest


_logger = logging.getLogger(__name__)


class TestSIPMessages:
    def test_parse(self, sip_packets):
        """Test that all the sample SIP messages can be parsed."""
        for packet in sip_packets:
            message = SIPMessage.parse(packet.data)
            # TODO: do asserts making sure (somehow) that parse->serialize == input

    def test_parse_requests(self, sip_requests):
        """Test that all the sample requests can be parsed."""
        for packet in sip_requests:
            request = SIPRequest.parse(packet.data)
            # TODO: do asserts making sure (somehow) that parse->serialize == input

    def test_parse_responses(self, sip_responses):
        """Test that all the sample responses can be parsed."""
        for packet in sip_responses:
            response = SIPResponse.parse(packet.data)
            # TODO: do asserts making sure (somehow) that parse->serialize == input


PacketAndSIPMessage = namedtuple("PacketAndSIPMessage", ["packet", "message"])


@pytest.fixture
def sip_transactions(sip_packets):
    """Return lists of packets and SIP messages, grouped by transaction."""
    transactions = defaultdict(list)
    for packet in sip_packets:
        sip_message = SIPMessage.parse(packet.data)
        call_id = sip_message.headers.get("Call-ID")
        if call_id is None:
            _logger.debug("SIP message has no Call-ID header, skipping")
        transactions[str(call_id)].append(PacketAndSIPMessage(packet, sip_message))

    return transactions


@pytest.fixture
def sip_registrations(sip_transactions):
    """Return lists of SIP REGISTER transactions, grouped by transaction."""
    return {
        call_id: messages
        for call_id, messages in sip_transactions.items()
        if messages[0].message.method == SIPMethod.REGISTER
    }


@pytest.fixture
def sip_invites(sip_transactions):
    """Return lists of SIP INVITE transactions, grouped by transaction."""
    return {
        call_id: messages
        for call_id, messages in sip_transactions.items()
        if messages[0].message.method == SIPMethod.INVITE
    }


@pytest.fixture
def incoming_invites(sip_invites):
    """Return lists of incoming SIP INVITE transactions, grouped by transaction."""
    return {
        call_id: messages
        for call_id, messages in sip_invites.items()
        if messages[0].packet.dest == Dest.CLIENT
    }


@pytest.fixture
def outgoing_invites(sip_invites):
    """Return lists of outgoing SIP INVITE transactions, grouped by transaction."""
    return {
        call_id: messages
        for call_id, messages in sip_invites.items()
        if messages[0].packet.dest == Dest.SERVER
    }


class MockSIPServer(MockServer[PacketAndSIPMessage]):
    """Small mock SIP server, opens up a connection and sends/recvs data."""

    def __init__(
        self, *args, wait_recv_timeout: float = 10.0, autoregister=False, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.last_sent_msg: Optional[SIPMessage] = None
        self.last_recv_msg: Optional[SIPMessage] = None
        self.wait_recv_timeout: float = wait_recv_timeout
        self.wait_for_recv = threading.Event()
        self.autoregister = autoregister

    def send(self, packet: PacketAndSIPMessage):
        assert self.socket is not None
        if packet is None:
            self.wait_for_recv.set()
            return

        start_time = time.time()
        while self.wait_for_recv.is_set():
            time.sleep(1e-3)
            if self.stop_event.is_set():
                return
            if time.time() - start_time > self.wait_recv_timeout:
                raise TimeoutError("Timed out waiting for recv")

        message = packet.message

        if (
            self.last_recv_msg is not None
            and isinstance(self.last_recv_msg, SIPRequest)
            and self.last_recv_msg.method == SIPMethod.REGISTER
        ):
            # adapt transaction ID, cseq, from and to
            message.headers["Call-ID"] = self.last_recv_msg.headers["Call-ID"]
            message.headers["CSeq"] = self.last_recv_msg.headers["CSeq"]
            message.headers["From"] = self.last_recv_msg.headers["From"]
            message.headers["To"] = self.last_recv_msg.headers["To"]

        self.socket.sendto(bytes(message), self.client_address)
        self.last_sent_msg = message

    def recv(self):
        try:
            data, addr = self.socket.recvfrom(8192)
        except (socket.timeout, BlockingIOError):
            pass
        else:
            message = SIPMessage.parse(data)
            if (
                self.autoregister
                and isinstance(message, SIPRequest)
                and message.method == SIPMethod.REGISTER
            ):
                response = SIPResponse(
                    SIPStatus.OK,
                    "SIP/2.0",
                    headers=Headers(*message.headers.values()),
                )
                self.socket.sendto(bytes(response), self.client_address)
            else:
                self.last_recv_msg = message
                self.wait_for_recv.clear()


class MockVoIPPhone(AbstractVoIPPhone):
    """A mock VoIP phone that can send and receive SIP messages."""

    @property
    def can_accept_calls(self) -> bool:
        return True

    async def answer(self, call: SIPCall) -> bool:
        return True

    def get_rtp_profiles_by_port(self) -> Mapping[int, Sequence[rtp.RTPMediaProfiles]]:
        raise NotImplementedError

    def get_default_media_flow(self) -> rtp.MediaFlowType:
        return rtp.MediaFlowType.SENDRECV

    def establish_call(self, call: SIPCall) -> None:
        pass

    def terminate_call(self, call: SIPCall) -> None:
        pass


class TestSIPClient:
    """
    Test SIPClient class.
    """

    @classmethod
    def _test_server_client(
        cls,
        server_packets,
        client_packets,
        server_address=None,
        client_address=None,
        autoregister=False,
        register_timeout=2.0,
        register_expires=3,
    ):
        if server_address is None:
            server_address = "127.0.0.1", 5060
        if client_address is None:
            client_address = "127.0.0.1", 15060

        server = MockSIPServer(
            iter(server_packets),
            server_address,
            client_address,
            send_delay=1e-1,
            recv_delay=1e-1,
            wait_recv_timeout=10.0,
            autoregister=autoregister,
        )
        client = SIPClient(
            phone=MockVoIPPhone(),
            username="alice",
            password="secret",
            server_host=server_address[0],
            server_port=server_address[1],
            local_host=client_address[0],
            local_port=client_address[1],
            register_timeout=register_timeout,
            register_expires=register_expires,
            skip_deregister=True,
        )
        with server:
            with pytest.raises(Exception) as exc_info:
                with client:
                    while not server.send_done:
                        time.sleep(1e-2)
                    raise StopIteration

            last_message = server.last_sent_msg
            expect_failure = (
                isinstance(last_message, SIPResponse)
                and (cseq := last_message.headers.get("CSeq"))
                and (cseq and cseq.method == SIPMethod.REGISTER)
                and last_message.status.code >= 400
            )
            assert (
                exc_info.type == StopIteration
                or issubclass(exc_info.type, SIPException)
                and expect_failure
            ), (
                f"SIP client failed with unexpected {exc_info.type}: {exc_info.value}"
                f"\nlast sent message: {last_message!r}"
                f"\nlast received message: {server.last_recv_msg!r}"
            )

    def test_register(self, sip_registrations):
        """Test that the client can register with the server."""
        for call_id, messages in sip_registrations.items():
            server_packets = [
                pm if pm.packet.dest == Dest.CLIENT else None for pm in messages
            ]
            try:
                self._test_server_client(server_packets, [])
            except Exception:
                print(f"{self.test_register.__name__} failed for call ID: {call_id}")
                raise
