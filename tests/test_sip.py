from __future__ import annotations

import logging
import re
import socket
import time
import traceback
from collections import defaultdict, deque, namedtuple
from contextlib import contextmanager, nullcontext
from typing import Mapping, Sequence

import pytest

from sibilant import rtp
from sibilant.exceptions import SIPException
from sibilant.sip import (
    CallHandler,
    CallState,
    Header,
    Headers,
    MultipleValuesHeader,
    SIPCall,
    SIPClient,
    SIPMessage,
    SIPMethod,
    SIPRegistration,
    SIPRequest,
    SIPResponse,
)

from .conftest import Dest, MockServer


_logger = logging.getLogger(__name__)


class TestHeaders:
    def test_multiple_values(self):
        """Test that headers with multiple values are parsed correctly."""
        support_mutliple_values_headers = [
            "Accept",
            "Accept-Encoding",
            "Accept-Language",
            "Call-Info",
            "Allow",
            "Contact",
            "Content-Encoding",
            "Content-Language",
            "Error-Info",
            "In-Reply-To",
            "Proxy-Require",
            "Record-Route",
            "Require",
            "Route",
            "Supported",
            "Unsupported",
            "Via",
            "Warning",
        ]
        wrong_classes = []
        for header_name in support_mutliple_values_headers:
            try:
                header_cls = Header.__registry_get_class_for__(header_name)
            except KeyError:  # noqa: PERF203
                _logger.info(f"Header {header_name} not implemented yet")
            else:
                if not issubclass(header_cls, MultipleValuesHeader):
                    wrong_classes.append(header_name)
        assert (
            not wrong_classes
        ), "Headers with multiple values should be MultipleValuesHeader"


class TestSIPMessages:
    def test_parse(self, sip_packets):
        """Test that all the sample SIP messages can be parsed without critical errors."""
        for packet in sip_packets:
            SIPMessage.parse(packet.data)
            # TODO: test origin
            # TODO: do asserts making sure (somehow) that parse->serialize == input

    def test_headers(self, sip_packets):
        """Test that all the sample SIP messages have the correct headers."""
        for packet in sip_packets:
            message = SIPMessage.parse(packet.data)
            headers = message.headers

            raw_headers_lines = (
                packet.data.decode().split("\r\n\r\n", 1)[0].split("\r\n")[1:]
            )
            raw_headers = dict(tuple(line.split(": ", 1)) for line in raw_headers_lines)
            assert list(headers.keys()) == list(
                raw_headers.keys()
            ), "Headers should be in the same order as the original message"

            def clean(s):
                """Clean headers for comparison."""
                if not s.endswith("\r\n"):
                    s += "\r\n"
                # remove extra whitespace in each header, collapse to a single space
                s = re.sub(r"( |(?<!\r)\n)+", " ", s)
                # remove whitespace around commas
                s = re.sub(r"\s*,\s*", ",", s)
                # make all bool values uppercase
                s = re.sub(
                    r"\b(false|true)\b", lambda m: m.group(1).upper(), s, flags=re.I
                )
                # remove unnecessary quotes from nc=
                s = re.sub(r'\bnc="(\w+)"', r"nc=\1", s, flags=re.I)
                # add quotes when missing in display name before <sip:...>
                s = re.sub(r"(\w+) *(?=<sip:)", r'"\1" ', s)
                # strip leading and trailing whitespace in each line
                s = re.sub(r"^ +| +$", "", s, flags=re.M)
                return s.strip()

            assert clean(str(headers)) == clean(
                "\r\n".join(raw_headers_lines)
            ), "Headers should serialize to the same string as the original message"

            previous_headers = Headers()
            for header in headers.values():
                hdr_cls_name = header.__class__.__name__
                assert (
                    header.name in headers
                ), f"{hdr_cls_name}: header name should be in Headers map"
                assert (  # noqa: PT018
                    header.name.upper() in headers and header.name.lower() in headers
                ), f"{hdr_cls_name}: headers should be case-insensitive"

                serialized_value = header.serialize()
                rebuilt_header = Header.parse(
                    header.name, serialized_value, previous_headers
                )
                assert (
                    rebuilt_header.serialize() == serialized_value
                ), f"{hdr_cls_name}: value should serialize without loss"
                assert str(rebuilt_header) == str(
                    header
                ), f"{hdr_cls_name}: entire header should serialize without loss"
                assert (
                    rebuilt_header == header
                ), f"{hdr_cls_name}: should be able to be rebuilt and still match"

                previous_headers[header.name] = rebuilt_header


PacketAndSIPMessage = namedtuple("PacketAndSIPMessage", ["packet", "message"])


@pytest.fixture()
def sip_transactions(sip_packets):
    """
    Return lists of packets and SIP messages, grouped by transaction.
    Duplicate messages are removed (eg. retransmissions).
    """
    transactions = defaultdict(list)
    for packet in sip_packets:
        sip_message = SIPMessage.parse(packet.data)  # TODO: add origin
        call_id = sip_message.headers.get("Call-ID")
        if call_id is None:
            _logger.debug("SIP message has no Call-ID header, skipping")
        transactions[str(call_id)].append(PacketAndSIPMessage(packet, sip_message))

    # use a sliding window of 10 messages to remove duplicates
    for packets in transactions.values():
        seen = deque(maxlen=10)
        packets[:] = [
            pm
            for pm in packets
            if pm.message not in seen and (not seen.append(pm.message))
        ]

    return transactions


@pytest.fixture()
def sip_registrations(sip_transactions):
    """Return lists of SIP REGISTER transactions, grouped by transaction."""
    return {
        call_id: messages
        for call_id, messages in sip_transactions.items()
        if messages[0].message.method == SIPMethod.REGISTER
    }


@pytest.fixture()
def sip_invites(sip_transactions):
    """Return lists of SIP INVITE transactions, grouped by transaction."""
    return {
        call_id: messages
        for call_id, messages in sip_transactions.items()
        if messages[0].message.method == SIPMethod.INVITE
    }


@pytest.fixture()
def incoming_invites(sip_invites):
    """Return lists of incoming SIP INVITE transactions, grouped by transaction."""
    return {
        call_id: messages
        for call_id, messages in sip_invites.items()
        if messages[0].packet.dest == Dest.CLIENT
    }


@pytest.fixture()
def outgoing_invites(sip_invites):
    """Return lists of outgoing SIP INVITE transactions, grouped by transaction."""
    return {
        call_id: messages
        for call_id, messages in sip_invites.items()
        if messages[0].packet.dest == Dest.SERVER
    }


class MockSIPServer(MockServer[PacketAndSIPMessage]):
    """Small mock SIP server, opens up a connection and sends/recvs data."""

    def __init__(self, *args, wait_recv_timeout: float = 10.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_sent_msg: SIPMessage | None = None
        self.last_recv_msg: SIPMessage | None = None
        self.wait_recv_timeout: float = wait_recv_timeout
        self.recv_queue = deque()
        self.sent_count = 0
        self.recv_count = 0

    def send(self, packet: PacketAndSIPMessage):
        assert self.socket is not None

        if packet is None:
            _logger.debug(f"Waiting for recv, ready responses: {len(self.recv_queue)}")
        start_time = time.time()
        while packet is None and not self.recv_queue:
            time.sleep(1e-3)
            if self.stop_event.is_set():
                return
            if time.time() - start_time > self.wait_recv_timeout:
                raise TimeoutError("Timed out waiting for recv")
        if packet is None:
            self.recv_queue.popleft()
            return

        message = packet.message

        if self.last_recv_msg is not None and isinstance(
            self.last_recv_msg, SIPRequest
        ):
            # adapt transaction ID, cseq, from and to
            message.headers["Call-ID"] = self.last_recv_msg.headers["Call-ID"]
            message.headers["CSeq"] = self.last_recv_msg.headers["CSeq"]
            message.headers["From"] = self.last_recv_msg.headers["From"]
            message.headers["To"] = self.last_recv_msg.headers["To"]

        self.recv_queue.clear()
        self.socket.sendto(bytes(message), self.client_address)
        self.last_sent_msg = message
        self.sent_count += 1
        _logger.debug(f"Sent {message!r}")

    def recv(self):
        try:
            data, addr = self.socket.recvfrom(8192)
        except (socket.timeout, BlockingIOError):
            pass
        else:
            if not data.strip():
                return
            message = SIPMessage.parse(data, origin=addr)
            self.last_recv_msg = message
            self.recv_count += 1
            self.recv_queue.append(message)
            _logger.debug(f"Received {message!r}")


class TestCallHandler(CallHandler):
    """A mock VoIP phone that can send and receive SIP messages."""

    @property
    def can_accept_calls(self) -> bool:
        return True

    @property
    def can_make_calls(self) -> bool:
        return True

    def prepare_call(self, call: SIPCall) -> None:
        pass

    def teardown_call(self, call: SIPCall) -> None:
        pass

    async def answer(self, call: SIPCall) -> bool:
        return True

    def get_rtp_profiles_by_port(self) -> Mapping[int, Sequence[rtp.RTPMediaProfiles]]:
        return {
            5060: [rtp.RTPMediaProfiles.PCMU, rtp.RTPMediaProfiles.PCMA],
        }

    def get_media_flow(self) -> rtp.MediaFlowType:
        return rtp.MediaFlowType.SENDRECV

    def establish_call(self, call: SIPCall) -> None:
        pass

    def terminate_call(self, call: SIPCall) -> None:
        pass

    def on_call_failure(self, call: SIPCall, error: Exception) -> bool | None:
        pass


def mute_caplog(caplog, mute, logger_name=None):
    """Return a context manager to maybe mute the caplog for the given logger."""
    if mute:
        log_level_context = caplog.at_level(logging.CRITICAL, logger=logger_name)
    else:
        log_level_context = nullcontext()
    return log_level_context


@pytest.fixture()
def _skip_register(monkeypatch):
    async def mock_register(self):
        self._registered = True

    monkeypatch.setattr(SIPRegistration, "register", mock_register)


@pytest.fixture()
def _skip_deregister(monkeypatch):
    original__register_transaction = SIPRegistration._register_transaction

    async def mock_register_transaction(self, *, deregister: bool = False) -> None:
        if deregister:
            return None  # skip deregister
        return await original__register_transaction(self, deregister=deregister)

    monkeypatch.setattr(
        SIPRegistration, "_register_transaction", mock_register_transaction
    )


class TestSIPClient:
    """Test SIPClient class."""

    @classmethod
    @contextmanager
    def _init_server_client(
        cls,
        server_packets,
        *,
        server_address=None,
        client_address=None,
        wait_recv_timeout=2.0,
        register_timeout=2e-1,
        register_expires=1,
        default_response_timeout=2e-1,
    ):
        if server_address is None:
            server_address = "127.0.0.1", 5060
        if client_address is None:
            client_address = "127.0.0.1", 15060

        server = MockSIPServer(
            iter(server_packets),
            server_address,
            client_address,
            send_delay=1e-2,
            wait_recv_timeout=wait_recv_timeout,
        )
        client = SIPClient(
            call_handler_factory=lambda call: TestCallHandler(),  # noqa: ARG005
            username="alice",
            password="secret",
            server_host=server_address[0],
            server_port=server_address[1],
            local_host=client_address[0],
            local_port=client_address[1],
            register_timeout=register_timeout,
            register_expires=register_expires,
            default_response_timeout=default_response_timeout,
            keep_alive_interval=None,  # disable keep-alive
        )

        yield server, client

    @classmethod
    def _test_registration(cls, server_packets, expect_failure, **kwargs):
        with cls._init_server_client(server_packets, **kwargs) as (server, client):  # noqa: SIM117
            with server:
                with pytest.raises(Exception) as exc_info, client:
                    while not server.send_done and not client.closed:
                        time.sleep(1e-9)
                    _logger.debug("Stopping test")

                    assert (
                        expect_failure or client.registered
                    ), "Client should be registered"

                    raise StopIteration

                assert exc_info.type is StopIteration or (
                    issubclass(exc_info.type, SIPException) and expect_failure
                ), (
                    f"SIP client failed with unexpected {exc_info.type}: {exc_info.value}"
                    f"\n{traceback.format_tb(exc_info.tb)}"
                    f"\nlast sent message: {server.last_sent_msg!r}"
                    f"\nlast received message: {server.last_recv_msg!r}"
                )

    @pytest.mark.usefixtures("_skip_deregister")
    def test_register(self, sip_registrations, monkeypatch, caplog):
        """Test that the client can register with the server."""
        for call_id, packets in sip_registrations.items():
            server_packets = [
                pm if pm.packet.dest == Dest.CLIENT else None for pm in packets
            ]
            # check if we have any 400,402+ responses in the server packets or 2 or more
            # subsequent 401, and set an expect_failure flag.
            # We have only REGISTER packets here, so we can skip the CSeq check.
            expect_failure = False
            last_message = None
            for pm in server_packets:
                if pm is None:
                    continue
                if (
                    (
                        isinstance(pm.message, SIPResponse)
                        and pm.message.status.code == 400
                    )
                    or pm.message.status.code >= 402
                    or (
                        pm.message.status.code == 401
                        and last_message
                        and isinstance(last_message, SIPResponse)
                        and last_message.status.code == 401
                    )
                ):
                    expect_failure = True
                    break
                last_message = pm.message

            try:
                with mute_caplog(caplog, expect_failure, "sibilant.sip.client"):
                    self._test_registration(server_packets, expect_failure)
            except Exception:
                print(f"{self.test_register.__name__} failed for call ID: {call_id}")
                raise

    @classmethod
    def _test_invite_wrapper(
        cls, call_test_fn, server_packets, expected_states, **kwargs
    ):
        with cls._init_server_client(server_packets, **kwargs) as (server, client):  # noqa: SIM117
            with client, server:
                call = call_test_fn(client, server)

                assert not client._pending_futures, "expected client to be done"
                assert server.sent_count, "at least one message should have been sent"
                assert call, "expected at least one call to have started"
                assert (
                    call.state in expected_states
                ), "call should be in expected states"
                expected_sent_count = len([m for m in server_packets if m is not None])
                assert server.sent_count == expected_sent_count

    @classmethod
    def _test_invite_incoming(cls, server_packets, expected_states, **kwargs):
        def grab_call_and_wait(client, server):
            call = None
            while (
                not server.send_done
                or client._pending_futures  # FIXME: might get stuck on keepalive
            ) and not server.error:
                if call is None and client.calls:
                    call = next(iter(client.calls.values()))
                time.sleep(1e-9)
            time.sleep(1e-1)
            if server.error:
                client.stop()
                raise server.error
            return call

        return cls._test_invite_wrapper(
            grab_call_and_wait, server_packets, expected_states, **kwargs
        )

    @pytest.mark.usefixtures("_skip_register", "_skip_deregister")
    def test_invite_incoming(self, incoming_invites, caplog):
        """Test that the client can send an INVITE to the server."""
        for call_id, packets in incoming_invites.items():
            # the flow is >INVITE, <180 Ringing, <200 Ok, >ACK [, >BYE, <200 Ok]
            # so make sure there's the correct order in server packets
            server_packets = []
            last_method = None
            for pm in packets:
                if pm.packet.dest == Dest.SERVER:
                    continue
                msg = pm.message
                if not server_packets and msg.method == SIPMethod.INVITE:
                    server_packets.extend([pm, None, None])  # add wait for 180 and 200
                elif last_method == SIPMethod.INVITE and msg.method == SIPMethod.ACK:
                    server_packets.append(pm)
                elif last_method == SIPMethod.ACK and msg.method == SIPMethod.BYE:
                    server_packets.extend([pm, None])  # add wait for final 200
                else:
                    _logger.warning(f"Unexpected packet in incoming INVITE flow: {pm}")
                    server_packets = []
                    break
                last_method = msg.method if msg else None
            if not server_packets:
                continue

            if last_method == SIPMethod.INVITE:
                expected_states = (CallState.FAILED,)  # never replied
            elif last_method == SIPMethod.ACK:
                expected_states = (CallState.ESTABLISHED,)
            elif last_method == SIPMethod.BYE:
                expected_states = (CallState.HUNG_UP,)
            else:
                raise RuntimeError(
                    f"Unexpected last method in incoming INVITE flow: {last_method}"
                )

            expect_failure = CallState.FAILED in expected_states
            try:
                with mute_caplog(caplog, expect_failure, "sibilant.sip.client"):
                    self._test_invite_incoming(server_packets, expected_states)
            except Exception:
                print(
                    f"{self.test_invite_incoming.__name__} failed for call ID: {call_id}"
                )
                raise

    @classmethod
    def _test_invite_outgoing(
        cls, contact, client_methods, server_packets, expected_states, **kwargs
    ):
        def send_invite_and_wait(client, server):
            # TODO: more client methods to simulate call flow (ignore ACK)
            call = client.invite(contact)
            while not server.send_done or client._pending_futures:
                time.sleep(1e-9)
            time.sleep(1e-1)
            return call

        return cls._test_invite_wrapper(
            send_invite_and_wait, server_packets, expected_states, **kwargs
        )

    @pytest.mark.usefixtures("_skip_register", "_skip_deregister")
    def test_invite_outgoing(self, outgoing_invites, caplog):
        """Test that the client can send an INVITE to the server."""
        for call_id, packets in outgoing_invites.items():
            assert isinstance(packets[0].message, SIPRequest)
            assert packets[0].message.method == SIPMethod.INVITE
            contact = packets[0].message.uri

            server_packets = []
            last_response_status = None
            client_methods = []
            for pm in packets:
                # calls communication can happen between client and client
                if isinstance(pm.message, SIPRequest):
                    method = pm.message.method
                    if method == SIPMethod.INVITE and method in client_methods:
                        break  # TODO: better split retransmitted packets from server
                    if method in {SIPMethod.CANCEL, SIPMethod.BYE}:
                        break  # TODO: implement
                    client_methods.append(method)
                    server_packets.append(None)
                elif isinstance(pm.message, SIPResponse):
                    server_packets.append(pm)
                    last_response_status = pm.message.status
                    if last_response_status.code not in {100, 180, 200}:
                        break
                else:
                    raise TypeError(f"Unexpected packet: {pm}")

            if last_response_status.code == 200:
                expected_states = (CallState.ESTABLISHED,)
            else:
                expected_states = (CallState.FAILED,)

            expect_failure = CallState.FAILED in expected_states

            try:
                with mute_caplog(caplog, expect_failure, "sibilant.sip.client"):
                    self._test_invite_outgoing(
                        contact, client_methods, server_packets, expected_states
                    )
            except Exception:
                print(
                    f"{self.test_invite_outgoing.__name__} failed for call ID: {call_id}"
                )
                raise
