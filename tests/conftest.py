from __future__ import annotations

import enum
import logging
import re
import socket
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace as dataclass_replace
from pathlib import Path
from typing import TYPE_CHECKING, Generic, TypeVar

import dpkt
import pytest
from dpkt.utils import inet_to_str


if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType


_logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    parser.addoption("--test-server-address", help="Address of the test server")
    parser.addoption(
        "--test-server-username", help="Username to use for the test server"
    )
    parser.addoption(
        "--test-server-password", help="Password to use for the test server"
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "needs_test_server: mark test as needing a test server"
    )


def get_test_server_options(config):
    server_address = config.getoption("--test-server-address")
    server_kwargs = dict(server_host=server_address)
    if server_address and ":" in server_address:
        server_host, server_port = server_address.split(":")
        server_kwargs.update(server_host=server_host, server_port=int(server_port))
    phone_kwargs = dict(
        username=config.getoption("--test-server-username"),
        password=config.getoption("--test-server-password"),
        **server_kwargs,
    )
    if not any(phone_kwargs.values()):
        raise ValueError(
            "need --test-server command line options to run with a real server"
        )
    if not all(phone_kwargs.values()):
        raise ValueError(
            "need ALL these command line options to run with a real server: "
            "--test-server-address, --test-server-username, --test-server-password"
        )
    return phone_kwargs


def pytest_collection_modifyitems(config, items):
    enable_real_server_tests = False
    skip_real_server_tests_reason = "need --test-server command line options to run"
    try:
        get_test_server_options(config)
        enable_real_server_tests = True
    except ValueError as e:
        skip_real_server_tests_reason = str(e)

    skip_needs_test_server = pytest.mark.skip(reason=skip_real_server_tests_reason)
    for item in items:
        if "needs_test_server" in item.keywords and not enable_real_server_tests:
            item.add_marker(skip_needs_test_server)


@pytest.fixture(scope="session")
def test_server_kwargs(pytestconfig):
    return get_test_server_options(pytestconfig)


class Dest(enum.Enum):
    CLIENT = enum.auto()
    SERVER = enum.auto()


class PacketType(enum.Enum):
    SIP = enum.auto()
    RTP = enum.auto()


@dataclass(frozen=True)
class Packet:
    timestamp: float
    dest: Dest | None
    src_addr: tuple[str, int]
    dst_addr: tuple[str, int]
    type: PacketType
    data: bytes


@pytest.fixture(scope="session")
def voip_calls():  # noqa: PLR0914
    """
    Parse pcap files, and return an iterable of calls, which are iterables of packets.
    Separate client and server packets, and SIP and RTP packets.
    """
    calls = []

    pcaps_dir = Path(__file__).parent / "pcaps"
    for pcap_file in pcaps_dir.glob("*.pcap"):
        call_packets = []
        known_server_ips = set()
        known_client_ips = set()
        with open(pcap_file, "rb") as fp:
            pcap = dpkt.pcap.Reader(fp)

            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue

                ip = eth.data
                if ip.p not in {dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP}:
                    continue
                data, src, sport, dst, dport = (
                    ip.data.data,
                    ip.src,
                    ip.data.sport,
                    ip.dst,
                    ip.data.dport,
                )
                src_str = inet_to_str(src)
                aux_src_str = None
                dst_str = inet_to_str(dst)

                is_sip = b"SIP/2.0" in data
                # make sure it's not a RTCP packet, checking that packet type is not 200-204
                is_rtp = data.startswith(b"\x80") and not (200 <= data[1] <= 204)
                packet_type = (
                    PacketType.SIP if is_sip else (PacketType.RTP if is_rtp else None)
                )
                if packet_type is None:
                    continue

                def extract_aux_ip():
                    nonlocal aux_src_str
                    if match := re.search(
                        r"^c *= *IN +IP4 +\b(\d+\.\d+\.\d+\.\d+)\b",
                        data.decode(),  # noqa: B023
                        re.MULTILINE | re.IGNORECASE,
                    ):
                        aux_src_str = match.group(1)

                if is_sip:
                    first_line = data.split(b"\r\n")[0]
                    dest = None
                    if first_line.startswith(b"REGISTER"):
                        dest = Dest.SERVER
                    elif first_line.startswith(b"INVITE"):
                        if re.search(
                            rf"^Via:.*{src_str}",
                            data.decode(),
                            re.MULTILINE | re.IGNORECASE,
                        ):
                            dest = Dest.SERVER
                        else:
                            dest = Dest.CLIENT
                        extract_aux_ip()
                    elif first_line.startswith(b"SIP/2.0"):
                        if re.search(
                            r"^CSeq:.*REGISTER",
                            data.decode(),
                            re.MULTILINE | re.IGNORECASE,
                        ):
                            dest = Dest.CLIENT
                        elif re.search(
                            r"^CSeq:.*INVITE",
                            data.decode(),
                            re.MULTILINE | re.IGNORECASE,
                        ):
                            dest = Dest.SERVER
                            extract_aux_ip()

                    # server packets are sometimes recognized as client, so ignore that
                    if dest is not None:
                        if dest is Dest.SERVER and src_str not in known_server_ips:
                            known_client_ips.add(src_str)
                            if aux_src_str:
                                known_client_ips.add(aux_src_str)
                        elif dest is Dest.CLIENT:
                            known_client_ips.discard(src_str)
                            known_server_ips.add(src_str)
                            if aux_src_str:
                                known_server_ips.add(aux_src_str)

                call_packets.append(
                    Packet(
                        timestamp=ts,
                        dest=None,
                        type=packet_type,
                        src_addr=(src_str, sport),
                        dst_addr=(dst_str, dport),
                        data=data,
                    )
                )

        def categorize_packet(packet):
            if packet.src_addr[0] in known_server_ips:  # noqa: B023
                return Dest.CLIENT
            if packet.src_addr[0] in known_client_ips:  # noqa: B023
                return Dest.SERVER
            if packet.dst_addr[0] in known_server_ips:  # noqa: B023
                return Dest.SERVER
            if packet.dst_addr[0] in known_client_ips:  # noqa: B023
                return Dest.CLIENT
            return None

        # re-categorize client/server packets, having seen all packets
        call_packets = [
            dataclass_replace(p, dest=categorize_packet(p)) for p in call_packets
        ]

        uncategorized_packets = [p for p in call_packets if p.dest is None]
        if uncategorized_packets:
            raise ValueError(f"Uncategorized packets in {pcap_file}")

        if call_packets:
            calls.append(tuple(call_packets))

    return tuple(calls)


@pytest.fixture
def sip_packets(voip_calls):
    """Return a list of SIP packets from all the calls."""
    return [
        packet
        for call in voip_calls
        for packet in call
        if packet.type == PacketType.SIP
    ]


@pytest.fixture
def sip_requests(sip_packets):
    """Return a list of SIP requests from all the calls."""
    return [packet for packet in sip_packets if not packet.data.startswith(b"SIP/2.0")]


@pytest.fixture
def sip_responses(sip_packets):
    """Return a list of SIP responses from all the calls."""
    return [packet for packet in sip_packets if packet.data.startswith(b"SIP/2.0")]


@pytest.fixture
def sip_packets_from_client(sip_packets):
    """Return a list of SIP packets from the client."""
    return [packet for packet in sip_packets if packet.dest == Dest.SERVER]


@pytest.fixture
def sip_packets_from_server(sip_packets):
    """Return a list of SIP packets from the server."""
    return [packet for packet in sip_packets if packet.dest == Dest.CLIENT]


@pytest.fixture
def rtp_packets(voip_calls):
    """Return a list of RTP packets from all the calls."""
    return [
        packet
        for call in voip_calls
        for packet in call
        if packet.type == PacketType.RTP
    ]


@pytest.fixture
def rtp_packets_from_client(rtp_packets):
    """Return a list of RTP packets from the client."""
    return [packet for packet in rtp_packets if packet.dest == Dest.SERVER]


@pytest.fixture
def rtp_packets_from_server(rtp_packets):
    """Return a list of RTP packets from the server."""
    return [packet for packet in rtp_packets if packet.dest == Dest.CLIENT]


_PT = TypeVar("_PT")


class MockServer(ABC, Generic[_PT]):
    """Small mock UDP server, opens up a connection and sends/recvs data."""

    def __init__(
        self,
        packets_iterator: Iterator[_PT],
        server_address,
        client_address,
        send_delay=1e-6,
        recv_delay=1e-6,
        *,
        pre_bind=False,
        ready=True,
    ):
        self.packets_iterator: Iterator[_PT] = packets_iterator
        self.server_address = server_address
        self.client_address = client_address
        self.send_delay = send_delay
        self.recv_delay = recv_delay

        self.socket = None
        if pre_bind:
            self.socket = self._create_socket()
        self.send_thread = None
        self.recv_thread = None
        self.ready_event = threading.Event()
        if ready:
            self.ready_event.set()
        self.stop_event = threading.Event()
        self.error = None

    def _create_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(self.server_address)
        return sock

    def start(self):
        if self.socket is None:
            self.socket = self._create_socket()

        self.send_thread = threading.Thread(
            target=self._run_send, daemon=True, name="MockServer._run_send"
        )
        self.recv_thread = threading.Thread(
            target=self._run_recv, daemon=True, name="MockServer._run_recv"
        )
        self.stop_event.clear()
        self.send_thread.start()
        self.recv_thread.start()

    @property
    def send_done(self):
        return self.send_thread is None or not self.send_thread.is_alive()

    @abstractmethod
    def send(self, packet: _PT):
        """Send a packet to the client."""

    def _run_send(self):
        self.ready_event.wait(timeout=30)
        while not self.stop_event.is_set():
            try:
                packet: _PT = next(self.packets_iterator)
                self.send(packet)
            except StopIteration:
                break
            except Exception as e:
                self.error = e
                self.stop_event.set()
                raise

            # FIXME: if we don't wait, we lose packets. Can we fix?
            #        does this have to do with the socket being non-blocking?
            time.sleep(self.send_delay)

    @abstractmethod
    def recv(self):
        """Receive a packet from the client."""

    def _run_recv(self):
        while not self.stop_event.is_set():
            try:
                self.recv()
            except Exception as e:
                self.error = e
                self.stop_event.set()
                raise

            time.sleep(self.recv_delay)

    def stop(self):
        self.stop_event.set()
        self.send_thread.join()
        self.recv_thread.join()
        self.socket.close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(
        self,
        exctype: type[BaseException] | None,
        excinst: BaseException | None,
        exctb: TracebackType | None,
    ) -> None:
        self.stop()
