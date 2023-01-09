import enum
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest
import dpkt


_logger = logging.getLogger(__name__)


class Dest(enum.Enum):
    CLIENT = enum.auto()
    SERVER = enum.auto()


class PacketType(enum.Enum):
    SIP = enum.auto()
    RTP = enum.auto()


@dataclass(frozen=True)
class Packet:
    timestamp: float
    dest: Dest
    type: PacketType
    data: bytes


@pytest.fixture(scope="session")
def voip_calls():
    """
    Parse pcap files, and return an iterable of calls, which are iterables of packets.
    Separate client and server packets, and SIP and RTP packets.
    """

    calls = []

    pcaps_dir = Path(__file__).parent / "pcaps"
    for pcap_file in pcaps_dir.glob("*.pcap"):
        server_ip = None
        client_ip = None
        call_packets = []
        with open(pcap_file, "rb") as fp:
            pcap = dpkt.pcap.Reader(fp)
            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue

                ip = eth.data
                if ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                    continue
                data, src, dst = ip.data.data, ip.src, ip.dst

                is_sip = b"SIP/2.0" in data
                # make sure it's not a RTCP packet, checking that packet type is not 200-204
                is_rtp = data.startswith(b"\x80") and not (200 <= data[1] <= 204)
                packet_type = PacketType.SIP if is_sip else (PacketType.RTP if is_rtp else None)
                if packet_type is None:
                    continue

                if server_ip is None or client_ip is None:
                    if (
                        packet_type == PacketType.SIP
                        and not data.startswith(b"SIP/2.0")
                        and b"SIP/2.0\r\n" in data
                    ):
                        server_ip = dst
                        client_ip = src
                    else:
                        _logger.warning(
                            f"Did not find first request packet, skipping pcap: {pcap_file}"
                        )
                        break

                dest = Dest.SERVER if dst == server_ip else Dest.CLIENT
                call_packets.append(Packet(ts, dest, packet_type, data))

        if call_packets:
            calls.append(tuple(call_packets))

    return tuple(calls)


@pytest.fixture
def sip_packets(voip_calls):
    """Return an iterable of SIP packets from all the calls."""
    return (
        packet
        for call in voip_calls
        for packet in call
        if packet.type == PacketType.SIP
    )


@pytest.fixture
def sip_requests(sip_packets):
    """Return an iterable of SIP requests from all the calls."""
    return (packet for packet in sip_packets if not packet.data.startswith(b"SIP/2.0"))


@pytest.fixture
def sip_responses(sip_packets):
    """Return an iterable of SIP responses from all the calls."""
    return (packet for packet in sip_packets if packet.data.startswith(b"SIP/2.0"))


@pytest.fixture
def rtp_packets(voip_calls):
    """Return an iterable of RTP packets from all the calls."""
    return (
        packet
        for call in voip_calls
        for packet in call
        if packet.type == PacketType.RTP
    )


@pytest.fixture
def rtp_packets_from_client(rtp_packets):
    """Return an iterable of RTP packets from the client."""
    return (packet for packet in rtp_packets if packet.dest == Dest.SERVER)


@pytest.fixture
def rtp_packets_from_server(rtp_packets):
    """Return an iterable of RTP packets from the server."""
    return (packet for packet in rtp_packets if packet.dest == Dest.CLIENT)
