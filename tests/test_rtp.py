from __future__ import annotations

import itertools
import random
import socket
import time
from collections import defaultdict, namedtuple

import pytest

from sibilant.exceptions import RTPBrokenStreamError, RTPMismatchedStreamError
from sibilant.rtp import (
    RTPClient,
    RTPMediaProfiles,
    RTPPacket,
    RTPPacketsStats,
    RTPStreamBuffer,
)

from .conftest import Dest, MockServer


class TestRTPPackets:
    def test_parse_packets(self, rtp_packets):
        """Test that all the sample RTP packets can be parsed."""
        for packet in rtp_packets:
            RTPPacket.parse(packet.data)
            # TODO: asserts


def _streams_iterator(packets, skip_payload_types=(96, 101)):
    """
    Iterate over packets, parse into RTPPackets, yield as long as
    they're from the same stream. Return a new (chained) iterator once
    the stream changes.
    """

    def _packets_iterator():
        nonlocal packets
        last_packet = None
        for packet in packets:
            rtp_packet = RTPPacket.parse(packet.data)
            if rtp_packet.payload_type.payload_type in skip_payload_types:
                rtp_packet.payload = b"\x00" * len(last_packet.payload)
                rtp_packet.payload_type = last_packet.payload_type
            if last_packet is None:
                last_packet = rtp_packet
            if rtp_packet.ssrc != last_packet.ssrc:
                packets = itertools.chain([packet], packets)
                return
            yield rtp_packet
        packets = None

    while True:
        yield _packets_iterator()
        if packets is None:
            break


def _streams_pair_iterator(packets):
    """Create pair-matched send and receive streams of packets to simulate server/client."""
    StreamsPair = namedtuple("Streampair", "client_streams, server_streams")
    streams_pairs = defaultdict(
        lambda: StreamsPair(defaultdict(list), defaultdict(list))
    )
    for packet in packets:
        rtp_packet = RTPPacket.parse(packet.data)
        stream = streams_pairs[frozenset((packet.src_addr, packet.dst_addr))]
        if packet.dest == Dest.CLIENT:
            stream.server_streams[rtp_packet.ssrc].append(rtp_packet)
        else:
            stream.client_streams[rtp_packet.ssrc].append(rtp_packet)

    def pair_iterator(server_streams, client_streams):
        server_streams = iter(server_streams)
        client_streams = iter(client_streams)
        while True:
            try:
                server_stream = next(server_streams)
            except StopIteration:
                server_stream = []
            try:
                client_stream = next(client_streams)
            except StopIteration:
                client_stream = []

            if not server_stream and not client_stream:
                break

            yield server_stream, client_stream

    for streams in streams_pairs.values():
        yield from pair_iterator(
            streams.server_streams.values(), streams.client_streams.values()
        )


class TestRTPStreamBuffer:
    _tot_write_stats = RTPPacketsStats()

    @classmethod
    def teardown_class(cls):
        if cls._tot_write_stats:
            print(f"{cls.__name__} written: " + cls._tot_write_stats.format())

    @classmethod
    def _test_write_packets(cls, rtp_packets, **buffer_kwargs):
        """Test that all packets from the server can be written to the buffer."""
        data = b""
        buffer = RTPStreamBuffer(mode="w", **buffer_kwargs)
        for rtp_packet in rtp_packets:
            with cls._tot_write_stats.track(rtp_packet):
                buffer.write_packet(rtp_packet)
            data += buffer.read(-1)
        return buffer, data

    def test_write_packets(self, rtp_packets_from_server):
        """Test that all packets from the server can be written to the buffer."""
        for stream_iterator in _streams_iterator(rtp_packets_from_server):
            self._test_write_packets(stream_iterator)

    def test_write_packets_wrong_stream(self, rtp_packets_from_server):
        def iterate_all_streams():
            for stream_iterator in _streams_iterator(rtp_packets_from_server):
                yield from stream_iterator

        with pytest.raises(RTPMismatchedStreamError):
            self._test_write_packets(iterate_all_streams())

    @staticmethod
    def _out_of_order_iterator(packets, shuffle_size):
        first_packet_yielded = False  # first packet is always yielded in order
        chunk = []
        while True:
            for _ in range(shuffle_size):
                try:
                    chunk.append(next(packets))
                except StopIteration:  # noqa: PERF203
                    return
            if not chunk:
                break
            first_packet = None
            if not first_packet_yielded:
                first_packet = chunk.pop(0)
            random.shuffle(chunk)
            if not first_packet_yielded:
                assert first_packet is not None
                chunk.insert(0, first_packet)
                first_packet_yielded = True
            yield from chunk

    def test_write_packets_out_of_order(self, rtp_packets_from_server):
        for stream_iterator in _streams_iterator(rtp_packets_from_server):
            buffer, _data = self._test_write_packets(
                self._out_of_order_iterator(stream_iterator, shuffle_size=8),
                max_pending=10,
            )
            if buffer.seen_count < 10:  # skip short streams
                continue
            assert buffer.out_of_order_count > 0
            assert buffer.lost_count == 0

    def test_write_packets_out_of_order_broken(self, rtp_packets_from_server):
        with pytest.raises(RTPBrokenStreamError):
            for stream_iterator in _streams_iterator(rtp_packets_from_server):
                self._test_write_packets(
                    self._out_of_order_iterator(stream_iterator, shuffle_size=30),
                    max_pending=5,
                )

    @staticmethod
    def _packets_loss_iterator(packets, lose_every, lose_count=1):
        seen_sequences = set()
        while True:
            chunk = []
            for _ in range(lose_every):
                try:
                    packet = next(packets)
                except StopIteration:  # noqa: PERF203
                    break
                else:
                    if packet.sequence in seen_sequences:
                        continue  # skip duplicates
                    chunk.append(packet)
                    seen_sequences.add(packet.sequence)
            if not chunk:
                break

            lose_start_idx = random.randint(0, max(1, len(chunk) - lose_count))
            chunk = chunk[:lose_start_idx] + chunk[lose_start_idx + lose_count :]
            yield from chunk

    def test_write_packets_lost(self, rtp_packets_from_server):
        for stream_iterator in _streams_iterator(rtp_packets_from_server):
            buffer, _data = self._test_write_packets(
                self._packets_loss_iterator(stream_iterator, lose_every=10),
                max_pending=10,
            )
            if buffer.seen_count < 20:  # skip short streams
                continue
            assert buffer.out_of_order_count > 0
            assert buffer.lost_count > 0

    def test_write_packets_lost_broken(self, rtp_packets_from_server):
        with pytest.raises(RTPBrokenStreamError):
            for stream_iterator in _streams_iterator(rtp_packets_from_server):
                self._test_write_packets(
                    self._packets_loss_iterator(
                        stream_iterator, lose_every=20, lose_count=10
                    ),
                    max_pending=5,
                )

    def test_write_packets_speed(self):  # TODO: make sure this runs after all others
        if not self._tot_write_stats:
            return

        assert self._tot_write_stats.realtime_factor > 1.0

    # TODO: implement read tests
    # def test_read_packets(self):
    #


class MockRTPServer(MockServer):
    """Small mock UDP RTP server, opens up a connection and sends/recvs RTP packets."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.recv_stats = RTPPacketsStats()
        self.send_stats = RTPPacketsStats()

    def send(self, packet):
        assert self.socket is not None
        with self.send_stats.track(packet):
            self.socket.sendto(packet.serialize(), self.client_address)

    def recv(self):
        pre_time_ns = time.perf_counter_ns()
        try:
            data, _addr = self.socket.recvfrom(8192)
        except (socket.timeout, BlockingIOError):
            pass
        else:
            packet: RTPPacket = RTPPacket.parse(data)
            post_time_ns = time.perf_counter_ns()
            self.recv_stats.add(packet, (post_time_ns - pre_time_ns) / 1e9)
            return data


class TestRTPClient:
    """
    Test RTPClient class. Start mock server,
    and check that the client sends and receives the packets correctly.
    """

    _tot_server_recv_stats = RTPPacketsStats()
    _tot_server_send_stats = RTPPacketsStats()
    _tot_client_recv_stats = RTPPacketsStats()
    _tot_client_send_stats = RTPPacketsStats()

    @classmethod
    def teardown_class(cls):
        if bool(cls._tot_server_recv_stats):
            print(f"{cls.__name__} server recv: " + cls._tot_server_recv_stats.format())
        if bool(cls._tot_server_send_stats):
            print(f"{cls.__name__} server sent: " + cls._tot_server_send_stats.format())
        if bool(cls._tot_client_recv_stats):
            print(f"{cls.__name__} client recv: " + cls._tot_client_recv_stats.format())
        if bool(cls._tot_client_send_stats):
            print(f"{cls.__name__} client sent: " + cls._tot_client_send_stats.format())

    @classmethod
    def _test_server_client(
        cls, server_packets, client_packets, server_address=None, client_address=None
    ):
        if server_address is None:
            server_address = "127.0.0.1", 24546  # TODO: get temp free ports
        if client_address is None:
            client_address = "127.0.0.1", 0

        test_profiles = {
            0: RTPMediaProfiles.PCMU,
            8: RTPMediaProfiles.PCMA,
            96: RTPMediaProfiles.TELEPHONE_EVENT,
            101: RTPMediaProfiles.TELEPHONE_EVENT,
            # TODO: test telephone-event, but we need to know the payload type from rtpmap
        }

        try:
            first_packet = next(client_packets)
        except StopIteration:
            client_packets = []
        else:
            if first_packet.payload_type.payload_type not in test_profiles:
                return
            client_packets = itertools.chain([first_packet], client_packets)
        client = RTPClient(
            client_address,
            server_address,
            media_formats=test_profiles,
            send_delay_factor=3e-3,
            pre_bind=True,
        )
        assert (
            client.local_port > 0
        ), "Client port should have been assigned in pre_bind"
        client_address = client.local_addr
        server = MockRTPServer(
            server_packets, server_address, client_address, send_delay=2e-3
        )
        with client, server:
            for packet in client_packets:
                client.write(packet.serialize())
                time.sleep(3e-3)
            time.sleep(1e-1)  # wait for the last packets to be sent
            server.send_thread.join()
            time.sleep(1e-1)  # wait for the last packets to be recv'd

        assert server.send_stats.count == client.recv_stats.count
        assert server.recv_stats.count == client.send_stats.count

        cls._tot_server_recv_stats += server.recv_stats
        cls._tot_server_send_stats += server.send_stats
        cls._tot_client_recv_stats += client.recv_stats
        cls._tot_client_send_stats += client.send_stats

    def test_rtp_client(self, rtp_packets):
        for server_packets, client_packets in _streams_pair_iterator(rtp_packets):
            self._test_server_client(iter(server_packets), iter(client_packets))

    # TODO: test codec + speed, include enc/dec stats in the classes
