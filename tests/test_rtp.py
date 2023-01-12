import itertools
import random
import socket
import threading
import time

import pytest

from sibilant.exceptions import RTPBrokenStreamError, RTPMismatchedStreamError
from sibilant.rtp import (
    RTPPacket,
    RTPStreamBuffer,
    RTPClient,
    RTPMediaProfiles,
    RTPPacketsStats,
)


class TestRTPPackets:
    def test_parse_packets(self, rtp_packets):
        """Test that all the sample RTP packets can be parsed."""
        for packet in rtp_packets:
            rtp_packet = RTPPacket.parse(packet.data)


def _streams_iterator(packets):
    """
    Iterate over packets, parse into RTPPackets, yield as long as
    they're from the same stream. Return a new (chained) iterator once
    the stream changes.
    """

    def _packets_iterator():
        nonlocal packets
        last_ssrc = None
        for packet in packets:
            rtp_packet = RTPPacket.parse(packet.data)
            if last_ssrc is None:
                last_ssrc = rtp_packet.ssrc
            if rtp_packet.ssrc != last_ssrc:
                packets = itertools.chain([packet], packets)
                return
            yield rtp_packet
        packets = None

    while True:
        yield _packets_iterator()
        if packets is None:
            break


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
                except StopIteration as e:
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
            buffer, data = self._test_write_packets(
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
                except StopIteration:
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
            buffer, data = self._test_write_packets(
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


class MockRTPServer:
    """Small mock UDP RTP server, opens up a connection and sends/recvs RTP packets."""

    def __init__(self, packets_iterator, server_address, client_address):
        self.packets_iterator = packets_iterator
        self.server_address = server_address
        self.client_address = client_address

        self.socket = None
        self.send_thread = None
        self.recv_thread = None
        self.stop_event = threading.Event()

        self.recv_stats = RTPPacketsStats()
        self.send_stats = RTPPacketsStats()

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        self.socket.bind(self.server_address)

        self.send_thread = threading.Thread(target=self._run_send)
        self.recv_thread = threading.Thread(target=self._run_recv)
        self.stop_event.clear()
        self.send_thread.start()
        self.recv_thread.start()

    def _run_send(self):
        while not self.stop_event.is_set():
            try:
                packet = next(self.packets_iterator)
            except StopIteration:
                break
            else:
                with self.send_stats.track(packet):
                    self.send(packet)
                time.sleep(1e-4)

    def send(self, packet):
        assert self.socket is not None
        self.socket.sendto(packet.serialize(), self.client_address)

    def _run_recv(self):
        while not self.stop_event.is_set():
            self.recv()

    def recv(self):
        try:
            data, addr = self.socket.recvfrom(8192)
        except (socket.timeout, BlockingIOError):
            pass
        else:
            packet: RTPPacket = RTPPacket.parse(data)
            with self.recv_stats.track(packet):
                return data
        time.sleep(1e-6)

    def stop(self):
        self.stop_event.set()
        self.send_thread.join()
        self.recv_thread.join()
        self.socket.close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


class TestRTPClient:
    """
    Test RTPClient class. Start an asyncio loop, a mock server,
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

    def test_rtp_client(self, rtp_packets_from_server, rtp_packets_from_client):
        client_address = "127.0.0.1", 14546
        server_address = "127.0.0.1", 24546

        def test(server_packets, client_packets):
            first_packet = next(client_packets)
            if first_packet.payload_type not in (
                RTPMediaProfiles.PCMU,
                RTPMediaProfiles.PCMA,
            ):
                return
            client_packets = itertools.chain([first_packet], client_packets)
            server = MockRTPServer(server_packets, server_address, client_address)
            client = RTPClient(
                client_address,
                server_address,
                profile=first_packet.payload_type,
                send_delay_factor=1e-4,
            )
            with client, server:
                for packet in client_packets:
                    client.write(packet.serialize())
                    time.sleep(1e-4)
                time.sleep(1e-1)  # wait for the last packets to be recv'd
                server.send_thread.join()

            assert server.send_stats.count == client.recv_stats.count
            assert server.recv_stats.count == client.send_stats.count

            self.__class__._tot_server_recv_stats += server.recv_stats
            self.__class__._tot_server_send_stats += server.send_stats
            self.__class__._tot_client_recv_stats += client.recv_stats
            self.__class__._tot_client_send_stats += client.send_stats

        streams = zip(
            _streams_iterator(rtp_packets_from_server),
            _streams_iterator(rtp_packets_from_client),
        )

        for server_packets, client_packets in streams:
            test(server_packets, client_packets)
