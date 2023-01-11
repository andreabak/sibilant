import itertools
import random
import time
from typing import Optional

import pytest

from sibilant.exceptions import RTPBrokenStreamError, RTPMismatchedStreamError
from sibilant.rtp import RTPPacket, RTPStreamBuffer


class TestRTPPackets:
    def test_parse_packets(self, rtp_packets):
        """Test that all the sample RTP packets can be parsed."""
        for packet in rtp_packets:
            rtp_packet = RTPPacket.parse(packet.data)


class TestRTPStreamBuffer:
    _tot_write_count = 0
    _tot_write_bytes = 0
    _tot_write_ts = 0
    _tot_write_time = 0

    @classmethod
    def _calc_write_stats(cls):
        write_count_per_sec = cls._tot_write_count / cls._tot_write_time
        write_speed = cls._tot_write_bytes / cls._tot_write_time
        write_realtime_ratio = cls._tot_write_ts / cls._tot_write_time
        return write_count_per_sec, write_speed, write_realtime_ratio

    @classmethod
    def teardown_class(cls):
        if cls._tot_write_time:
            write_count_per_sec, write_speed, write_realtime_ratio = cls._calc_write_stats()
            print(
                f"{cls.__name__}: {cls._tot_write_count} packets written to RTP buffers\n"
                f"Average write speed: {write_speed/(1024**2):,.2f} MB/s, "
                f"{write_count_per_sec:,.2f} packets/s, "
                f"{write_realtime_ratio:,.2f}x realtime"
            )

    def _streams_iterator(self, packets):
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

    @classmethod
    def _test_write_packets(cls, rtp_packets, **buffer_kwargs):
        """Test that all packets from the server can be written to the buffer."""
        data = b""
        buffer = RTPStreamBuffer(mode="r", **buffer_kwargs)
        for rtp_packet in rtp_packets:
            start_time = time.monotonic()
            buffer.write_packet(rtp_packet)
            end_time = time.monotonic()
            data += buffer.read(-1)
            if rtp_packet.payload_type.payload_type in (0, 8):
                cls._tot_write_count += 1
                cls._tot_write_time += end_time - start_time
                cls._tot_write_bytes += len(rtp_packet.payload)
                cls._tot_write_ts += len(rtp_packet.payload) / rtp_packet.payload_type.clock_rate
        return buffer, data

    def test_write_packets(self, rtp_packets_from_server):
        """Test that all packets from the server can be written to the buffer."""
        for stream_iterator in self._streams_iterator(rtp_packets_from_server):
            self._test_write_packets(stream_iterator)

    def test_write_packets_wrong_stream(self, rtp_packets_from_server):
        def iterate_all_streams():
            for stream_iterator in self._streams_iterator(rtp_packets_from_server):
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
        for stream_iterator in self._streams_iterator(rtp_packets_from_server):
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
            for stream_iterator in self._streams_iterator(rtp_packets_from_server):
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
        for stream_iterator in self._streams_iterator(rtp_packets_from_server):
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
            for stream_iterator in self._streams_iterator(rtp_packets_from_server):
                self._test_write_packets(
                    self._packets_loss_iterator(
                        stream_iterator, lose_every=20, lose_count=10
                    ),
                    max_pending=5,
                )

    def test_write_packets_speed(self):  # TODO: make sure this runs after all others
        *_, write_realtime_ratio = self._calc_write_stats()
        assert write_realtime_ratio > 1.0

    # TODO: implement read tests
    # def test_read_packets(self):
    #
