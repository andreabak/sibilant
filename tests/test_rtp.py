from sibilant.rtp import RTPPacket


class TestRTPPackets:
    def test_parse_packets(self, rtp_packets):
        """Test that all the sample RTP packets can be parsed."""
        for packet in rtp_packets:
            rtp_packet = RTPPacket.parse(packet.data)
