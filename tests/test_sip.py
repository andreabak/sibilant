from sibilant.sip import SIPRequest, SIPResponse


class TestSIPMessages:
    def test_parse_requests(self, sip_requests):
        """Test that all the sample requests can be parsed."""
        for packet in sip_requests:
            request = SIPRequest.parse(packet.data)

    def test_parse_responses(self, sip_responses):
        """Test that all the sample responses can be parsed."""
        for packet in sip_responses:
            response = SIPResponse.parse(packet.data)
