from __future__ import annotations

import logging

import pytest

from sibilant import PhoneState
from sibilant.voip import VoIPPhone


_logger = logging.getLogger(__name__)


@pytest.mark.needs_test_server()
class TestVoIPPhoneReal:
    def test_start_stop(self, test_server_kwargs):
        phone = VoIPPhone(**test_server_kwargs)

        phone.start()
        assert phone.registered, "Phone should be registered with the server"
        assert phone.state == PhoneState.READY, "Phone state should be READY"

        phone.stop()
        assert not phone.registered, "Phone should be unregistered with the server"
        assert phone.state == PhoneState.INACTIVE, "Phone state should be INACTIVE"

    def test_start_stop_context(self, test_server_kwargs):
        with VoIPPhone(**test_server_kwargs) as phone:
            assert phone.registered, "Phone should be registered with the server"
            assert phone.state == PhoneState.READY, "Phone state should be READY"

        assert not phone.registered, "Phone should be unregistered with the server"
        assert phone.state == PhoneState.INACTIVE, "Phone state should be INACTIVE"
