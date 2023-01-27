from __future__ import annotations

import asyncio
import enum
import threading
import time
from dataclasses import replace as dataclass_replace
from functools import partial
from types import MappingProxyType
from typing import (
    Mapping,
    Sequence,
    Optional,
    Any,
    Union,
    Callable,
    Dict,
    Tuple,
    Collection,
)

import numpy as np

from .. import rtp, sip
from ..constants import DEFAULT_SIP_PORT
from ..exceptions import VoIPPhoneException, VoIPCallException, VoIPCallTimeoutError


SUPPORTED_MEDIA_FORMATS: Collection[rtp.RTPMediaFormat] = [
    fmt if payload_type is None else dataclass_replace(fmt, payload_type=payload_type)
    for payload_type, profile in [
        (None, rtp.RTPMediaProfiles.PCMU),
        (None, rtp.RTPMediaProfiles.PCMA),
        (101, rtp.RTPMediaProfiles.TELEPHONE_EVENT),
    ]
    if (fmt := profile.fmt) is not None
]


class VoIPCall:
    def __init__(
        self,
        phone: VoIPPhone,
        sip_call: sip.SIPCall,
        media_flow: rtp.MediaFlowType = rtp.MediaFlowType.SENDRECV,
    ) -> None:
        self._phone = phone
        self._sip_call = sip_call

        self._media_flow: rtp.MediaFlowType = media_flow

        remote_addr: Optional[Tuple[str, int]] = None
        if self._sip_call.received_sdp is not None:
            remote_addr = self._sip_call.received_sdp.connection_address
        self._rtp_client = rtp.RTPClient(
            local_addr=(self._phone.sip_client.local_host, 0),
            remote_addr=remote_addr,
            media_formats=SUPPORTED_MEDIA_FORMATS,
        )

    @property
    def call_id(self) -> str:
        """Get the call ID."""
        return self._sip_call.call_id

    @property
    def state(self) -> sip.CallState:
        """Get the call state."""
        return self._sip_call.state

    @property
    def can_accept_calls(self) -> bool:
        """Whether we can accept calls."""
        return self._phone.can_accept_calls

    @property
    def can_make_calls(self) -> bool:
        """Whether we can make calls."""
        return self._phone.can_make_calls

    def track(self) -> None:
        """Track the call."""
        if self.call_id not in self._phone.calls:
            self._phone.track_call(self)

    def untrack(self) -> None:
        """Untrack the call."""
        if self.call_id in self._phone.calls:
            self._phone.untrack_call(self)

    def prepare_call(self, call: sip.SIPCall) -> None:
        """Prepare a call to be answered or cancelled."""
        self.track()

    def teardown_call(self, call: sip.SIPCall) -> None:
        """The SIP call is being closed. Untrack it and make sure streams are stopped."""
        if not self._rtp_client.closed:
            self._rtp_client.stop()
        self.untrack()

    async def answer(self, call: sip.SIPCall) -> bool:
        """
        Answer an incoming call. Returns True if the call was answered.
        If the call was cancelled by the other party, will internally raise a
        :class:`asyncio.CancelledError`, that the handler should catch to stop ringing.
        """
        # TODO: handle asyncio.CancelledError for early hangup (before answer)
        self._phone.check_can_accept_calls()
        assert self._phone.on_incoming_call is not None
        result = await asyncio.get_event_loop().run_in_executor(
            None, self._phone.on_incoming_call, call
        )
        # TODO: do we need this? closing the call would call this anyways
        if not result:
            self.teardown_call(self._sip_call)
        return result

    def wait_answer(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for the call to be answered. Returns True if answered, False if not.
        If a timeout is provided, wait until reached, then raise a :class:`VoIPCallTimeoutError`.
        If the call failed for some other reason, re-raise the failure exception.

        :param timeout: Timeout in seconds.
        """
        start_time = time.monotonic()
        while self.state in (
            sip.CallState.INIT,
            sip.CallState.INVITE,
            sip.CallState.RINGING,
            sip.CallState.ANSWERING,
        ):
            if timeout is not None and time.monotonic() - start_time > timeout:
                raise VoIPCallTimeoutError(f"Call not answered after {timeout} seconds")
            time.sleep(1e-3)

        if self.state == sip.CallState.FAILED:
            raise self._sip_call.failure_exception

        if self.state in (sip.CallState.ESTABLISHED, sip.CallState.CANCELLED):
            return self.state == sip.CallState.ESTABLISHED

        raise VoIPCallException(f"Unexpected call state: {self.state}")

    def hangup(self) -> None:
        """Hangup the call."""
        # send either a SIP BYE or a CANCEL depending on the call state (answered or not)
        if self.state == sip.CallState.ESTABLISHED:
            self._sip_call.client.event_loop.run_until_complete(self._sip_call.bye())
        elif self.state in (sip.CallState.INVITE, sip.CallState.RINGING):
            self._sip_call.set_cancel()
        else:
            raise VoIPCallException(f"Cannot hangup call in state {self.state}")

    def get_rtp_profiles_by_port(self) -> Mapping[int, Sequence[rtp.RTPMediaProfiles]]:
        """Get the RTP profiles and ports that will be used for calls."""
        rtp_clients = [self._rtp_client]
        return {
            rtp_client.local_port: rtp_client.media_profiles.values()
            for rtp_client in rtp_clients
        }

    def get_media_flow(self) -> rtp.MediaFlowType:
        """Get the default media flow for the calls."""
        return self._media_flow

    def establish_call(self, call: sip.SIPCall) -> None:
        """A call is established. Start handling streams."""
        assert call.received_sdp is not None
        self._rtp_client.remote_addr = call.received_sdp.connection_address
        self._rtp_client.start()

    def read_audio(self, size: int = rtp.RTPStreamBuffer.DEFAULT_SIZE) -> np.ndarray:
        """
        Read incoming audio data from the call, decoded with the appropriate codec,
        as a float32 numpy array in the range [-1, 1].
        The rate is unchanged, so the same as the stream profile.
        If no data is available, will return an empty array.

        :param size: the number of samples to read. If not specified, will read
            the default size of the stream buffer.
        """
        if self.state != sip.CallState.ESTABLISHED:
            raise VoIPCallException(f"Cannot read audio in call state: {self.state}")
        if self._rtp_client.closed:  # TODO: how about pending data? Lift restriction?
            raise VoIPCallException("Cannot read audio, RTP client closed")
        return self._rtp_client.read_audio(size)

    def write_audio(self, data: np.ndarray) -> int:
        """
        Write audio data to the outgoing RTP stream, encoded with the appropriate codec,
        given a float32 numpy array in the range [-1, 1].
        The rate is fed unchanged, so it must match the stream's profile.
        Returns the number of bytes written.

        :param data: The data to write.
        """
        if self.state != sip.CallState.ESTABLISHED:
            raise VoIPCallException(f"Cannot write audio in call state: {self.state}")
        if self._rtp_client.closed:
            raise VoIPCallException("Cannot write audio, RTP client closed")
        return self._rtp_client.write_audio(data)

    # TODO: do we have too many startup/shutdown methods? Maybe just one each?
    def terminate_call(self, call: sip.SIPCall) -> None:
        """Terminate an established call. Stop handling streams."""
        self._rtp_client.stop()
        self.teardown_call(self._sip_call)


class PhoneState(enum.Enum):
    INACTIVE = "inactive"
    READY = "ready"
    CALLING = "calling"
    BUSY = "busy"
    ERROR = "error"


IncomingCallCallback = Callable[[VoIPCall], bool]


class VoIPPhone:
    def __init__(
        self,
        username: str,
        password: str,
        server_host: str,
        server_port: int = DEFAULT_SIP_PORT,
        display_name: Optional[str] = None,
        login: Optional[str] = None,
        domain: Optional[str] = None,
        local_host: str = "0.0.0.0",
        local_port: int = 0,
        on_incoming_call: Optional[IncomingCallCallback] = None,
        sip_kwargs: Optional[Mapping[str, Any]] = None,
        rtp_kwargs: Optional[Mapping[str, Any]] = None,
    ):
        self._rtp_kwargs: Mapping[str, Any] = rtp_kwargs or {}
        self._sip_client: sip.SIPClient = sip.SIPClient(
            call_handler_factory=self._create_call,
            username=username,
            password=password,
            server_host=server_host,
            server_port=server_port,
            display_name=display_name,
            login=login,
            domain=domain,
            local_host=local_host,
            local_port=local_port,
            **(sip_kwargs or {}),
        )

        self.on_incoming_call: Optional[IncomingCallCallback] = on_incoming_call

        self._calls: Dict[str, VoIPCall] = {}
        """Mapping of currently active calls, by call ID."""

        self._state: PhoneState = PhoneState.INACTIVE
        """Current phone state."""

        self._stopping_event: threading.Event = threading.Event()

    @property
    def sip_client(self) -> sip.SIPClient:
        """Get the SIP client."""
        return self._sip_client

    @property
    def calls(self) -> Mapping[str, VoIPCall]:
        """Get the currently active calls."""
        return MappingProxyType(self._calls)

    @property
    def state(self) -> PhoneState:
        """Get the current phone state."""
        return self._state

    def start(self) -> None:
        self._sip_client.start()
        self._state = PhoneState.READY

    def stop(self) -> None:
        self._stopping_event.set()
        # TODO: teardown calls
        self._sip_client.stop()
        self._state = PhoneState.INACTIVE
        self._stopping_event.clear()

    def __enter__(self) -> VoIPPhone:
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.stop()

    def check_can_accept_calls(self) -> None:
        if not self._sip_client.registered:
            raise VoIPPhoneException("Phone is not registered with the server.")
        if self._calls:
            # TODO: allow handling multiple calls at once
            raise VoIPPhoneException("Phone is busy with another call.")
        if self.on_incoming_call is None:
            raise VoIPPhoneException("No incoming call callback registered.")
        if not callable(self.on_incoming_call):
            raise VoIPPhoneException("Incoming call callback is not a callable.")

    @property
    def can_accept_calls(self) -> bool:
        try:
            self.check_can_accept_calls()
        except VoIPPhoneException:
            return False
        return True

    def check_can_make_calls(self) -> None:
        if not self._sip_client.registered:
            raise VoIPPhoneException("Phone is not registered with the server.")
        if self._calls:
            # TODO: allow handling multiple calls at once
            raise VoIPPhoneException("Phone is busy with another call.")

    @property
    def can_make_calls(self) -> bool:
        try:
            self.check_can_make_calls()
        except VoIPPhoneException:
            return False
        return True

    def _create_call(self, sip_call: sip.SIPCall, **kwargs) -> VoIPCall:
        """
        Create a new call object for the given SIP call.
        The call is not tracked by the phone yet, we'll wait for the transaction to start
        with basic sanity checks, and enter a waiting state. VoIPCall will take care of
        registering the call in the phone when it's ready.
        """
        call = VoIPCall(self, sip_call, **kwargs)
        # do not track yet, wait for the call to at least enter a waiting state
        return call

    def track_call(self, call: VoIPCall) -> None:
        self._calls[call.call_id] = call

    def untrack_call(self, call: VoIPCall) -> None:
        self._calls.pop(call.call_id, None)

    def call(
        self,
        contact: Union[sip.SIPAddress, sip.SIPURI, str],
        media_flow: rtp.MediaFlowType = rtp.MediaFlowType.SENDRECV,
    ) -> VoIPCall:
        self.check_can_make_calls()
        sip_call = self._sip_client.invite(
            contact,
            call_handler_factory=partial(self._create_call, media_flow=media_flow),
        )
        handler = sip_call.handler
        assert isinstance(handler, VoIPCall)
        return handler

    async def _sipclient_monitor(self) -> None:
        try:
            while True:
                active_calls: bool = any(
                    call.state == sip.SIPCallState.ESTABLISHED
                    for call in self._calls.values()
                )
                if self._calls and active_calls:
                    self._state = PhoneState.CALLING
                elif self._calls or not self.can_accept_calls:
                    self._state = PhoneState.BUSY
                else:
                    self._state = PhoneState.READY

                await asyncio.sleep(0.1)

        except asyncio.CancelledError:  # SIP client is terminating
            if not self._stopping_event.is_set():
                self._state = PhoneState.ERROR
