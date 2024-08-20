"""VoIP phone implementation that uses SIP+RTP for communication."""

from __future__ import annotations

import asyncio
import enum
import logging
import threading
import time
from dataclasses import replace as dataclass_replace
from functools import partial
from types import MappingProxyType, TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Collection,
    Mapping,
    Sequence,
    Union,
)

from sibilant import rtp, sip
from sibilant.exceptions import (
    VoIPCallException,
    VoIPCallTimeoutError,
    VoIPPhoneException,
)


if TYPE_CHECKING:
    import numpy as np
    from numpy.typing import NDArray

    from sibilant.structures import SIPAddress


# ruff: noqa: ARG002


_logger = logging.getLogger(__name__)


SUPPORTED_MEDIA_FORMATS: Collection[rtp.RTPMediaFormat] = [
    fmt if payload_type is None else dataclass_replace(fmt, payload_type=payload_type)
    for payload_type, profile in [
        (None, rtp.RTPMediaProfiles.PCMU),
        (None, rtp.RTPMediaProfiles.PCMA),
        (101, rtp.RTPMediaProfiles.TELEPHONE_EVENT),
    ]
    if (fmt := profile.fmt) is not None
]


class VoIPCall(sip.CallHandler):
    """
    VoIP call handler.

    This class implements the :class:`sip.CallHandler` interface, and is used to
    handle SIP calls events and media streams.

    :param phone: The phone object.
    :param sip_call: The SIP call object.
    :param media_flow: The media flow type to use. Defaults to ``SENDRECV``.
    """

    def __init__(
        self,
        phone: VoIPPhone,
        sip_call: sip.SIPCall,
        media_flow: rtp.MediaFlowType = rtp.MediaFlowType.SENDRECV,
    ) -> None:
        self._phone = phone
        self._sip_call = sip_call

        self._media_flow: rtp.MediaFlowType = media_flow

        remote_addr: tuple[str, int] | None = None
        if self._sip_call.received_sdp is not None:
            remote_addr = self._sip_call.received_sdp.connection_address
        self._rtp_client = rtp.RTPClient(
            local_addr=(self._phone.sip_client.local_host, 0),
            remote_addr=remote_addr,
            media_formats=SUPPORTED_MEDIA_FORMATS,
        )

    @property
    def call_id(self) -> str:
        """The SIP call ID."""
        return self._sip_call.call_id

    @property
    def remote_address(self) -> SIPAddress:
        """The address of the remote party."""
        return self._sip_call.remote_address

    @property
    def number(self) -> str:
        """The number (or user name) of the remote party."""
        # FIXME: proper handling of To/From URIs, see https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.2
        return self.remote_address.uri.user or "<unknown>"

    @property
    def state(self) -> sip.CallState:
        """The call state."""
        return self._sip_call.state

    @property
    def active(self) -> bool:
        """Whether the call is active or soon to be."""
        return self._sip_call.state in {
            sip.CallState.RINGING,
            sip.CallState.ANSWERING,
            sip.CallState.ESTABLISHED,
            sip.CallState.HANGING_UP,
        }

    @property
    def rtp_profile(self) -> rtp.RTPMediaProfiles:
        """The RTP profile."""
        return self._rtp_client.profile

    @property
    def can_accept_calls(self) -> bool:  # noqa: D102
        return self._phone.can_accept_calls

    @property
    def can_make_calls(self) -> bool:  # noqa: D102
        return self._phone.can_make_calls

    def track(self) -> None:
        """Track the call."""
        if self.call_id not in self._phone.calls:
            self._phone._track_call(self)

    def untrack(self) -> None:
        """Untrack the call."""
        if self.call_id in self._phone.calls:
            self._phone._untrack_call(self)

    def prepare_call(self, call: sip.SIPCall) -> None:  # noqa: D102
        self.track()

    def teardown_call(self, call: sip.SIPCall) -> None:  # noqa: D102
        if not self._rtp_client.closed:
            self._rtp_client.stop()
        self.untrack()

    async def answer(self, call: sip.SIPCall) -> bool:  # noqa: D102
        # TODO: handle asyncio.CancelledError for early hangup (before answer)
        self._phone.check_can_accept_calls(excluded_calls=[self])
        assert self._phone.on_incoming_call is not None
        result = await asyncio.get_event_loop().run_in_executor(
            None, self._phone.on_incoming_call, self
        )
        # TODO: do we need this? closing the call would call this anyways
        if not result:
            self.teardown_call(self._sip_call)
        return result

    def wait_answer(self, timeout: float | None = None) -> bool:
        """
        Wait for the call to be answered.

        Returns True if answered, False if not.
        If a timeout is provided, wait until reached, then raise a :class:`VoIPCallTimeoutError`.
        If the call failed for some other reason, re-raise the failure exception.

        :param timeout: Timeout in seconds.
        """
        start_time = time.monotonic()
        while self.state in {
            sip.CallState.INIT,
            sip.CallState.INVITE,
            sip.CallState.RINGING,
            sip.CallState.ANSWERING,
        }:
            if timeout is not None and time.monotonic() - start_time > timeout:
                raise VoIPCallTimeoutError(f"Call not answered after {timeout} seconds")
            time.sleep(1e-3)

        if self.state == sip.CallState.FAILED:
            assert isinstance(self._sip_call.failure_exception, Exception)
            raise self._sip_call.failure_exception

        if self.state in {sip.CallState.ESTABLISHED, sip.CallState.CANCELLED}:
            return self.state == sip.CallState.ESTABLISHED

        raise VoIPCallException(f"Unexpected call state: {self.state}")

    def hangup(self) -> None:
        """Hangup the call."""
        # send either a SIP BYE or a CANCEL depending on the call state (answered or not)
        if self.state == sip.CallState.ESTABLISHED:
            self._sip_call.client._schedule(self._sip_call.bye()).result()
        elif self.state in {sip.CallState.INVITE, sip.CallState.RINGING}:
            self._sip_call.set_cancel()
        else:
            raise VoIPCallException(f"Cannot hangup call in state {self.state}")

    def get_rtp_profiles_by_port(self) -> Mapping[int, Sequence[rtp.RTPMediaProfiles]]:  # noqa: D102
        rtp_clients = [self._rtp_client]
        return {
            rtp_client.local_port: list(rtp_client.media_profiles.values())
            for rtp_client in rtp_clients
        }

    def get_media_flow(self) -> rtp.MediaFlowType:  # noqa: D102
        return self._media_flow

    def establish_call(self, call: sip.SIPCall) -> None:  # noqa: D102
        if not call.received_sdp or not call.received_sdp.connection_address:
            raise VoIPCallException("No RTP connection address in SDP payload")
        self._rtp_client.remote_addr = call.received_sdp.connection_address
        self._rtp_client.start()
        if callable(self._phone.on_call_established):
            self._phone.on_call_established(self)

    def read_audio(
        self, size: int = rtp.RTPStreamBuffer.DEFAULT_SIZE
    ) -> NDArray[np.float32]:
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

    def write_audio(self, data: NDArray[np.float32]) -> int:
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
    def terminate_call(self, call: sip.SIPCall) -> None:  # noqa: D102
        if callable(self._phone.on_call_terminated):
            self._phone.on_call_terminated(self)
        self._rtp_client.stop()
        self.teardown_call(self._sip_call)

    def on_call_failure(self, call: sip.SIPCall, error: Exception) -> bool | None:  # noqa: D102
        if callable(self._phone.on_call_failure):
            return self._phone.on_call_failure(self, error)
        return False


class PhoneState(enum.Enum):
    """Enum of possible VoIP phone states."""

    INACTIVE = "inactive"
    READY = "ready"
    CALLING = "calling"
    BUSY = "busy"
    ERROR = "error"


IncomingCallCallback = Callable[[VoIPCall], bool]
EstablishedCallCallback = Callable[[VoIPCall], None]
TerminatedCallCallback = Callable[[VoIPCall], None]
CallFailureCallback = Callable[[VoIPCall, Exception], Union[bool, None]]


class VoIPPhone:
    """
    VoIP phone.

    This class is the main high-level interface to the VoIP phone.
    It combines SIP and RTP clients to handle calls, and provides a high-level
    interface to the user.

    :param username: The username for registration with the SIP server.
    :param password: The password for authentication with the SIP server.
    :param server_host: The address of the SIP server to connect to.
    :param server_port: The port of the SIP server to connect to.
        If not provided, it will be determined from the server address.
    :param display_name: The display name for registering the client user.
    :param login: The login for authentication with the SIP server.
        If not provided, the username value will be used instead.
    :param domain: The domain for registration with the SIP server.
        If not provided, the server host value will be used instead.
    :param local_host: The local address to bind the SIP client's socket to.
        Defaults to 0.0.0.0.
    :param local_port: The local port to bind the SIP client's socket to.
        Defaults to 0, which means a random port will be chosen by the OS.
    :param on_incoming_call: Callback to handle incoming calls. It must be provided to accept calls.
        The callback will receive a :class:`VoIPCall` object, and must return a boolean
        indicating whether the call should be accepted or not.
    :param on_call_established: Optional callback event for established calls.
        The callback will receive a :class:`VoIPCall` object when a call is established;
        the return value is ignored.
    :param on_call_terminated: Optional callback event for terminated calls.
        The callback will receive a :class:`VoIPCall` object when a call is terminated;
        the return value is ignored.
    :param on_call_failure: Optional callback event for failed calls.
        The callback will receive a :class:`VoIPCall` and :class:`Exception` objects
        when an unrecoverable error occurs during the call;
        if the callback returns True, the exception will be suppressed.
    """

    def __init__(  # noqa: PLR0913
        self,
        username: str,
        password: str,
        server_host: str,
        server_port: int | None = None,
        *,
        display_name: str | None = None,
        login: str | None = None,
        domain: str | None = None,
        local_host: str = "0.0.0.0",
        local_port: int = 0,
        on_incoming_call: IncomingCallCallback | None = None,
        on_call_established: EstablishedCallCallback | None = None,
        on_call_terminated: TerminatedCallCallback | None = None,
        on_call_failure: CallFailureCallback | None = None,
        sip_kwargs: Mapping[str, Any] | None = None,
        rtp_kwargs: Mapping[str, Any] | None = None,
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

        self.on_incoming_call: IncomingCallCallback | None = on_incoming_call
        self.on_call_established: EstablishedCallCallback | None = on_call_established
        self.on_call_terminated: TerminatedCallCallback | None = on_call_terminated
        self.on_call_failure: CallFailureCallback | None = on_call_failure

        self._calls: dict[str, VoIPCall] = {}
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
    def registered(self) -> bool:
        """Check if the phone is registered with the SIP server."""
        return self._sip_client.registered

    @property
    def state(self) -> PhoneState:
        """Get the current phone state."""
        return self._state

    def start(self) -> None:
        """Start the phone, registering with the SIP server."""
        self._sip_client.start()
        self._state = PhoneState.READY

    def stop(self) -> None:
        """Stop the phone, hanging up any active calls and unregistering from the server."""
        self._stopping_event.set()
        call: VoIPCall
        for call in list(self._calls.values()):
            try:
                call.hangup()
            except VoIPCallException as exc:  # noqa: PERF203
                if call.state in {
                    sip.CallState.HANGING_UP,
                    sip.CallState.HUNG_UP,
                    sip.CallState.CANCELLED,
                    sip.CallState.FAILED,
                }:
                    pass
                else:
                    _logger.warning(f"Error while hanging up call: {exc}")
        self._sip_client.stop()
        self._state = PhoneState.INACTIVE
        self._stopping_event.clear()

    def __enter__(self) -> VoIPPhone:
        self.start()
        return self

    def __exit__(
        self,
        exctype: type[BaseException] | None,
        excinst: BaseException | None,
        exctb: TracebackType | None,
    ) -> None:
        self.stop()

    def check_can_accept_calls(self, excluded_calls: Collection[VoIPCall] = ()) -> None:
        """Check if the phone can accept calls in the current state. Raises an exception if not."""
        if not self._sip_client.registered:
            raise VoIPPhoneException("Phone is not registered with the server.")
        if any(
            call.active for call in self._calls.values() if call not in excluded_calls
        ):
            # TODO: allow handling multiple calls at once
            raise VoIPPhoneException("Phone is busy with another call.")
        if self.on_incoming_call is None:
            raise VoIPPhoneException("No incoming call callback registered.")
        if not callable(self.on_incoming_call):
            raise VoIPPhoneException("Incoming call callback is not a callable.")

    @property
    def can_accept_calls(self) -> bool:
        """Check if the phone can accept calls in the current state. Returns a boolean."""
        try:
            self.check_can_accept_calls()
        except VoIPPhoneException:
            return False
        return True

    def check_can_make_calls(self) -> None:
        """Check if the phone can make calls in the current state. Raises an exception if not."""
        if not self._sip_client.registered:
            raise VoIPPhoneException("Phone is not registered with the server.")
        if self._calls:
            # TODO: allow handling multiple calls at once
            raise VoIPPhoneException("Phone is busy with another call.")

    @property
    def can_make_calls(self) -> bool:
        """Check if the phone can make calls in the current state. Returns a boolean."""
        try:
            self.check_can_make_calls()
        except VoIPPhoneException:
            return False
        return True

    def _create_call(self, sip_call: sip.SIPCall, **kwargs: Any) -> VoIPCall:
        """
        Create a new call object for the given SIP call.

        The call is not tracked by the phone yet, we'll wait for the transaction to start
        with basic sanity checks, and enter a waiting state. VoIPCall will take care of
        registering the call in the phone when it's ready.
        """
        # do not track yet, wait for the call to at least enter a waiting state
        return VoIPCall(self, sip_call, **kwargs)

    def _track_call(self, call: VoIPCall) -> None:
        """Add the call handler to the active calls."""
        self._calls[call.call_id] = call

    def _untrack_call(self, call: VoIPCall) -> None:
        """Remove the call handler from the active calls."""
        self._calls.pop(call.call_id, None)

    def call(
        self,
        contact: sip.SIPAddress | sip.SIPURI | str,
        media_flow: rtp.MediaFlowType = rtp.MediaFlowType.SENDRECV,
    ) -> VoIPCall:
        """
        Start a new call to the given contact.

        :param contact: The contact to call.
        :param media_flow: The media flow type to use.
        :return: The call handler object.
        """
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
                    call.state == sip.CallState.ESTABLISHED
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
