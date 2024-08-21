"""SIP client implementation."""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import contextlib
import enum
import hashlib
import logging
import random
import re
import socket
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import replace as dataclass_replace
from functools import partial
from types import MappingProxyType, TracebackType
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Collection,
    Coroutine,
    Mapping,
    MutableMapping,
    Protocol,
    Sequence,
    TypeVar,
    runtime_checkable,
)

from typing_extensions import Self, override

import sibilant
from sibilant import rtp, sdp
from sibilant.constants import DEFAULT_SIP_PORT
from sibilant.exceptions import (
    SIPAuthenticationError,
    SIPBadMessage,
    SIPBadRequest,
    SIPBadResponse,
    SIPException,
    SIPParseError,
    SIPTimeout,
    SIPUnsupportedError,
    SIPUnsupportedVersion,
)
from sibilant.helpers import SupportsStr, get_external_ip_for_dest
from sibilant.structures import SIPURI, SIPAddress

from . import headers as hdr
from .messages import SIPMessage, SIPMethod, SIPRequest, SIPResponse, SIPStatus


_logger = logging.getLogger(__name__)


def generate_via_branch() -> str:
    """Generate a unique branch identifier for Via headers."""
    branch: str = base64.b64encode(uuid.uuid4().bytes, altchars=b"00").decode()[:22]
    return f"z9hG4bK-{branch[:6]}-{branch[6:15]}-{branch[15:]}"


def generate_tag() -> str:
    """Generate a tag for From/To headers for SIP sessions."""
    return base64.b32encode(random.getrandbits(36).to_bytes(5, "big")).decode()


def generate_call_id(local_host: str, local_port: int | None = None) -> str:
    """Generate a unique call ID for SIP sessions, using UUID and local host name."""
    addr_str = f"{local_host}:{local_port}" if local_port else local_host
    return f"{uuid.uuid4()}@{addr_str}"


def generate_cseq() -> int:
    """Generate a random CSeq number for SIP requests."""
    return random.randrange(0, 2**15)


async def discard_statuses(
    msg_getter: Callable[[], Awaitable[SIPMessage]],
    statuses: Collection[SIPStatus] = (SIPStatus.TRYING,),
) -> SIPMessage:
    """Await for the next response, ignoring TRYING responses."""
    # TODO: if you do the wait within here, you could log the trying messages received while waiting for the response
    discarded_count = 0
    while True:
        message: SIPMessage = await msg_getter()
        if isinstance(message, SIPResponse) and message.status in statuses:
            discarded_count += 1
            continue

        return message


_rT = TypeVar("_rT")


async def call_later(delay: float, coro: Coroutine[Any, Any, _rT]) -> _rT | None:
    """Call a coroutine after a delay."""
    try:
        await asyncio.sleep(delay)
    except asyncio.CancelledError:
        coro.close()
    else:
        return await coro
    return None


async def cancel_task_silent(task: asyncio.Task) -> None:
    """Cancel a task, awaiting it, and ignore the raised :class:`asyncio.CancelledError`."""
    try:
        task.cancel()
        await task
    except asyncio.CancelledError:
        pass


@runtime_checkable
class CallHandler(Protocol):
    """
    A protocol for call handlers, duck-typed classes which instances are used to handle
    async events happening during SIP calls (INVITE transactions).

    The call handlers provide a variety of methods that might be called during SIP calls
    to check capabilities (e.g. can receive a call) of the underlying application
    (e.g. a soft phone), and to notify it of events happening during the call dialog
    (e.g. call established, terminated, etc.).
    """

    @property
    def can_accept_calls(self) -> bool:
        """Whether we can accept calls."""

    @property
    def can_make_calls(self) -> bool:
        """Whether we can make calls."""

    def prepare_call(self, call: SIPCall) -> None:
        """
        The call has been validated, and we're in transaction to start it.
        The handler should now do any necessary steps to prepare to handle it.
        Ideally this should return quickly, as it blocks the transaction.
        """

    def teardown_call(self, call: SIPCall) -> None:
        """A call is being closed. Clean up any resources used by the call."""

    async def answer(self, call: SIPCall) -> bool:
        """
        Answer an incoming call. Returns True if the call was answered.
        If the call was cancelled by the other party, will internally raise a
        :class:`asyncio.CancelledError`, that the handler should catch to stop ringing.
        """

    def get_rtp_profiles_by_port(self) -> Mapping[int, Sequence[rtp.RTPMediaProfiles]]:
        """Get the RTP profiles and ports that will be used for calls."""

    def get_media_flow(self) -> rtp.MediaFlowType:
        """Get the default media flow for the calls."""

    # TODO: check if we want async here
    def establish_call(self, call: SIPCall) -> None:
        """A call is established. Start handling streams."""

    # TODO: check if we want async here
    def terminate_call(self, call: SIPCall) -> None:
        """Terminate an established call. Stop handling streams."""

    def on_call_failure(self, call: SIPCall, error: Exception) -> bool | None:
        """
        Invoked when an unrecoverable error happens during the call process.
        It can suppress raising the given error by returning True.
        """


CallHandlerFactory = Callable[["SIPCall"], CallHandler]


class SIPDialog(ABC):
    """
    Base class for SIP dialog implementations, i.e. SIP session between two endpoints,
    defined in :rfc:`3261#section-8` and :rfc:`3261#section-12`.

    :param client: The SIP client instance associated to this dialog.
    :param uri: The URI of the dialog used for requests.
    :param to_address: The SIP address used in To headers.
    :param from_address: The SIP address used in From headers.
    :param to_tag: The initial tag used in To headers, if available.
    :param from_tag: The initial tag used in From headers, if available.
    :param call_id: The Call-ID for this dialog. If None, a random one will be generated.
    :param cseq: The CSeq for this dialog. If None, a random one will be generated.
    :param response_timeout: The timeout for receiving responses in this dialog.
        If None, the default timeout from the client will be used.
    """

    def __init__(
        self,
        client: SIPClient,
        *,
        uri: SIPURI,
        to_address: SIPAddress,
        from_address: SIPAddress,
        to_tag: str | None = None,
        from_tag: str | None = None,
        call_id: str | None = None,
        cseq: int | None = None,
        response_timeout: float | None = None,
    ):
        self._client: SIPClient = client

        self._uri: SIPURI = uri

        self._to_address: SIPAddress = to_address
        self._to_tag: str | None = to_tag

        self._from_address: SIPAddress = from_address
        self._from_tag: str | None = from_tag

        self._call_id: str = call_id or generate_call_id(*self._client.local_addr)
        self._cseq: int = cseq if cseq is not None else generate_cseq()

        self._rport: int | None = None
        self._destination: tuple[str, int] | None = None

        self._cnonce: str | None = None

        self._recv_queue: asyncio.Queue[SIPMessage] = asyncio.Queue()
        self._expecting_msg: bool = False
        if response_timeout is None:
            response_timeout = self._client.default_response_timeout
        self._response_timeout: float = response_timeout

        self._closed: bool = False

        self._client._track_dialog(self)

    @classmethod
    def from_request(
        cls, client: SIPClient, request: SIPRequest, **kwargs: Any
    ) -> Self:
        """Create a new dialog from an incoming request."""
        if "To" not in request.headers:
            raise SIPBadRequest(f"Missing To header: {request!r}")
        to_header: hdr.ToHeader = request.headers["To"]
        to_tag = to_header.tag or generate_tag()
        if "From" not in request.headers:
            raise SIPBadRequest(f"Missing From header: {request!r}")
        from_header: hdr.FromHeader = request.headers["From"]
        return cls(
            uri=request.uri,
            client=client,
            to_address=to_header.address,
            from_address=from_header.address,
            to_tag=to_tag,
            from_tag=from_header.tag,
            call_id=request.headers["Call-ID"].value,
            cseq=request.headers["CSeq"].sequence,
            **kwargs,
        )

    @property
    def client(self) -> SIPClient:
        """The client associated to dialog."""
        return self._client

    @property
    def call_id(self) -> str:
        """The Call-ID for this dialog."""
        return self._call_id

    @property
    def cseq(self) -> int:
        """The CSeq for this dialog."""
        return self._cseq

    @property
    def closed(self) -> bool:
        """
        Whether this dialog is closed / has ended.
        The client should not be tracking it anymore,
        effectively rejecting any new messages related to it.
        """
        return self._closed

    def _close(self) -> None:
        """Close this dialog."""
        self._client._untrack_dialog(self)
        self._closed = True

    async def terminate(self) -> None:
        """Terminate this dialog."""
        self._close()

    # FIXME: make more of these methods private, they're not meant to be called from users
    #        of the library directly, but only by related classes
    async def receive_message(self, message: SIPMessage) -> None:
        """
        Receive a SIP from the client receive loop and handle it appropriately.
        Call-ID checks are not done here, as it's assumed the client already did them.
        """
        if (
            self._to_tag is None
            and "To" in message.headers
            and (to_tag := message.headers["To"].tag) is not None
        ):
            self._to_tag = to_tag
        if (
            self._from_tag is None
            and "From" in message.headers
            and (from_tag := message.headers["From"].tag) is not None
        ):
            self._from_tag = from_tag

        if self._expecting_msg:
            # Put the message in the queue, and whatever is awaiting will get it
            if not self._recv_queue.empty():
                _logger.warning(
                    "Received message while still processing "
                    f"{self._recv_queue.qsize()} previous ones"
                )

            self._recv_queue.put_nowait(message)

        else:
            # We're not expecting anything, try to handle the message
            self._store_sender(message, replace=False)
            await self._handle_message(message)

    @abstractmethod
    async def _handle_message(self, message: SIPMessage) -> None:
        """Handle an incoming SIP message."""

    async def _wait_for_message(
        self,
        timeout: float | None = None,
        *,
        discard_trying_and_info: bool = True,
        more_discard_statuses: Collection[SIPStatus] = (),
    ) -> SIPMessage:
        """
        Wait for the next message to arrive in the queue.

        :param timeout: The timeout for the wait. None for default, -1 for no timeout.
        :param discard_trying_and_info: Whether to discard TRYING and informational responses.
        :return: The next message.
        :raises asyncio.TimeoutError: If the timeout is reached.
        """
        if timeout is None:
            timeout = self._response_timeout
        msg_getter: Callable[[], Awaitable[SIPMessage]] = self._recv_queue.get
        if discard_trying_and_info or more_discard_statuses:
            statuses: set[SIPStatus] = set(more_discard_statuses)
            if discard_trying_and_info:
                statuses |= {SIPStatus.TRYING, SIPStatus.SESSION_PROGRESS}
            msg_getter = partial(discard_statuses, msg_getter, statuses=statuses)
        if timeout != -1:
            msg_getter = partial(asyncio.wait_for, msg_getter(), timeout)
        self._expecting_msg = True
        try:
            message = await msg_getter()
            self._store_sender(message)
            return message
        finally:
            self._expecting_msg = False

    def _store_sender(self, message: SIPMessage, *, replace: bool = True) -> None:
        """Store sender information from origin and Via header of a received message."""
        # TODO: make sure called only on received messages
        if "Via" not in message.headers:
            raise SIPBadMessage("Missing Via header")
        via_hdr: hdr.ViaHeader = message.headers["Via"]
        if (isinstance(via_hdr.first.rport, int) and not self._rport) or replace:
            self._rport = via_hdr.first.rport
        if not self._destination or replace:
            self._destination = message.origin

    def _follow_cseq(self, request: SIPMessage) -> SIPMessage:
        """Set the internal CSeq to the one in the request and increment it."""
        if "CSeq" not in request.headers:
            raise SIPBadMessage("Missing CSeq header")
        cseq: hdr.CSeqHeader = request.headers["CSeq"]
        self._cseq = cseq.sequence + 1
        return request

    async def _send_message(self, message: SIPMessage) -> None:
        """Send a SIP message."""
        self._client._send_msg(message)  # TODO: make async and await?

    async def _send_request(self, request: SIPRequest) -> None:
        """Send a request and increment the internal CSeq."""
        await self._send_message(request)
        self._follow_cseq(request)

    def _dialog_headers_kwargs(
        self,
        kwargs: MutableMapping[str, Any],
        *,
        add_via: bool = True,
    ) -> Mapping[str, Any]:
        """Get the headers that should be added to a request in this dialog."""
        dialog_hdrs = dict(
            from_address=kwargs.pop("from_address", self._from_address),
            from_tag=kwargs.pop("from_tag", self._from_tag),
            to_address=kwargs.pop("to_address", self._to_address),
            to_tag=kwargs.pop("to_tag", self._to_tag),
            call_id=kwargs.pop("call_id", self._call_id),
        )
        if add_via:
            via_hdr: hdr.ViaHeader = (
                kwargs.pop("via_hdr", None) or self._client.generate_via_hdr()
            )
            via_entry = via_hdr.first
            if via_entry.received is None and self._destination is not None:
                received, rport = self._destination
                via_entry = dataclass_replace(via_entry, received=received)
                via_entry.rport = rport
                via_hdr = hdr.ViaHeader([via_entry, *via_hdr[1:]])
            dialog_hdrs["via_hdr"] = via_hdr
        return dialog_hdrs

    def _generate_request(
        self, method: SIPMethod, *, add_via: bool = True, **kwargs: Any
    ) -> SIPRequest:
        return self._client.generate_request(
            method,
            **self._dialog_headers_kwargs(kwargs, add_via=add_via),
            cseq=kwargs.pop("cseq", self._cseq),
            uri=kwargs.pop("uri", self._uri),
            destination=kwargs.pop("destination", self._destination),
            **kwargs,
        )

    def _generate_response_from_request(
        self, request: SIPRequest, status: SIPStatus, **kwargs: Any
    ) -> SIPResponse:
        assert request.headers["Call-ID"].value == self._call_id
        kwargs.setdefault("via_hdr", request.headers["Via"])
        return self._client.generate_response_from_request(
            request, status, **self._dialog_headers_kwargs(kwargs), **kwargs
        )

    async def _might_authenticate(
        self,
        sender_factory: Callable[
            [hdr.AuthorizationHeader | None], Coroutine[Any, Any, SIPRequest]
        ],
        max_attempts: int = 5,
    ) -> tuple[SIPRequest, SIPResponse]:
        """
        Handle sending a request with an optional authentication challenge.

        :param sender_factory: the coroutine that generates and sends the request,
            must accept an (optional) authorization header to add to the request,
            and return the sent request.
        :return: the last sent request and the last received response.
        """
        authorization: hdr.AuthorizationHeader | None = None
        response: SIPMessage | None = None
        attempts: int = max_attempts
        while attempts > 0:
            request: SIPRequest = await sender_factory(authorization)
            method: str = request.method.name
            try:
                response = await self._wait_for_message(self._client.register_timeout)
            except asyncio.TimeoutError:
                raise SIPTimeout(  # noqa: B904
                    f"Timed out waiting for {method} response"
                )

            if not isinstance(response, SIPResponse):
                raise SIPBadResponse(f"Unexpected response for {method}: {response!r}")

            if response.status in {
                SIPStatus.UNAUTHORIZED,
                SIPStatus.PROXY_AUTHENTICATION_REQUIRED,
            }:
                is_proxy = response.status == SIPStatus.PROXY_AUTHENTICATION_REQUIRED

                nonce_changed = "nonce" in response.status.reason
                if authorization is not None and not nonce_changed:
                    raise SIPAuthenticationError(
                        "Failed to authenticate with given credentials"
                    )

                authorization = self._client.generate_auth(
                    response, is_proxy=is_proxy, cnonce=self._cnonce, nc=self._cseq
                )
                if not self._cnonce and authorization.cnonce:
                    self._cnonce = authorization.cnonce

            else:
                return request, response

            attempts -= 1

        raise SIPException(
            "Failed to authenticate with server "
            f"(after {max_attempts - attempts} attempts)"
            + (f"\nLast response: {response!r}" if response is not None else "")
        )


class SIPRegistration(SIPDialog):
    """
    SIP REGISTER dialog implementation, defined in :rfc:`3261#section-10`.

    Used to register the client with a SIP server and keep the registration alive.

    :param client: The SIP client instance associated to this dialog.
    """

    def __init__(self, client: SIPClient):
        super().__init__(
            client,
            uri=client.server_uri,
            from_address=client.binding_address,
            to_address=client.binding_address,
            from_tag=generate_tag(),
        )

        self._reg_refresh_task: asyncio.Task | None = None
        self._registered: bool = False

    @property
    def registered(self) -> bool:
        """Whether we are currently registered with the server within this dialog."""
        return self._registered

    async def _handle_message(self, message: SIPMessage) -> None:
        raise SIPException("Received unexpected message in registration flow")

    def _register_request(
        self,
        *,
        authorization: hdr.AuthorizationHeader | None = None,
        deregister: bool = False,
    ) -> SIPRequest:
        extra_headers = [
            hdr.ExpiresHeader(0 if deregister else self._client.register_expires),
            *self._client.generate_capabilities_headers(),
        ]
        if authorization is not None:
            extra_headers.append(authorization)

        # TODO: allow-events ??

        return self._generate_request(
            SIPMethod.REGISTER,
            is_initial=True,
            extra_headers=extra_headers,
        )

    async def _register_transaction(self, *, deregister: bool = False) -> None:
        async def sender(
            authorization: hdr.AuthorizationHeader | None,
        ) -> SIPRequest:
            request: SIPRequest = self._register_request(
                authorization=authorization, deregister=deregister
            )
            await self._send_request(request)
            return request

        response: SIPResponse
        _, response = await self._might_authenticate(sender)

        if response.status == SIPStatus.BAD_REQUEST:
            raise SIPBadRequest("REGISTER failed: server replied with 400 Bad Request")

        elif (  # noqa: RET506
            400 <= int(response.status) <= 499 or 600 <= int(response.status) <= 699
        ):
            raise SIPException(f"REGISTER failed: {response!r}")

        elif response.status == SIPStatus.OK:
            return  # all good, exit flow

        raise SIPException(f"Unexpected response for REGISTER: {response!r}")

    async def _schedule_reg_refresh(self) -> None:
        await self._cancel_reg_refresh()
        reg_refresh_interval: float = max(
            0.0, self._client.register_expires - self._client.register_timeout
        )
        self._reg_refresh_task = asyncio.create_task(
            call_later(reg_refresh_interval, self.register()),
            name=f"{self.__class__.__name__}.reg_refresh-{id(self._client)} task",
        )
        self._client._track_future(self._reg_refresh_task)

    async def _cancel_reg_refresh(self) -> None:
        if self._reg_refresh_task is not None:
            await cancel_task_silent(self._reg_refresh_task)
            self._reg_refresh_task = None

    async def register(self) -> None:
        """Register with the server and schedule periodic registration refresh."""
        try:
            await self._register_transaction()
        except Exception:
            self._registered = False
            self._close()
            raise
        self._registered = True
        await self._schedule_reg_refresh()

    async def deregister(self) -> None:
        """Deregister from the server and cancel periodic registration refresh."""
        await self._cancel_reg_refresh()
        try:
            await self._register_transaction(deregister=True)
        finally:
            self._registered = False
            self._close()

    @override
    async def terminate(self) -> None:
        await self.deregister()


class SIPOptions(SIPDialog):
    """
    SIP OPTIONS dialog implementation, defined in :rfc:`3261#section-11`.

    Used by servers or other UAs to check the capabilities of the client.
    """

    async def _handle_message(self, message: SIPMessage) -> None:
        if isinstance(message, SIPRequest) and message.method == SIPMethod.OPTIONS:
            return await self._options_recv_transaction(message)

        raise SIPException("Received unexpected message in OPTIONS transaction")

    def _generate_capabilities_response(self, request: SIPRequest) -> SIPResponse:
        return self._generate_response_from_request(
            request,
            SIPStatus.OK,
            extra_headers=self.client.generate_capabilities_headers(),
        )

    async def _options_recv_transaction(self, request: SIPRequest) -> None:
        """Check OPTIONS request and reply with appropriate response (own capabilities)."""
        if not isinstance(request, SIPRequest) or request.method != SIPMethod.OPTIONS:
            raise TypeError(f"Invalid type for OPTIONS request: {request!r}")

        response: SIPResponse = self._generate_capabilities_response(request)
        await self._send_message(response)

        self._close()


# TODO: we might not need all of these states, because some are intermediate and
#       can be handled by the async flows. Maybe stick to what RFC 3261 section 17 says?
class CallState(enum.Enum):
    """Enums representing the state of a SIP call."""

    INIT = enum.auto()
    """Call is being initiated, no INVITE has been sent or processed yet."""
    INVITE = enum.auto()
    """INVITE has been sent or received, and we're waiting for further info."""
    RINGING = enum.auto()
    """INVITE has been processed, and the call is ringing."""
    ANSWERING = enum.auto()
    """INVITE has been accepted, and the call is being answered, ACK pending."""
    ESTABLISHED = enum.auto()
    """Call is established, ACK has been sent or received."""
    HANGING_UP = enum.auto()
    """Call is being hung up, BYE has been sent or received."""
    HUNG_UP = enum.auto()
    """Call has been hung up, BYE has been processed."""
    CANCELLED = enum.auto()
    """Call has been terminated early due to CANCEL or Busy Here."""
    FAILED = enum.auto()
    """Call has failed due to an error."""


class CallSide(enum.Enum):
    """Enums representing the side of a SIP call."""

    CALLER = enum.auto()
    """The caller side of a call."""
    RECEIVER = enum.auto()
    """The receiver side of a call."""


class SIPCall(SIPDialog):
    """
    SIP INVITE dialog implementation, defined in :rfc:`3261#section-13`.

    Used to initiate outgoing calls (UAC role) and handle incoming calls (UAS role).

    It works in conjunction with a :class:`CallHandler` instance, which is used to
    notify and make the underlying application (e.g. a soft phone) handle call events.

    :param client: The SIP client instance associated to this dialog.
    :param uri: The URI of the dialog used for requests, if different from the one in the To header.
    :param to: The To header for the dialog or a SIP Address.
        Must be present if `to_address` is not provided.
    :param from_hdr: The From header for the dialog.
        Must be present if `from_address` is not provided.
    :param to_address: The SIP address to use in To headers.
        Must be present if `to` is not provided.
    :param from_address: The SIP address to use in From headers.
        Must be present if `from_hdr` is not provided.
    :param to_tag: The initial tag to use in To headers, if available.
    :param from_tag: The initial tag to use in From headers, if available.
    :param call_id: The Call-ID for this dialog. If None, a random one will be generated.
    :param cseq: The CSeq for this dialog. If None, a random one will be generated.
    :param own_side: The side of the call that we're on (caller or receiver).
        If not provided, it will be determined based on the From header/address.
    :param call_handler_factory: A callable that returns a :class:`CallHandler` instance.
        If not provided, the client's default call handler factory will be used.
    """

    def __init__(  # noqa: PLR0913
        self,
        client: SIPClient,
        *,
        uri: SIPURI | None = None,
        to: hdr.ToHeader | SIPAddress | None = None,
        from_hdr: hdr.FromHeader | None = None,
        to_address: SIPAddress | None = None,
        from_address: SIPAddress | None = None,
        to_tag: str | None = None,
        from_tag: str | None = None,
        call_id: str | None = None,
        cseq: int | None = None,
        own_side: CallSide | None = None,
        call_handler_factory: CallHandlerFactory | None = None,
    ):
        if (to is None) == (to_address is None):
            raise ValueError("Exactly one of `to` or `to_address` must be given")
        if from_hdr is not None and from_address is not None:
            raise ValueError("Only one of `from_hdr` or `from_address` must be given")

        if to is not None:
            if isinstance(to, hdr.ToHeader):
                to_address, to_tag = to.address, (to.tag or to_tag)
            elif isinstance(to, SIPAddress):
                to_address = to
            else:
                raise TypeError(f"Invalid type for 'to': {to!r}")
        assert to_address is not None

        if from_hdr is not None:
            if isinstance(from_hdr, hdr.FromHeader):
                from_address, from_tag = from_hdr.address, (from_hdr.tag or from_tag)
            else:
                raise TypeError(f"Invalid type for 'from_header': {from_hdr!r}")
        elif from_address is None:
            from_address = client.binding_address
        assert from_address is not None

        if from_tag is None:
            from_tag = generate_tag()
        assert from_tag is not None

        # FIXME: better determine if we are the caller or callee / From or To, and generate the tag accordingly

        if uri is None:
            uri = dataclass_replace(
                to_address.uri, password=None, params={}, headers={}
            )
        assert uri is not None

        if own_side is None:
            if from_address == client.binding_address:
                own_side = CallSide.CALLER
            else:
                own_side = CallSide.RECEIVER
        assert own_side is not None

        super().__init__(
            client,
            uri=uri,
            to_address=to_address,
            to_tag=to_tag,
            from_address=from_address,
            from_tag=from_tag,
            call_id=call_id,
            cseq=cseq,
        )

        self._own_side: CallSide = own_side
        self._state: CallState = CallState.INIT
        self._received_sdp: sdp.SDPSession | None = None
        self._sent_sdp: sdp.SDPSession | None = None
        self._failure_exception: Exception | None = None
        self._cancel_event: asyncio.Event = asyncio.Event()

        if call_handler_factory is None:
            call_handler_factory = self._client.call_handler_factory

        self._handler: CallHandler = call_handler_factory(self)

    @property
    def own_side(self) -> CallSide:
        """The side of the call that we're on."""
        return self._own_side

    @property
    def remote_address(self) -> SIPAddress:
        """The address of the remote party."""
        if self.own_side == CallSide.CALLER:
            return self._to_address
        else:
            return self._from_address

    @property
    def state(self) -> CallState:
        """The current state of the call."""
        return self._state

    @property
    def handler(self) -> CallHandler:
        """The :class:`CallHandler` instance used for this call."""
        return self._handler

    @property
    def received_sdp(self) -> sdp.SDPSession | None:
        """The SDP session received from the other party during the invite transaction."""
        return self._received_sdp

    @property
    def sent_sdp(self) -> sdp.SDPSession | None:
        """The SDP session sent by the client during the invite transaction."""
        return self._sent_sdp

    @property
    def failure_exception(self) -> Exception | None:
        """The exception that caused the call to fail, if any."""
        return self._failure_exception

    @override
    def _close(self) -> None:
        self._handler.teardown_call(self)
        super()._close()

    @contextlib.asynccontextmanager
    async def _handle_errors(self) -> AsyncGenerator[None, None]:
        try:
            yield
        # TODO: better handle other exceptions, like bad request, and send appropriate response
        except Exception as exc:  # noqa: BLE001
            self._state = CallState.FAILED
            self._failure_exception = exc
            self._close()
            if not self._handler.on_call_failure(self, exc):  # allow suppressing raise
                raise

    async def invite(self) -> None:
        """Start an outgoing call, and wait for the other party to answer."""
        async with self._handle_errors():
            await self._invite_send_transaction()

    def set_cancel(self) -> None:
        """Set the cancel event, to cancel a yet-unanswered outbound call."""
        self._cancel_event.set()

    async def bye(self) -> None:
        """Send a BYE request to terminate the call."""
        async with self._handle_errors():
            await self._bye_send_transaction()

    @override
    async def terminate(self) -> None:
        if self._closed:
            return

        if self._state not in {
            CallState.INIT,
            CallState.HUNG_UP,
            CallState.CANCELLED,
            CallState.FAILED,
        }:
            await self.bye()

    async def _handle_message(self, message: SIPMessage) -> None:
        """Handle an incoming SIP message, and start the appropriate flow."""
        if isinstance(message, SIPRequest):
            if message.method == SIPMethod.INVITE:
                async with self._handle_errors():
                    return await self._invite_recv_transaction(message)
            elif message.method == SIPMethod.BYE:
                return await self._bye_recv_transaction(message)

        # We shouldn't need to handle any response here, as they're caught by transactions

        raise SIPBadRequest(f"Unexpected request: {message!r}")

    def _process_received_message(
        self, message: SIPMessage, *, follow_cseq: bool = True, process_sdp: bool = True
    ) -> None:
        if follow_cseq:
            self._follow_cseq(message)
        if process_sdp and message.sdp is not None:
            self._process_received_sdp(message)

    def _process_received_sdp(self, message: SIPMessage) -> None:
        """Process the SDP from an incoming message, and update the state accordingly."""
        if message.sdp is None or not isinstance(message.sdp, sdp.SDPSession):
            raise SIPBadMessage("Missing or invalid SDP in message")
        # TODO: check if we have at least 1 supported media type
        self._received_sdp = message.sdp

    def _process_sent_sdp(self, message: SIPMessage) -> None:
        """Process the SDP from an outgoing message, and update the state accordingly."""
        if message.sdp is None or not isinstance(message.sdp, sdp.SDPSession):
            raise SIPBadMessage("Missing or invalid SDP in message")
        self._sent_sdp = message.sdp

    async def _invite_recv_transaction(self, invite: SIPRequest) -> None:
        """Handle an incoming INVITE request, wait for client answer and send 200 OK."""
        if not isinstance(invite, SIPRequest) or invite.method != SIPMethod.INVITE:
            raise TypeError(f"Invalid type for INVITE request: {invite!r}")

        if self._state != CallState.INIT:
            raise SIPException("Cannot handle incoming INVITE in current state")

        self._process_received_message(invite)

        self._state = CallState.INVITE

        if not self._handler.can_accept_calls:
            # TODO: should handle in some other way, maybe with a method vs property,
            #       that way we can detect missed calls in the handler/phone
            await self._reply_busy(invite)
            self._close()
            return

        # TODO: good opportunity here to send 100 Trying maybe? Or is that UAS only?
        self._handler.prepare_call(self)

        await self._reply_ringing(invite)

        request: SIPMessage
        # we now wait for the phone to answer, or for a CANCEL request, whatever comes first
        incoming_request = asyncio.create_task(
            self._wait_for_message(more_discard_statuses={SIPStatus.SESSION_PROGRESS}),
            name=f"{self.__class__.__name__}._wait_for_message-{self._call_id} task",
        )
        phone_answer = asyncio.create_task(
            self._handler.answer(self),
            name=f"{self.__class__.__name__}._call_handler.answer-{self._call_id} task",
        )
        done, _pending = await asyncio.wait(
            [incoming_request, phone_answer], return_when=asyncio.FIRST_COMPLETED
        )
        if incoming_request in done:
            await cancel_task_silent(phone_answer)

            request = incoming_request.result()
            if isinstance(request, SIPRequest) and request.method in {
                SIPMethod.CANCEL,
                SIPMethod.BYE,
            }:
                self._process_received_message(request, process_sdp=False)
                await self._reply_terminated(request)
                self._close()
                return

            raise SIPBadResponse(
                f"Unexpected message while waiting for answer: {request!r}"
            )

        elif phone_answer in done:  # noqa: RET506
            await cancel_task_silent(incoming_request)

            answered: bool = phone_answer.result()
            if not answered:
                await self._reply_busy(invite)
                return

            rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]]
            rtp_profiles_by_port = self._handler.get_rtp_profiles_by_port()
            media_flow: rtp.MediaFlowType = self._handler.get_media_flow()

            await self._reply_answer(invite, rtp_profiles_by_port, media_flow)

            try:
                request = await self._wait_for_message()
                if isinstance(request, SIPRequest) and request.method == SIPMethod.ACK:
                    self._process_received_message(request)
                    if self._received_sdp is None:
                        raise SIPBadRequest("Never received SDP in INVITE transaction")
                    self._state = CallState.ESTABLISHED
                    self._handler.establish_call(self)
                    return

            except asyncio.TimeoutError as e:
                raise SIPTimeout("ACK never received after 200 OK") from e

            raise SIPBadResponse(
                f"Unexpected message while waiting for ACK: {request!r}"
            )

        raise RuntimeError("INVITE never answered by phone, nor CANCELLED by caller")

    async def _invite_send_transaction(self) -> None:
        """Start an outgoing INVITE request, wait for 200 OK."""
        if self._state != CallState.INIT:
            raise SIPException("Cannot start INVITE flow in current state")

        if not self._handler.can_make_calls:
            raise SIPException(f"Call handler cannot make calls: {self._handler!r}")

        self._handler.prepare_call(self)

        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]]
        rtp_profiles_by_port = self._handler.get_rtp_profiles_by_port()
        media_flow: rtp.MediaFlowType = self._handler.get_media_flow()

        invite: SIPRequest | None = None

        async def sender(
            authorization: hdr.AuthorizationHeader | None = None,
        ) -> SIPRequest:
            nonlocal invite
            if invite is not None:  # clear previous transaction, reset
                await self._send_ack(invite, copy_via=True)
                self._from_tag = generate_tag()
                self._to_tag = None

            invite = await self._send_invite(
                rtp_profiles_by_port, media_flow, authorization=authorization
            )
            return invite

        response: SIPMessage
        invite, response = await self._might_authenticate(sender)
        self._state = CallState.INVITE
        self._recv_queue.put_nowait(response)

        async def wait_while_ringing() -> SIPResponse:
            while (
                isinstance((response := await self._wait_for_message()), SIPResponse)
                and response.status == SIPStatus.RINGING
            ):
                self._state = CallState.RINGING
            assert isinstance(response, SIPResponse)
            return response

        incoming_response = asyncio.create_task(
            wait_while_ringing(),
            name=f"{self.__class__.__name__}._invite_send_transaction"
            f".wait_while_ringing-{self._call_id} task",
        )
        self._cancel_event.clear()
        cancel_event = asyncio.create_task(
            self._cancel_event.wait(),
            name=f"{self.__class__.__name__}._cancel_event.wait-{self._call_id} task",
        )
        done, _pending = await asyncio.wait(
            [incoming_response, cancel_event], return_when=asyncio.FIRST_COMPLETED
        )

        if cancel_event in done:
            await cancel_task_silent(incoming_response)
            await self._send_cancel(invite)
            self._close()
            return

        elif incoming_response in done:
            await cancel_task_silent(cancel_event)

            response = incoming_response.result()

            if isinstance(response, SIPResponse) and response.status == SIPStatus.OK:
                self._state = CallState.ANSWERING

                if response.sdp is not None:
                    self._process_received_sdp(response)

                # process target refresh, if any
                ack_uri: SIPURI = self._uri
                if (ok_contact := response.headers.get("Contact")) is not None:
                    assert isinstance(ok_contact, hdr.ContactHeader)
                    if len(ok_contact) > 1:
                        raise SIPBadResponse(
                            f"Unexpected multiple contacts in 200 OK: {ok_contact!r}"
                        )
                    ok_contact_uri: SIPURI = ok_contact.contact.address.uri
                    # FIXME: doing this breaks the transaction, the URI should be changed only in ACK
                    #        but then what should we do to correctly do target refresh?
                    # if ok_contact_uri != self._uri:
                    #     self._uri = ok_contact_uri
                    ack_uri = ok_contact_uri

                await self._send_ack(invite, last_recv_msg=response, uri=ack_uri)

                self._state = CallState.ESTABLISHED
                self._handler.establish_call(self)
                return

            # TODO: handle other failure modes

            raise SIPBadResponse(f"Unexpected response to INVITE: {response!r}")

        raise RuntimeError("INVITE never answered by phone, nor CANCELLED by caller")

    async def _bye_recv_transaction(self, bye: SIPRequest) -> None:
        """Handle an incoming BYE request, and send 200 OK."""
        if not isinstance(bye, SIPRequest) or bye.method != SIPMethod.BYE:
            raise TypeError(f"Invalid type for BYE request: {bye!r}")

        if self._state not in {CallState.ESTABLISHED, CallState.ANSWERING}:
            raise SIPException("Cannot handle incoming BYE in current state")

        _logger.debug(f"Received BYE request, terminating call: {bye!r}")

        self._follow_cseq(bye)

        self._state = CallState.HANGING_UP
        self._handler.terminate_call(self)

        await self._reply_ok(bye)

        self._state = CallState.HUNG_UP
        self._close()

    async def _bye_send_transaction(self) -> None:
        """Start an outgoing BYE request, wait for 200 OK (or silent timeout)."""
        if self._state in {
            CallState.INIT,
            CallState.HUNG_UP,
            CallState.CANCELLED,
            CallState.FAILED,
        }:
            raise SIPException("Cannot start BYE flow in current state")

        try:
            await self._send_bye()

            self._state = CallState.HANGING_UP
            self._handler.terminate_call(self)

            response: SIPMessage = await self._wait_for_message()
            if isinstance(response, SIPResponse) and response.status == SIPStatus.OK:
                pass  # ok
            else:
                raise SIPBadResponse(f"Unexpected response to BYE: {response!r}")

        except asyncio.TimeoutError:
            pass

        finally:
            self._state = CallState.HUNG_UP
            self._close()

    def _generate_sdp_session(
        self,
        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]],
        media_flow: rtp.MediaFlowType,
    ) -> sdp.SDPSession:
        return self._client.generate_sdp_session(
            session_id=abs(hash(self._call_id)),
            rtp_profiles_by_port=rtp_profiles_by_port,
            media_flow=media_flow,
        )

    def _invite_request(
        self,
        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]],
        media_flow: rtp.MediaFlowType,
        authorization: hdr.AuthorizationHeader | None = None,
    ) -> SIPRequest:
        """Create an INVITE request."""
        return self._generate_request(
            SIPMethod.INVITE,
            is_initial=True,
            extra_headers=[authorization] if authorization else [],
            body=self._generate_sdp_session(rtp_profiles_by_port, media_flow),
        )

    def _ack_request(
        self,
        invite: SIPRequest,
        *,
        last_recv_msg: SIPMessage | None = None,
        copy_via: bool = False,
        **kwargs: Any,
    ) -> SIPRequest:
        """Create an ACK request."""
        if "CSeq" not in invite.headers:
            raise RuntimeError("INVITE request has no CSeq header")
        invite_cseq: hdr.CSeqHeader = invite.headers["CSeq"]
        if copy_via and "Via" not in invite.headers:
            raise RuntimeError("INVITE request has no Via header")
        via_hdr: hdr.ViaHeader = invite.headers["Via"]
        route_hdr = self._client.generate_route_hdr(last_recv_msg or invite)

        return self._generate_request(
            SIPMethod.ACK,
            add_via=False,
            cseq=invite_cseq.sequence,
            cseq_method=SIPMethod.ACK,
            via_hdr=via_hdr if copy_via else self._client.generate_via_hdr(),
            **kwargs,
            extra_headers=[route_hdr] if route_hdr is not None else (),
        )

    def _cancel_request(self, invite: SIPRequest) -> SIPRequest:
        """Create a CANCEL request."""
        if "CSeq" not in invite.headers:
            raise RuntimeError("INVITE request has no CSeq header")
        invite_cseq: hdr.CSeqHeader = invite.headers["CSeq"]
        if "Via" not in invite.headers:
            raise RuntimeError("INVITE request has no Via header")
        via_hdr: hdr.ViaHeader = invite.headers["Via"]
        return self._generate_request(
            SIPMethod.CANCEL,
            cseq=invite_cseq.sequence,
            cseq_method=invite_cseq.method,
            via_hdr=via_hdr,
        )

    def _ringing_response(self, request: SIPRequest) -> SIPResponse:
        """Create a 180 Ringing response to an INVITE request."""
        # TODO: add Supported?
        return self._generate_response_from_request(request, SIPStatus.RINGING)

    def _ok_response(self, request: SIPRequest) -> SIPResponse:
        """Create a 200 OK response to an INVITE request."""
        return self._generate_response_from_request(request, SIPStatus.OK)

    def _answer_response(
        self,
        request: SIPRequest,
        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]],
        media_flow: rtp.MediaFlowType,
    ) -> SIPResponse:
        """Create a 200 OK response to an INVITE request."""
        return self._generate_response_from_request(
            request,
            SIPStatus.OK,
            body=self._generate_sdp_session(rtp_profiles_by_port, media_flow),
        )

    def _busy_response(self, request: SIPRequest) -> SIPResponse:
        """Create a 486 Busy Here response to an INVITE request."""
        # TODO: add a Warning header?
        return self._generate_response_from_request(request, SIPStatus.BUSY_HERE)

    def _terminated_response(self, request: SIPRequest) -> SIPResponse:
        """Create a 487 Request Terminated response to a CANCEL request."""
        return self._generate_response_from_request(
            request, SIPStatus.REQUEST_TERMINATED
        )

    # FIXME: should we do state transitions here? Wouldn't it be cleaner in the transactions methods?

    async def _send_invite(
        self,
        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]],
        media_flow: rtp.MediaFlowType,
        authorization: hdr.AuthorizationHeader | None = None,
    ) -> SIPRequest:
        if self._state != CallState.INIT:
            raise RuntimeError(f"Cannot send INVITE in state {self._state}")

        invite_request: SIPRequest = self._invite_request(
            rtp_profiles_by_port, media_flow, authorization=authorization
        )
        assert invite_request.sdp is not None
        await self._send_request(invite_request)
        self._process_sent_sdp(invite_request)
        return invite_request

    async def _send_ack(
        self,
        invite: SIPRequest,
        *,
        last_recv_msg: SIPMessage | None = None,
        copy_via: bool = False,
        **kwargs: Any,
    ) -> SIPRequest:
        ack_request: SIPRequest = self._ack_request(
            invite,
            last_recv_msg=last_recv_msg,
            copy_via=copy_via,
            **kwargs,
        )
        await self._send_message(ack_request)
        return ack_request

    async def _send_cancel(self, invite: SIPRequest) -> SIPRequest:
        if self._state not in {CallState.INVITE, CallState.RINGING}:
            raise RuntimeError(f"Cannot send CANCEL in state {self._state}")

        cancel_request: SIPRequest = self._cancel_request(invite)
        await self._send_message(cancel_request)
        self._state = CallState.CANCELLED
        return cancel_request

    async def _send_bye(self) -> SIPRequest:
        if self._state not in {CallState.ESTABLISHED, CallState.INVITE}:
            raise RuntimeError(f"Cannot send BYE in state {self._state}")

        bye_request: SIPRequest = self._generate_request(SIPMethod.BYE)
        await self._send_message(bye_request)
        self._state = CallState.HANGING_UP
        return bye_request

    async def _reply_ringing(self, request: SIPRequest) -> SIPResponse:
        if self._state != CallState.INVITE:
            raise RuntimeError(f"Cannot reply 180 Ringing in state: {self._state}")

        self._state = CallState.RINGING
        ringing_response: SIPResponse = self._ringing_response(request)
        await self._send_message(ringing_response)
        return ringing_response

    async def _reply_answer(
        self,
        request: SIPRequest,
        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]],
        media_flow: rtp.MediaFlowType,
    ) -> SIPResponse:
        if self._state != CallState.RINGING:
            raise RuntimeError(f"Cannot reply 200 OK in state: {self._state}")

        self._state = CallState.ANSWERING
        ok_response: SIPResponse = self._answer_response(
            request, rtp_profiles_by_port, media_flow
        )
        assert ok_response.sdp is not None
        await self._send_message(ok_response)
        # TODO: if the c= in the received SDP is not the server, we need to provide
        #       the connection address to the sdp generation method so that our external IP
        #       can be properly determined from it, and we can include it in our c= line
        self._process_sent_sdp(ok_response)
        return ok_response

    async def _reply_ok(self, request: SIPRequest) -> SIPResponse:
        ok_response: SIPResponse = self._ok_response(request)
        await self._send_message(ok_response)
        return ok_response

    async def _reply_busy(self, request: SIPRequest) -> SIPResponse:
        if self._state in {CallState.INIT, CallState.CANCELLED, CallState.FAILED}:
            raise RuntimeError(f"Cannot reply 486 Busy Here in state {self._state}")

        self._state = CallState.CANCELLED
        busy_response: SIPResponse = self._busy_response(request)
        await self._send_message(busy_response)
        return busy_response

    async def _reply_terminated(self, request: SIPRequest) -> SIPResponse:
        if self._state in {CallState.INIT, CallState.CANCELLED, CallState.FAILED}:
            raise RuntimeError(
                f"Cannot reply 487 Request Terminated in state {self._state}"
            )

        self._state = CallState.CANCELLED
        terminated_response: SIPResponse = self._terminated_response(request)
        await self._send_message(terminated_response)
        return terminated_response


class SIPClient:  # noqa: PLR0904
    """
    SIP client implementation that communicates over UDP.

    :param call_handler_factory: A callable that returns a :class:`CallHandler` instance.
        This will be used to handle outgoing and incoming calls.
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
    :param local_host: The local address to bind the client's socket to.
        Defaults to 0.0.0.0.
    :param local_port: The local port to bind the client's socket to.
        Defaults to 0, which means a random port will be chosen by the OS.
    :param register_attempts: The number of attempts to register with the SIP server.
        Defaults to 5.
    :param register_timeout: The timeout for registration attempts, in seconds.
        Defaults to 30.0.
    :param register_expires: The expiration time for registration, in seconds.
        Defaults to 3600 (1 hour).
    :param default_response_timeout: The default timeout for SIP responses, in seconds.
        Defaults to 32.0.
    :param max_forwards: The maximum number of hops for SIP requests.
        Defaults to 70.
    :param keep_alive_interval: The interval at which to send keep-alive UDP packets,
        in seconds. This is used to keep the NAT mapping alive. Defaults to 5.0.
    """

    def __init__(  # noqa: PLR0913
        self,
        call_handler_factory: CallHandlerFactory,
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
        register_attempts: int = 5,
        register_timeout: float = 30.0,
        register_expires: int = 3600,
        default_response_timeout: float = 32.0,
        max_forwards: int = 70,
        keep_alive_interval: float | None = 5.0,
    ):
        self.call_handler_factory: CallHandlerFactory = call_handler_factory

        self._username: str = username
        self._login: str = login if login is not None else username
        self._password: str = password
        self._display_name: str | None = display_name
        self._domain: str = domain if domain is not None else server_host

        if server_port is None:
            if match := re.search(r"^(?P<host>.+):(?P<port>\d+)$", server_host):
                server_host = match.group(1)
                server_port = int(match.group(2))
            else:
                server_port = DEFAULT_SIP_PORT
        self._server_addr: tuple[str, int] = (server_host, server_port)
        # FIXME: do we even need this local address now? Since we determine automatically our external address (be it interface or public IP)
        self._local_addr: tuple[str, int] = (local_host, local_port)

        self.default_response_timeout: float = default_response_timeout
        self._max_forwards: int = max_forwards

        self.register_attempts: int = register_attempts  # FIXME: unused, implement
        self.register_timeout: float = register_timeout
        self.register_expires: int = register_expires
        self._register_dialog: SIPRegistration | None = None

        self.generic_timeout: float = (
            max(self.default_response_timeout, self.register_timeout) * 1.5
        )

        self._keep_alive_interval: float | None = keep_alive_interval
        self._keep_alive_known_addresses: set[tuple[str, int]] = set()

        self._dialogs: MutableMapping[str, SIPDialog] = {}
        """Map of call IDs to SIP sessions."""

        self._event_loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)
        self._event_loop.set_exception_handler(self._handle_loop_exception)
        self._event_loop_thread: threading.Thread = threading.Thread(
            target=self._run_event_loop,
            name=f"{self.__class__.__name__}._run_event_loop-{id(self)}",
        )
        self._pending_futures: list[asyncio.Future | concurrent.futures.Future]
        self._pending_futures = []

        self._socket: socket.socket | None = None
        self._socket_lock: threading.Lock = threading.Lock()

        self._registered: bool = False
        self._recv_thread: threading.Thread | None = None
        self._recv_msg_hashes: set[bytes] = set()
        self._recv_ignore_count: int = 0

        self._closed: bool = True
        self._closing_event: threading.Event = threading.Event()
        self._closing_event.clear()

    @property
    def server_addr(self) -> tuple[str, int]:
        """The address and port of the SIP server used by the client."""
        return self._server_addr

    @property
    def server_host(self) -> str:
        """The address of the SIP server used by the client."""
        return self._server_addr[0]

    @property
    def server_port(self) -> int:
        """The port of the SIP server used by the client."""
        return self._server_addr[1]

    @property
    def local_addr(self) -> tuple[str, int]:
        """The local address and port to which the client's socket is bound."""
        return self._local_addr

    @property
    def local_host(self) -> str:
        """The local address to which the client's socket is bound."""
        return self._local_addr[0]

    @property
    def local_port(self) -> int:
        """The local port to which the client's socket is bound."""
        return self._local_addr[1]

    @property
    def own_ip_to_server(self) -> str:
        """The IP address of the client as seen by the SIP server."""
        return get_external_ip_for_dest(self.server_host)

    @property
    def own_addr_to_server(self) -> tuple[str, int]:
        """The IP address and port of the client as seen by the SIP server."""
        # FIXME: if the connection is over NAT the port will be different as well!
        #        this is usually okay, due to the rport mechanism, but we should still
        #        investigate proper handling of this (see e.g. RFC 3581)
        return self.own_ip_to_server, self.local_port

    @property
    def server_uri(self) -> SIPURI:
        """The URI of the SIP server used by the client to register and send requests to."""
        return SIPURI(
            host=self._domain,
            port=self.server_port if self.server_port != DEFAULT_SIP_PORT else None,
        )

    @property
    def _auth_uri(self) -> SIPURI:
        return dataclass_replace(self.server_uri, params={"transport": "UDP"})

    @property
    def binding_uri(self) -> SIPURI:
        """
        Return the binding URI for this client, i.e. the logical URI of the client's
        identity as registered within the SIP location service.
        This value is used primarily in the ``Form:`` / ``To:`` headers.
        """
        return dataclass_replace(self.server_uri, user=self._username)

    @property
    def binding_address(self) -> SIPAddress:
        """
        Return the binding address for this client, i.e. the logical address of the client's
        identity as registered within the SIP location service.
        This value is used primarily in the ``Form:`` / ``To:`` headers.
        """
        return SIPAddress(display_name=self._display_name, uri=self.binding_uri)

    @property
    def contact_uri(self) -> SIPURI:
        """
        Return the contact URI for this client, i.e. the direct URI of the client
        to which other UA can send request within a dialog.
        This value is used primarily in the ``Contact:`` header.
        """
        # TODO: should Contact: URI always include stuff like transport etc?
        return dataclass_replace(
            self.binding_uri,
            host=self.own_ip_to_server,
            port=self.local_port,
            params={"ob": None, "transport": "UDP"},
        )

    @property
    def contact_address(self) -> SIPAddress:
        """
        Return the contact address for this client, i.e. the direct address of the client
        to which other UA can send request within a dialog.
        This value is used primarily in the Contact: header.
        """
        return SIPAddress(display_name=self._display_name, uri=self.contact_uri)

    @property
    def _contact(self) -> hdr.Contact:
        return hdr.Contact(self.contact_address)

    @property
    def user_agent(self) -> str:
        """The User-Agent header value for this client."""
        return f"{sibilant.__title__}/{sibilant.__version__}"

    @property
    def registered(self) -> bool:
        """Whether the client is registered to the SIP server."""
        return bool(self._register_dialog and self._register_dialog.registered)

    @property
    def allowed_methods(self) -> Sequence[str]:  # TODO: make dynamic?
        """The allowed methods in SIP requests supported by this client."""
        return "INVITE", "ACK", "CANCEL", "BYE", "OPTIONS"

    @property
    def supported_content_types(self) -> Sequence[str]:
        """The content types in SIP messages supported by this client."""
        return ("application/sdp",)

    @property
    def closed(self) -> bool:
        """Whether the client is closed and inactive."""
        return self._closed

    @property
    def calls(self) -> Mapping[str, SIPDialog]:
        """A mapping of call IDs to active calls."""
        return MappingProxyType({
            call_id: dialog
            for call_id, dialog in self._dialogs.items()
            if isinstance(dialog, SIPCall)
        })

    @property
    def _dialogs_except_register(self) -> Mapping[str, SIPDialog]:
        return MappingProxyType({
            call_id: dialog
            for call_id, dialog in self._dialogs.items()
            if not isinstance(dialog, SIPRegistration)
        })

    def _track_dialog(self, dialog: SIPDialog) -> None:
        assert dialog.call_id not in self._dialogs
        assert dialog.client is self
        self._dialogs[dialog.call_id] = dialog

    def _untrack_dialog(
        self, dialog: SIPDialog | None, call_id: str | None = None
    ) -> None:
        if dialog is None and call_id is None:
            raise ValueError("Either 'dialog' or 'call_id' must be specified")
        if dialog is not None and call_id is not None and dialog.call_id != call_id:
            raise ValueError("Call ID does not match dialog")
        if call_id is None:
            assert dialog is not None
            call_id = dialog.call_id
        if call_id not in self._dialogs:
            _logger.warning(
                f"Call ID {call_id} not found in tracked dialogs"
            )  # TODO: debug?
        else:
            del self._dialogs[call_id]

    def start(self) -> None:
        """Start the SIP client, registering to the SIP server."""
        try:
            if self._socket is not None:
                raise RuntimeError("SIP client already started")

            self._closed = False

            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024
            )
            self._socket.setblocking(False)
            self._socket.bind(self._local_addr)

            # TODO: name threads
            self._recv_thread = threading.Thread(
                target=self._recv_loop,
                name=f"{self.__class__.__name__}._recv_loop-{id(self)}",
            )
            self._recv_thread.start()

            self._event_loop_thread.start()

            self._register()

        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        """Stop the SIP client, closing active dialogs and deregistering if needed."""
        if self._dialogs_except_register:
            try:
                self._schedule(self._close_active_dialogs()).result(
                    self.generic_timeout
                )
            except (asyncio.TimeoutError, concurrent.futures.TimeoutError) as exc:
                _logger.warning(f"Timeout while closing active dialogs: {exc!r}")

        if self.registered:
            self._deregister()

        self._closing_event.set()

        if (
            threading.current_thread() is not self._event_loop_thread
            and self._event_loop_thread.is_alive()
        ):
            self._event_loop_thread.join()

        if self._recv_thread is not None and self._recv_thread.is_alive():
            self._recv_thread.join()
        if self._socket is not None:
            self._socket.close()

        self._socket = None
        self._recv_thread = None
        self._closed = True
        self._closing_event.clear()

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exctype: type[BaseException] | None,
        excinst: BaseException | None,
        exctb: TracebackType | None,
    ) -> None:
        self.stop()

    @property
    def event_loop(self) -> asyncio.AbstractEventLoop:
        """The asyncio event loop used by the client instance."""
        return self._event_loop

    # FIXME: we want errors raised in the event loop thread to stop the main loop
    def _run_event_loop(self) -> None:
        asyncio.set_event_loop(self._event_loop)
        try:
            self._event_loop.run_until_complete(self._async_monitor())
        finally:
            self._event_loop.stop()
            self._event_loop.close()
            if not self._closing_event.is_set():
                self.stop()

    async def _async_monitor(self) -> None:
        """
        Async loop that monitors pending tasks for any exceptions and makes sure
        everything is cleaned up when stopping.
        """
        terminate_asap: bool = False
        while not self._closing_event.is_set() or self._pending_futures:
            fut: asyncio.Future | concurrent.futures.Future
            for fut in list(self._pending_futures):
                if fut.done():
                    if not fut.cancelled() and (exc := fut.exception()) is not None:
                        context = {
                            "message": f"Exception in SIP client async: {exc}",
                            "exception": exc,
                            "future": fut,
                        }
                        self._event_loop.call_exception_handler(context)

                    self._pending_futures.remove(fut)

                elif self._closing_event.is_set():
                    fut.cancel()

            if (
                not (self._closing_event.is_set() or terminate_asap)
                and self._register_dialog is not None
                and self._register_dialog.closed
            ):
                _logger.error("Registration or refresh failed, stopping client")
                terminate_asap = True

            await asyncio.sleep(1e-2)

        await self._event_loop.shutdown_asyncgens()

    def _handle_loop_exception(
        self, loop: asyncio.AbstractEventLoop, context: Mapping[str, Any]
    ) -> None:
        """Handle exceptions in the event loop by logging as error."""
        message: str = (
            f"Exception in event loop: {context['message']}\nContext: {context!r}"
        )
        exception = context.get("exception")
        # FIXME: this does not work, will stop the async loop thread at most
        # if exception is not None and not isinstance(
        #     exception, (asyncio.CancelledError, SIPException)
        # ):
        #     raise exception
        if _logger.getEffectiveLevel() <= logging.DEBUG:
            _logger.exception(message, exc_info=exception)
        else:
            _logger.error(message)

    def _track_future(self, future: asyncio.Future | concurrent.futures.Future) -> None:
        if hasattr(future, "get_loop") and future.get_loop() is not self._event_loop:
            raise RuntimeError("Cannot track future from another event loop")
        self._pending_futures.append(future)

    def _schedule(self, coro: Awaitable) -> concurrent.futures.Future:
        future = asyncio.run_coroutine_threadsafe(coro, self._event_loop)
        self._track_future(future)
        return future

    def _recv_msg(self, timeout: float | None = None) -> SIPMessage:
        assert self._socket is not None
        start_time: float = time.monotonic()
        while not timeout or (time.monotonic() - start_time < timeout):
            with self._socket_lock:
                self._socket.setblocking(False)
                try:
                    data, addr = self._socket.recvfrom(8192)
                    # TODO: assert addr == self._server_addr?
                except (socket.timeout, BlockingIOError, ConnectionResetError):
                    pass
                else:
                    msg = SIPMessage.parse(data, origin=addr)
                    data_hash: bytes = hashlib.md5(data).digest()
                    if data_hash in self._recv_msg_hashes:
                        _logger.debug(f"Ignoring retransmitted message: {msg!r}")
                        self._recv_ignore_count += 1
                    else:
                        self._recv_msg_hashes.add(data_hash)
                        return msg

            if not timeout:
                break

        raise SIPTimeout("Timed out waiting for SIP message")

    def _recv_loop(self) -> None:
        while not self._closing_event.is_set():
            try:
                message = self._recv_msg()

            except SIPTimeout:
                pass

            except SIPUnsupportedVersion:
                pass  # TODO: implement. Send a not supported message?

            except SIPParseError as e:
                _logger.debug(f"Error parsing SIP message: {e}")

            else:
                self._schedule(self._handle_message(message))

            time.sleep(1e-6)

    async def _handle_message(self, message: SIPMessage) -> None:
        call_id_hdr: hdr.CallIDHeader | None = message.headers.get("Call-ID")
        if call_id_hdr is None:
            _logger.warning(f"Discarding SIP message without Call-ID: {message!r}")
            return

        call_id: str = call_id_hdr.value

        if call_id in self._dialogs:
            await self._dialogs[call_id].receive_message(message)
        # TODO: make this dynamic? make a registry of "handlers" from the dialog classes?
        elif isinstance(message, SIPRequest):
            if message.method == SIPMethod.INVITE:
                await self._handle_invite(message)
            elif message.method == SIPMethod.OPTIONS:
                await self._handle_options(message)
        else:
            _logger.warning(
                f"Discarding SIP message for untracked call ID: {message!r}"
            )
            return

    # TODO: this must be a coro
    def _send_msg(self, message: SIPMessage) -> None:
        message_raw: bytes = message.serialize()
        self._send_bytes(message_raw, addr=message.destination or None)

    def _send_bytes(
        self,
        data_raw: bytes,
        addr: tuple[str, int] | None = None,
        *,
        send_wait: bool = False,
    ) -> None:
        assert self._socket is not None
        if not addr:
            addr = self._server_addr
        with self._socket_lock:
            self._socket.setblocking(True)
            sent: int = 0
            while sent < len(data_raw):
                sent += self._socket.sendto(data_raw[sent:], addr)
                if not send_wait:
                    break
            self._socket.setblocking(False)
        self._keep_alive_known_addresses.add(addr)

    def _register(self) -> None:
        if self._register_dialog is not None:
            raise RuntimeError("Registration already active")

        _logger.debug(f"Registering with {self.server_host} with user {self._username}")
        self._register_dialog = SIPRegistration(self)

        try:
            self._schedule(self._register_dialog.register()).result(
                self.generic_timeout
            )
        except (asyncio.TimeoutError, concurrent.futures.TimeoutError) as exc:
            _logger.warning(f"Timeout while registering: {exc!r}")
            self.stop()
            raise

        if self._keep_alive_interval:
            self._schedule(self._udp_keep_alive())

    def _deregister(self) -> None:
        if self._register_dialog is None:
            raise RuntimeError("Registration not active")

        async def _deregister() -> None:
            assert self._register_dialog is not None
            await self._register_dialog.deregister()
            self._register_dialog = None

        try:
            self._schedule(_deregister()).result(self.generic_timeout)
        except (asyncio.TimeoutError, concurrent.futures.TimeoutError) as exc:
            _logger.warning(f"Timeout while deregistering: {exc!r}")
        except SIPException as exc:
            _logger.warning(f"Error while deregistering: {exc}")

    async def _close_active_dialogs(self) -> None:
        """Schedule close all dialogs with their async close using gather."""
        await asyncio.gather(
            *(dialog.terminate() for dialog in self._dialogs_except_register.values()),
            return_exceptions=True,
        )

    async def _udp_keep_alive(self) -> None:
        """Send a periodic UDP keepalive to the server, to keep NAT traversal open."""
        assert self._keep_alive_interval is not None
        try:
            while not self._closing_event.is_set():
                known_addresses = list(self._keep_alive_known_addresses)
                for addr in known_addresses:
                    sleep_time = self._keep_alive_interval / len(known_addresses)
                    await asyncio.sleep(sleep_time)
                    data = b"\x0d\x0a\x0d\x0a"
                    self._send_bytes(data, addr=addr, send_wait=True)
                if not known_addresses:
                    await asyncio.sleep(self._keep_alive_interval)
        except asyncio.CancelledError:
            pass

    # TODO: should this be async? or should it be blocking?
    def invite(
        self,
        contact: SIPAddress | SIPURI | str,
        call_handler_factory: CallHandlerFactory | None = None,
    ) -> SIPCall:
        """
        Start a new SIP call (INVITE request in UAC role).

        This function is not blocking, it returns a :class:`SIPCall` dialog object
        that can be used to inspect the call state.

        The handling of async events generated by the call is delegated to the
        call handler object returned by the call handler factory.

        :param contact: the contact address to invite.
        :param call_handler_factory: the factory to use to create the call handler.
            If not specified, the client's call handler factory provided at initialization time
            will be used instead.
        :return: the created call dialog.
        """
        if isinstance(contact, str):
            if "@" not in contact:
                contact = SIPURI(
                    host=self.server_host, port=self.server_port, user=contact
                )
            else:
                contact = SIPAddress.parse(contact, force_brackets=True)
        if isinstance(contact, SIPURI):
            contact = SIPAddress(uri=contact)
        if not isinstance(contact, SIPAddress):
            raise TypeError(f"Invalid type for contact {type(contact)}: {contact!r}")

        if call_handler_factory is None:
            call_handler_factory = self.call_handler_factory

        call = SIPCall(
            self,
            to=contact,
            own_side=CallSide.CALLER,
            call_handler_factory=call_handler_factory,
        )
        self._schedule(call.invite())
        return call

    # TODO: start invite

    async def _handle_invite(self, message: SIPRequest) -> None:
        # TODO: check if the call is for us

        # TODO: sanity check the message has From etc.
        _logger.debug(f"Received INVITE {message.headers['From']}: {message!r}")
        call = SIPCall.from_request(self, message, own_side=CallSide.RECEIVER)
        await call.receive_message(message)

    async def _handle_options(self, message: SIPRequest) -> None:
        _logger.debug(f"Received OPTIONS {message.headers['From']}: {message!r}")
        dialog = SIPOptions.from_request(self, message)
        await dialog.receive_message(message)

    def generate_via_hdr(self) -> hdr.ViaHeader:
        """Generate a Via header for a SIP message using the client's public address."""
        via_entry = hdr.ViaEntry(
            "SIP/2.0/UDP",
            *self.own_addr_to_server,
            branch=generate_via_branch(),
        )
        via_entry.rport = True
        return hdr.ViaHeader([via_entry])

    def generate_route_hdr(self, message: SIPMessage) -> hdr.RouteHeader | None:
        """
        Generate a Route header for a SIP message.

        :param message: the SIP message to generate the Route header for.
            Will return None if no Record-Route header is present.
        :return: the generated Route header or None.
        """
        # TODO: review correctness of this method logic
        route: list[hdr.Contact]
        if (record_route_hdr := message.headers.get("Record-Route")) is not None:
            route = list(reversed(record_route_hdr.values))
            return hdr.RouteHeader(route)
        return None

    def prepare_headers(  # noqa: PLR0913
        self,
        *extra_headers: hdr.Header,
        from_address: SIPAddress,
        to_address: SIPAddress,
        call_id: str,
        cseq: int,
        cseq_method: SIPMethod,
        via_hdr: hdr.ViaHeader | None = None,
        is_initial: bool = False,
        contact: hdr.Contact | None = None,
        from_tag: str | None = None,
        to_tag: str | None = None,
        allow: Sequence[str] | None = None,
        content_type: str | None = None,
        body: SupportsStr | None = None,
    ) -> hdr.Headers:
        """
        Prepare the headers for a SIP message.

        :param extra_headers: extra headers to include in the message.
        :param from_address: the address to use in the From header.
        :param to_address: the address to use in the To header.
        :param call_id: the call ID to use in the Call-ID header.
        :param cseq: the CSeq sequence number to use in the CSeq header.
        :param cseq_method: the CSeq method to use in the CSeq header.
        :param via_hdr: the Via headers to use. If not specified, a new one will be generated.
        :param is_initial: whether the message is an initial request in a dialog. Defaults to False.
        :param contact: the contact address for the Contact header.
            If not specified, the client's contact address will be used.
        :param from_tag: the tag to use in the From header, if any.
        :param to_tag: the tag to use in the To header, if any.
        :param allow: the methods to include in the Allow header, if any.
        :param content_type: the content type to use in the Content-Type header, if any.
        :param body: the body of the message, if any.
        :return: the prepared headers.
        """
        if body and content_type is None:
            if hasattr(body, "mimetype"):
                content_type = body.mimetype
            else:
                raise ValueError("Cannot have body without content type")

        if call_id is None:  # TODO: make this mandatory?
            call_id = generate_call_id(*self.local_addr)

        if via_hdr is None:
            via_hdr = self.generate_via_hdr()

        # FIXME: this is_initial code is probably wrong. Investigate correct usage of Contact:
        if is_initial and contact is None:
            contact = self._contact

        if allow is not None:
            extra_headers += (hdr.AllowHeader(list(allow)),)

        return hdr.Headers(
            via_hdr,
            hdr.FromHeader(from_address, tag=from_tag),
            hdr.ToHeader(to_address, tag=to_tag),
            hdr.CallIDHeader(call_id),
            hdr.CSeqHeader(cseq, cseq_method),
            *([hdr.ContactHeader([contact])] if contact else ()),
            hdr.MaxForwardsHeader(self._max_forwards),
            *([hdr.UserAgentHeader(self.user_agent)] if is_initial else ()),
            *extra_headers,
            *([hdr.ContentTypeHeader(content_type)] if content_type else ()),
            hdr.ContentLengthHeader(len(str(body).encode()) if body else 0),
        )

    def generate_request(  # noqa: PLR0913
        self,
        method: SIPMethod,
        uri: SIPURI | None = None,
        *,
        from_address: SIPAddress,
        to_address: SIPAddress,
        call_id: str,
        cseq: int,
        cseq_method: SIPMethod | None = None,
        via_hdr: hdr.ViaHeader | None = None,
        is_initial: bool = False,
        contact: hdr.Contact | None = None,
        from_tag: str | None = None,
        to_tag: str | None = None,
        allow: Sequence[str] | None = None,
        content_type: str | None = None,
        extra_headers: Sequence[hdr.Header] = (),
        body: SupportsStr | None = None,
        origin: tuple[str, int] | None = None,
        destination: tuple[str, int] | None = None,
    ) -> SIPRequest:
        """
        Generate a SIP request with the given method and headers arguments.

        For documentation on the accepted arguments see :meth:`.prepare_headers`.

        :param method: the method of the request.
        :param uri: the URI of the request.
        :return: the generated request.
        """
        if uri is None:
            uri = self.binding_uri
        if cseq_method is None:
            cseq_method = method

        prepared_headers: hdr.Headers = self.prepare_headers(
            *extra_headers,
            from_address=from_address,
            to_address=to_address,
            call_id=call_id,
            cseq=cseq,
            cseq_method=cseq_method,
            via_hdr=via_hdr,
            is_initial=is_initial,
            contact=contact,
            from_tag=from_tag,
            to_tag=to_tag,
            allow=allow,
            content_type=content_type,
            body=body,
        )
        return SIPRequest(
            version="SIP/2.0",
            method=method,
            uri=uri,
            headers=prepared_headers,
            body=body,
            origin=origin,
            destination=destination,
        )

    def generate_response(  # noqa: PLR0913
        self,
        status: SIPStatus,
        *,
        via_hdr: hdr.ViaHeader,
        from_address: SIPAddress,
        to_address: SIPAddress,
        call_id: str,
        cseq: int,
        cseq_method: SIPMethod,
        contact: hdr.Contact | None = None,
        from_tag: str | None = None,
        to_tag: str | None = None,
        allow: Sequence[str] | None = None,
        content_type: str | None = None,
        extra_headers: Sequence[hdr.Header] = (),
        body: SupportsStr | None = None,
        origin: tuple[str, int] | None = None,
        destination: tuple[str, int] | None = None,
    ) -> SIPResponse:
        """
        Generate a SIP response with the given status code and headers arguments.

        For documentation on the accepted arguments see :meth:`.prepare_headers`.

        :param status: the status code of the response.
        :return: the generated response.
        """
        prepared_headers: hdr.Headers = self.prepare_headers(
            *extra_headers,
            from_address=from_address,
            to_address=to_address,
            call_id=call_id,
            cseq=cseq,
            cseq_method=cseq_method,
            via_hdr=via_hdr,
            contact=contact,
            from_tag=from_tag,
            to_tag=to_tag,
            allow=allow,
            content_type=content_type,
            body=body,
        )
        return SIPResponse(
            version="SIP/2.0",
            status=status,
            headers=prepared_headers,
            body=body,
            origin=origin,
            destination=destination,
        )

    def generate_response_from_request(
        self, request: SIPRequest, status: SIPStatus, **kwargs: Any
    ) -> SIPResponse:
        """
        Generate a response to the given request, properly copying the necessary headers.

        :param request: the request to generate the response for.
        :param status: the status of the response.
        :param kwargs: additional keyword arguments to pass to :meth:`.generate_response`.
        :return: the generated response.
        """

        def set_from_request(kwarg: str, header: str, attr: str | None) -> None:
            nonlocal kwargs
            if kwarg not in kwargs:
                req_value = request.headers.get(header)
                if req_value is not None:
                    if attr is not None:
                        req_value = getattr(req_value, attr)
                    kwargs[kwarg] = req_value

        set_from_request("via_hdr", "Via", None)
        set_from_request("from_address", "From", "address")
        set_from_request("from_tag", "From", "tag")
        set_from_request("to_address", "To", "address")
        set_from_request("to_tag", "To", "tag")
        set_from_request("call_id", "Call-ID", "value")
        set_from_request("cseq", "CSeq", "sequence")
        set_from_request("cseq_method", "CSeq", "method")
        kwargs.setdefault("contact", self._contact)

        extra_headers: list[hdr.Header] = list(kwargs.pop("extra_headers", ()))
        # check if "Route" is in extra_headers, if not, set it from the request
        # FIXME: apparently this should not happen. Instead we should echo the Record-Route headers
        # if not any(isinstance(h, hdr.RouteHeader) for h in extra_headers):
        #     extra_headers.append(self.generate_route_hdr(request))
        if record_route_hdr := request.headers.get("Record-Route"):
            extra_headers.append(record_route_hdr)
        kwargs["extra_headers"] = tuple(extra_headers)

        kwargs.setdefault("destination", request.origin)

        return self.generate_response(status, **kwargs)

    def generate_auth(
        self,
        response: SIPResponse,
        *,
        is_proxy: bool = False,
        cnonce: str | None = None,
        nc: int | None = None,
    ) -> hdr.AuthorizationHeader | hdr.ProxyAuthorizationHeader:
        """
        Generate an authorization header for the given response.

        The response should contain a WWW-Authenticate header, and the method will
        return an Authorization header.
        In proxy mode, the response is expected to contain a Proxy-Authenticate header,
        and the method will return a Proxy-Authorization header.

        :param response: the response to generate the header for.
        :param is_proxy: whether the response is for a proxy.
        :param cnonce: the cnonce to use for computing the hashed response, if any.
        :param nc: the nc value to use for computing the hashed response, if any.
        :return: the generated authorization header.
        """
        authenticate_hdr_name: str = (
            "WWW-Authenticate" if not is_proxy else "Proxy-Authenticate"
        )
        authenticate_hdr: (
            hdr.WWWAuthenticateHeader | hdr.ProxyAuthenticateHeader | None
        ) = response.headers.get(authenticate_hdr_name)
        if authenticate_hdr is None:
            raise SIPBadResponse(f"No {authenticate_hdr_name} header in response")
        realm = authenticate_hdr.realm
        if not realm:
            raise SIPBadResponse(f"No realm in {authenticate_hdr_name} header")
        nonce = authenticate_hdr.nonce
        if not nonce:
            raise SIPBadResponse(f"No nonce in {authenticate_hdr_name} header")
        if "CSeq" not in response.headers:
            raise SIPBadResponse("No CSeq header in response")
        method = response.headers["CSeq"].method
        qop = authenticate_hdr.qop
        if qop and qop not in {"auth", "auth-int"}:
            raise NotImplementedError(
                f"Unsupported qop={qop} in {authenticate_hdr_name} header"
            )
        if nc is None and (qop or cnonce is not None):
            raise ValueError("cnonce and nc must be set together")
        nc_str = f"{nc:08}" if isinstance(nc, int) else str(nc)

        def digest(s: str) -> str:
            return hashlib.md5(s.encode("utf-8")).hexdigest()

        ha1 = digest(f"{self._login}:{realm}:{self._password}")
        ha2 = digest(f"{method}:{self._auth_uri}")
        if qop:  # assumes already validated
            qop = "auth"  # TODO: add auth-int support
            if not cnonce:
                cnonce = random.getrandbits(32).to_bytes(4, "big").hex()
            auth_response = digest(f"{ha1}:{nonce}:{nc_str}:{cnonce}:{qop}:{ha2}")
        else:
            cnonce = None
            auth_response = digest(f"{ha1}:{nonce}:{ha2}")

        hdr_cls = hdr.ProxyAuthorizationHeader if is_proxy else hdr.AuthorizationHeader
        return hdr_cls(
            username=self._login,
            realm=realm,
            nonce=nonce,
            qop=qop,
            nc=nc_str,
            cnonce=cnonce,
            uri=str(self._auth_uri),
            response=auth_response,
            algorithm="MD5",
        )

    def generate_capabilities_headers(self) -> list[hdr.Header]:
        """Generate the headers for the OPTIONS request."""
        return [
            hdr.AllowHeader(list(self.allowed_methods)),
            hdr.AcceptHeader(list(self.supported_content_types)),
            # hdr.SupportedHeader([]),  # TODO: supported extensions
            # TODO: allow-events?
        ]

    def generate_sdp_session(
        self,
        session_id: int,
        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]],
        media_flow: rtp.MediaFlowType,
        remote_address: tuple[str, int] | None = None,
    ) -> sdp.SDPSession:
        """
        Generate an SDP session for the client with the given RTP parameters.

        :param session_id: the session ID to use.
        :param rtp_profiles_by_port: a mapping of RTP port to RTP profiles to use.
        :param media_flow: the media flow type to use.
        :param remote_address: the remote address to use for determining the external IP.
        :return: the generated SDP session.
        """
        if remote_address is None:
            remote_address = self.server_addr

        own_external_ip: str = get_external_ip_for_dest(remote_address[0])

        medias: list[sdp.SDPMedia] = []
        for port, profiles in rtp_profiles_by_port.items():
            media_type_set: set[rtp.RTPMediaType] = {p.media_type for p in profiles}
            if len(media_type_set) != 1:
                raise ValueError("All RTP profiles must have the same media type")
            media_type: rtp.RTPMediaType = media_type_set.pop()
            if media_type != rtp.RTPMediaType.AUDIO:
                raise SIPUnsupportedError(f"Unsupported media type: {media_type}")

            media_attributes: list[sdp.SDPMediaAttribute] = [
                sdp.PTimeAttribute(20),
                sdp.MaxPTimeAttribute(150),
                sdp.get_media_flow_attribute(media_flow),
            ]
            for profile in profiles:
                # noinspection PyTypeChecker
                media_attributes.append(
                    sdp.RTPMapAttribute(
                        payload_type=int(profile.payload_type),
                        encoding_name=str(profile.encoding_name),
                        clock_rate=int(profile.clock_rate),
                        encoding_parameters=None
                        if profile.channels is None
                        else str(profile.channels),
                    )
                )
                if (
                    rtp.RTPMediaProfiles.match(payload_type=profile.encoding_name)
                    == rtp.RTPMediaProfiles.TELEPHONE_EVENT
                ):
                    # noinspection PyTypeChecker
                    media_attributes.append(
                        sdp.FMTPAttribute(int(profile.payload_type), "0-15")
                    )

            # noinspection PyTypeChecker
            medias.append(
                sdp.SDPMedia(
                    media=sdp.SDPMediaMedia(
                        media_type.value,
                        port,
                        None,
                        "RTP/AVP",
                        [int(p.payload_type) for p in profiles],
                    ),
                    attributes=[
                        sdp.SDPMediaAttributeField(a) for a in media_attributes
                    ],
                )
            )

        return sdp.SDPSession(
            version=sdp.SDPSessionVersion("0"),
            origin=sdp.SDPSessionOrigin(
                self._username,
                str(session_id),
                str(session_id + 1),
                "IN",
                "IP4",
                own_external_ip,
            ),
            name=sdp.SDPSessionName(f"{sibilant.__title__} {sibilant.__version__}"),
            connection=sdp.SDPSessionConnection("IN", "IP4", own_external_ip),
            time=[sdp.SDPTime(sdp.SDPTimeTime(0, 0))],
            media=medias,
        )
