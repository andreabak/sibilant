from __future__ import annotations

import asyncio
import base64
import contextlib
import enum
import hashlib
import logging
import random
import socket
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import replace as dataclass_replace
from functools import partial
from typing import (
    Optional,
    Tuple,
    MutableMapping,
    Union,
    Sequence,
    Awaitable,
    TypeVar,
    Mapping,
    List,
    Set,
    Callable,
    Any,
    Coroutine,
    Collection,
)

from ..helpers import SupportsStr

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

import sibilant
from .. import sdp, rtp
from ..constants import DEFAULT_SIP_PORT
from ..exceptions import (
    SIPParseError,
    SIPUnsupportedVersion,
    SIPTimeout,
    SIPBadResponse,
    SIPAuthenticationError,
    SIPBadRequest,
    SIPException,
    SIPUnsupportedError,
)
from ..structures import SIPURI, SIPAddress
from . import headers as hdr
from .messages import SIPResponse, SIPRequest, SIPMessage, SIPMethod, SIPStatus


_logger = logging.getLogger(__name__)


def generate_via_branch() -> str:
    """Generate a unique branch identifier for Via headers."""
    branch: str = base64.b64encode(uuid.uuid4().bytes, altchars=b"00").decode()[:22]
    return f"z9hG4bK-{branch[:6]}-{branch[6:15]}-{branch[15:]}"


def generate_tag() -> str:
    """Generate a tag for From/To headers for SIP sessions."""
    return base64.b32encode(random.getrandbits(36).to_bytes(5, "big")).decode()


def generate_call_id(local_host: str, local_port: Optional[int] = None) -> str:
    """Generate a unique call ID for SIP sessions, using UUID and local host name."""
    addr_str = f"{local_host}:{local_port}" if local_port else local_host
    return f"{uuid.uuid4()}@{addr_str}"


def generate_cseq() -> int:
    """Generate a random CSeq number for SIP requests."""
    return random.randrange(0, 2**31)


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


async def call_later(delay: float, coro: Coroutine[_rT]) -> _rT:
    """Call a coroutine after a delay."""
    try:
        await asyncio.sleep(delay)
    except asyncio.CancelledError:
        coro.close()
    else:
        return await coro


async def cancel_task_silent(task: asyncio.Task) -> None:
    """
    Cancel a task, awaiting it, and ignore the raised :class:`asyncio.CancelledError`.
    """
    try:
        task.cancel()
        await task
    except asyncio.CancelledError:
        pass


# TODO: move this to a separate module, probably rename
class AbstractVoIPPhone(ABC):
    @property
    @abstractmethod
    def can_accept_calls(self) -> bool:
        """Whether this phone can accept calls."""

    @abstractmethod
    async def answer(self, call: SIPCall) -> bool:
        """
        Answer an incoming call. Returns True if the call was answered.
        If the call was cancelled by the other party, will internally raise a
        :class:`asyncio.CancelledError`, that the phone should catch to stop ringing.
        """

    @abstractmethod
    def get_rtp_profiles_by_port(self) -> Mapping[int, Sequence[rtp.RTPMediaProfiles]]:
        """Get the RTP profiles and ports that this phone will use for calls."""

    @abstractmethod
    def get_default_media_flow(self) -> rtp.MediaFlowType:
        """Get the default media flow for this phone."""

    # TODO: check if we want async here
    @abstractmethod
    def establish_call(self, call: SIPCall) -> None:
        """A call is established. Start handling streams."""

    # TODO: check if we want async here
    @abstractmethod
    def terminate_call(self, call: SIPCall) -> None:
        """Terminate an established call. Stop handling streams."""


class SIPDialogue(ABC):
    """
    Implements a SIP dialogue, a single SIP session between two endpoints.
    """

    def __init__(
        self,
        client: SIPClient,
        uri: SIPURI,
        to_address: SIPAddress,
        from_address: SIPAddress,
        to_tag: Optional[str] = None,
        from_tag: Optional[str] = None,
        call_id: Optional[str] = None,
        cseq: Optional[int] = None,
        response_timeout: Optional[float] = None,
    ):
        self._client: SIPClient = client

        self._uri: SIPURI = uri

        self._to_address: SIPAddress = to_address
        self._to_tag: Optional[str] = to_tag

        self._from_address: SIPAddress = from_address
        self._from_tag: Optional[str] = from_tag

        self._call_id: str = call_id or generate_call_id(*self._client.local_addr)
        self._cseq: int = cseq if cseq is not None else generate_cseq()

        self._recv_queue: asyncio.Queue[SIPMessage] = asyncio.Queue()
        self._expecting_msg: bool = False
        if response_timeout is None:
            response_timeout = self._client.default_response_timeout
        self._response_timeout: float = response_timeout

        self._closed: bool = False

        self._client.track_dialogue(self)

    @property
    def client(self) -> SIPClient:
        """The client associated to dialogue."""
        return self._client

    @property
    def call_id(self) -> str:
        """The Call-ID for this dialogue."""
        return self._call_id

    @property
    def cseq(self) -> int:
        """The CSeq for this dialogue."""
        return self._cseq

    @property
    def closed(self) -> bool:
        """
        Whether this dialogue is closed / has ended.
        The client should not be tracking it anymore,
        effectively rejecting any new messages related to it.
        """
        return self._closed

    def _close(self) -> None:
        """Close this dialogue."""
        self._client.untrack_dialogue(self)
        self._closed = True

    async def receive_message(self, message: SIPMessage) -> None:
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
            await self._handle_message(message)

    @abstractmethod
    async def _handle_message(self, message: SIPMessage) -> None:
        """Handle an incoming SIP message."""

    async def _wait_for_message(
        self,
        timeout: Optional[float] = None,
        discard_trying: bool = True,
        more_discard_statuses: Collection[SIPStatus] = (),
    ) -> SIPMessage:
        """
        Wait for the next message to arrive in the queue.

        :param timeout: The timeout for the wait. None for default, -1 for no timeout.
        :param discard_trying: Whether to discard TRYING responses.
        :return: The next message.
        :raises asyncio.TimeoutError: If the timeout is reached.
        """
        if timeout is None:
            timeout = self._response_timeout
        msg_getter: Callable[[], Awaitable[SIPMessage]] = self._recv_queue.get
        if discard_trying or more_discard_statuses:
            statuses: Collection[SIPStatus] = more_discard_statuses
            statuses += (SIPStatus.TRYING,) if discard_trying else ()
            msg_getter = partial(discard_statuses, msg_getter, statuses=statuses)
        if timeout != -1:
            msg_getter = partial(asyncio.wait_for, msg_getter(), timeout)
        self._expecting_msg = True
        try:
            return await msg_getter()
        finally:
            self._expecting_msg = False

    def _follow_cseq(self, request: SIPRequest) -> SIPRequest:
        """Set the internal CSeq to the one in the request and increment it."""
        cseq: hdr.CSeqHeader = request.headers.get("CSeq")
        if cseq is None:
            raise SIPBadRequest("Missing CSeq header")
        self._cseq = cseq.sequence + 1
        return request

    async def _send_message(self, message: SIPMessage) -> None:
        """Send a SIP message."""
        self._client.send_msg(message)  # TODO: make async and await?

    async def _send_request(self, request: SIPRequest) -> None:
        """Send a request and increment the internal CSeq."""
        await self._send_message(request)
        self._follow_cseq(request)

    def _generate_request(self, method: SIPMethod, **kwargs) -> SIPRequest:
        from_address: SIPAddress = kwargs.pop("from_address", self._from_address)
        from_tag: Optional[str] = kwargs.pop("from_tag", self._from_tag)
        to_address: SIPAddress = kwargs.pop("to_address", self._to_address)
        to_tag: Optional[str] = kwargs.pop("to_tag", self._to_tag)
        call_id: str = kwargs.pop("call_id", self._call_id)
        cseq: int = kwargs.pop("cseq", self._cseq)
        uri: SIPURI = kwargs.pop("uri", self._uri)

        return self._client.generate_request(
            method,
            from_address=from_address,
            from_tag=from_tag,
            to_address=to_address,
            to_tag=to_tag,
            call_id=call_id,
            cseq=cseq,
            uri=uri,
            **kwargs,
        )

    def _generate_response_from_request(
        self, request: SIPRequest, status: SIPStatus, **kwargs
    ) -> SIPResponse:
        return self._client.generate_response_from_request(request, status, **kwargs)


class SIPRegistration(SIPDialogue):
    def __init__(self, client: SIPClient):
        super().__init__(
            client,
            client.server_uri,
            from_address=client.contact_address,
            to_address=client.contact_address,
            from_tag=generate_tag(),
        )

        self._keep_alive_task: Optional[asyncio.Task] = None
        self._registered: bool = False

    @property
    def registered(self) -> bool:
        return self._registered

    async def _handle_message(self, message: SIPMessage) -> None:
        raise SIPException("Received unexpected message in registration flow")

    def _register_request(
        self,
        authorization: Optional[hdr.AuthorizationHeader] = None,
        deregister: bool = False,
    ) -> SIPRequest:
        extra_headers = [
            hdr.ExpiresHeader(0 if deregister else self._client.register_expires),
        ]
        if authorization is not None:
            extra_headers.append(authorization)
        # TODO: Allow
        # TODO: allow-events ??

        return self._generate_request(SIPMethod.REGISTER, extra_headers=extra_headers)

    async def _register_transaction(self, deregister: bool = False) -> None:
        authorization: Optional[hdr.AuthorizationHeader] = None

        response: Optional[SIPMessage] = None
        attempts: int = self._client.register_attempts
        while attempts > 0:
            request: SIPRequest = self._register_request(authorization, deregister)
            await self._send_request(request)
            try:
                response = await self._wait_for_message(self._client.register_timeout)
            except asyncio.TimeoutError:
                raise SIPTimeout("Timed out waiting for REGISTER response")

            if not isinstance(response, SIPResponse):
                raise SIPBadResponse("Unexpected response for REGISTER: {response!r}")

            if response.status == SIPStatus.UNAUTHORIZED:
                nonce_changed = "nonce" in response.status.reason
                if authorization is not None and not nonce_changed:
                    raise SIPAuthenticationError(
                        "Failed to authenticate with given credentials"
                    )

                authorization = self._client.generate_auth(response)

            elif response.status == SIPStatus.PROXY_AUTHENTICATION_REQUIRED:
                raise SIPUnsupportedError("Proxy authentication not implemented")

            elif response.status == SIPStatus.BAD_REQUEST:
                raise SIPBadRequest(
                    "REGISTER failed: server replied with 400 Bad Request"
                )

            elif (
                400 <= int(response.status) <= 499 or 600 <= int(response.status) <= 699
            ):
                raise SIPException(f"REGISTER failed: {response!r}")

            elif response.status == SIPStatus.OK:
                return  # all good, exit flow

            attempts -= 1

        raise SIPException(
            f"Failed to REGISTER with server "
            f"(after {self._client.register_attempts - attempts} attempts)"
            + (f"\nLast response: {response!r}" if response is not None else "")
        )

    async def _schedule_keep_alive(self):
        await self._cancel_keep_alive()
        keep_alive_interval: float = max(
            0.0, self._client.register_expires - self._client.register_timeout
        )
        self._keep_alive_task = asyncio.create_task(
            call_later(keep_alive_interval, self.register()),
            name=f"{self.__class__.__name__}.keep_alive-{id(self._client)} task",
        )
        self._client._pending_futures.append(self._keep_alive_task)

    async def _cancel_keep_alive(self):
        if self._keep_alive_task is not None:
            await cancel_task_silent(self._keep_alive_task)
            self._keep_alive_task = None

    async def register(self):
        try:
            await self._register_transaction()
        except Exception:
            self._registered = False
            self._close()
            raise
        self._registered = True
        await self._schedule_keep_alive()

    async def deregister(self):
        await self._cancel_keep_alive()
        try:
            await self._register_transaction(deregister=True)
        finally:
            self._registered = False
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


class SIPCall(SIPDialogue):
    def __init__(
        self,
        client: SIPClient,
        to: Union[hdr.ToHeader, SIPAddress],
        from_header: Optional[hdr.FromHeader] = None,
        call_id: Optional[str] = None,
        cseq: Optional[int] = None,
    ):
        to_address: SIPAddress
        to_tag: Optional[str]
        if isinstance(to, hdr.ToHeader):
            to_address, to_tag = to.address, to.tag
        elif isinstance(to, SIPAddress):
            to_address, to_tag = to, None
        else:
            raise TypeError(f"Invalid type for 'to': {to!r}")

        from_address: SIPAddress
        from_tag: Optional[str]
        if from_header is None:
            from_address, from_tag = client.contact_address, None
        elif isinstance(from_header, hdr.FromHeader):
            from_address, from_tag = from_header.address, from_header.tag
        else:
            raise TypeError(f"Invalid type for 'from_header': {from_header!r}")
        if from_tag is None:
            from_tag = generate_tag()

        # FIXME: better determine if we are the caller or callee / From or To, and generate the tag accordingly

        uri: SIPURI = dataclass_replace(
            to_address.uri, password=None, params={}, headers={}
        )

        super().__init__(
            client,
            uri,
            to_address=to_address,
            to_tag=to_tag,
            from_address=from_address,
            from_tag=from_tag,
            call_id=call_id,
            cseq=cseq,
        )

        self._state: CallState = CallState.INIT
        self._failure_exc: Optional[Exception] = None

    @classmethod
    def from_invite(cls, client: SIPClient, invite: SIPRequest) -> Self:
        """Create a new SIPCall instance from an incoming INVITE request."""
        return cls(
            client=client,
            to=invite.headers["To"],
            from_header=invite.headers["From"],
            call_id=invite.headers["Call-ID"].value,
            cseq=invite.headers["CSeq"].sequence,
        )

    @property
    def state(self) -> CallState:
        return self._state

    @contextlib.asynccontextmanager
    async def _handle_errors(self):
        try:
            yield
        # TODO: better handle other exceptions, like bad request, and send appropriate response
        except Exception as exc:
            self._state = CallState.FAILED
            self._failure_exc = exc
            self._close()
            raise

    async def invite(self) -> None:
        async with self._handle_errors():
            await self._invite_send_transaction()

    async def _handle_message(self, message: SIPMessage) -> None:
        """Handle an incoming SIP message, and start the appropriate flow"""
        if isinstance(message, SIPRequest):
            if message.method == SIPMethod.INVITE:
                async with self._handle_errors():
                    return await self._invite_recv_transaction(message)
            elif message.method == SIPMethod.BYE:
                return await self._bye_recv_transaction(message)

        # We shouldn't need to handle any response here, as they're caught by transactions

        raise SIPBadRequest(f"Unexpected request: {message!r}")

    async def _invite_recv_transaction(self, invite: SIPRequest) -> None:
        """Handle an incoming INVITE request, wait for client answer and send 200 OK."""
        if not isinstance(invite, SIPRequest) or invite.method != SIPMethod.INVITE:
            raise TypeError(f"Invalid type for INVITE request: {invite!r}")

        if self._state != CallState.INIT:
            raise SIPException("Cannot handle incoming INVITE in current state")

        self._follow_cseq(invite)

        self._state = CallState.INVITE

        # TODO: check if invite contains SDP if we have at least 1 supported media type

        if not self._client.phone.can_accept_calls:
            await self._reply_busy(invite)
            self._close()
            return

        await self._reply_ringing(invite)

        # we now wait for the phone to answer, or for a CANCEL request, whatever comes first
        incoming_request = asyncio.create_task(
            self._wait_for_message(),
            name=f"{self.__class__.__name__}._wait_for_message-{self._call_id} task",
        )
        phone_answer = asyncio.create_task(
            self._client.phone.answer(self),
            name=f"{self.__class__.__name__}._client.phone.answer-{self._call_id} task",
        )
        done, pending = await asyncio.wait(
            [incoming_request, phone_answer], return_when=asyncio.FIRST_COMPLETED
        )
        if incoming_request in done:
            await cancel_task_silent(phone_answer)

            request: SIPMessage = incoming_request.result()
            if isinstance(request, SIPRequest) and request.method in (
                SIPMethod.CANCEL,
                SIPMethod.BYE,
            ):
                self._follow_cseq(request)
                await self._reply_terminated(request)
                self._close()
                return

            raise SIPBadResponse(
                f"Unexpected message while waiting for answer: {request!r}"
            )

        elif phone_answer in done:
            await cancel_task_silent(incoming_request)

            answered: bool = phone_answer.result()
            if not answered:
                await self._reply_busy(invite)
                return

            rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]]
            rtp_profiles_by_port = self._client.phone.get_rtp_profiles_by_port()
            media_flow: rtp.MediaFlowType = self._client.phone.get_default_media_flow()

            await self._reply_answer(invite, rtp_profiles_by_port, media_flow)
            try:
                request: SIPMessage = await self._wait_for_message()
                if isinstance(request, SIPRequest) and request.method == SIPMethod.ACK:
                    self._follow_cseq(request)
                    self._state = CallState.ESTABLISHED
                    self._client.phone.establish_call(self)
                    return
            except asyncio.TimeoutError as e:
                raise SIPTimeout("ACK never received after 200 OK") from e

            raise SIPBadResponse(
                f"Unexpected message while waiting for ACK: {request!r}"
            )

        raise RuntimeError("INVITE never answered by phone, nor CANCELLED by caller")

    async def _invite_send_transaction(self):
        """Start an outgoing INVITE request, wait for 200 OK."""
        if self._state != CallState.INIT:
            raise SIPException("Cannot start INVITE flow in current state")

        # TODO: sanity check phone can make calls?

        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]]
        rtp_profiles_by_port = self._client.phone.get_rtp_profiles_by_port()
        media_flow: rtp.MediaFlowType = self._client.phone.get_default_media_flow()

        invite: SIPRequest = await self._send_invite(rtp_profiles_by_port, media_flow)

        # TODO: have a way for client to terminate call attempt while we're waiting (catch raise? idk)
        response: SIPMessage
        while (
            isinstance((response := await self._wait_for_message()), SIPResponse)
            and response.status == SIPStatus.RINGING
        ):
            self._state = CallState.RINGING

        if isinstance(response, SIPResponse) and response.status == SIPStatus.OK:
            self._state = CallState.ANSWERING

            await self._send_ack(invite)

            self._client.phone.establish_call(self)
            return

        # TODO: handle other failure modes

        raise SIPBadResponse(f"Unexpected response to INVITE: {response!r}")

    async def _bye_recv_transaction(self, bye: SIPRequest) -> None:
        """Handle an incoming BYE request, and send 200 OK."""
        if not isinstance(bye, SIPRequest) or bye.method != SIPMethod.BYE:
            raise TypeError(f"Invalid type for BYE request: {bye!r}")

        if self._state not in (CallState.ESTABLISHED, CallState.ANSWERING):
            raise SIPException("Cannot handle incoming BYE in current state")

        _logger.debug(f"Received BYE request, terminating call: {bye!r}")

        self._follow_cseq(bye)

        self._state = CallState.HANGING_UP
        self._client.phone.terminate_call(self)

        await self._reply_ok(bye)

        self._state = CallState.HUNG_UP
        self._close()

    async def _bye_send_transaction(self) -> None:
        """Start an outgoing BYE request, wait for 200 OK (or silent timeout)."""
        if self._state != CallState.ESTABLISHED:
            raise SIPException("Cannot start BYE flow in current state")

        await self._send_bye()

        self._state = CallState.HANGING_UP
        self._client.phone.terminate_call(self)

        try:
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
            session_id=hash(self._call_id),
            rtp_profiles_by_port=rtp_profiles_by_port,
            media_flow=media_flow,
        )

    def _invite_request(
        self,
        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]],
        media_flow: rtp.MediaFlowType,
    ) -> SIPRequest:
        """Create an INVITE request."""
        return self._generate_request(
            SIPMethod.INVITE,
            body=self._generate_sdp_session(rtp_profiles_by_port, media_flow),
        )

    def _ack_request(self, invite: SIPRequest) -> SIPRequest:
        """Create an ACK request."""
        invite_cseq: hdr.CSeqHeader = invite.headers.get("CSeq")
        if invite_cseq is None:
            raise RuntimeError("INVITE request has no CSeq header")
        return self._generate_request(
            SIPMethod.ACK, cseq=invite_cseq.sequence, cseq_method=invite_cseq.method
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
    ) -> SIPRequest:
        if self._state != CallState.INIT:
            raise RuntimeError(f"Cannot send INVITE in state {self._state}")

        invite_request: SIPRequest = self._invite_request(
            rtp_profiles_by_port, media_flow
        )
        await self._send_message(invite_request)
        self._state = CallState.INVITE
        return invite_request

    async def _send_ack(self, invite: SIPRequest) -> SIPRequest:
        if self._state != CallState.ANSWERING:
            raise RuntimeError(f"Cannot send ACK in state {self._state}")

        ack_request: SIPRequest = self._ack_request(invite)
        await self._send_message(ack_request)
        self._state = CallState.ESTABLISHED
        return ack_request

    async def _send_bye(self) -> SIPRequest:
        if self._state not in (CallState.ESTABLISHED, CallState.INVITE):
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
        await self._send_message(ok_response)
        return ok_response

    async def _reply_ok(self, request: SIPRequest) -> SIPResponse:
        ok_response: SIPResponse = self._ok_response(request)
        await self._send_message(ok_response)
        return ok_response

    async def _reply_busy(self, request: SIPRequest) -> SIPResponse:
        if self._state in (CallState.INIT, CallState.CANCELLED, CallState.FAILED):
            raise RuntimeError(f"Cannot reply 486 Busy Here in state {self._state}")

        self._state = CallState.CANCELLED
        busy_response: SIPResponse = self._busy_response(request)
        await self._send_message(busy_response)
        return busy_response

    async def _reply_terminated(self, request: SIPRequest) -> SIPResponse:
        if self._state in (CallState.INIT, CallState.CANCELLED, CallState.FAILED):
            raise RuntimeError(
                f"Cannot reply 487 Request Terminated in state {self._state}"
            )

        self._state = CallState.CANCELLED
        terminated_response: SIPResponse = self._terminated_response(request)
        await self._send_message(terminated_response)
        return terminated_response

    # TODO: invite method to start a call, start transaction
    # TODO: bye method to end a call, start transaction

    # TODO: make sure `to` has a tag after we get 200 OK / INVITE


class SIPClient:
    """Implements a SIP client that communicates over UDP."""

    def __init__(
        self,
        phone: AbstractVoIPPhone,
        username: str,
        password: str,
        server_host: str,
        server_port: int = DEFAULT_SIP_PORT,
        display_name: Optional[str] = None,
        login: Optional[str] = None,
        domain: Optional[str] = None,
        local_host: str = "0.0.0.0",
        local_port: int = 0,
        register_attempts: int = 5,
        register_timeout: float = 30.0,
        register_expires: int = 3600,
        default_response_timeout: float = 32.0,
        max_forwards: int = 70,
    ):
        self._phone: AbstractVoIPPhone = phone

        self._username: str = username
        self._login: str = (login is not None and login) or username
        self._password: str = password
        self._display_name: Optional[str] = display_name
        self._domain: str = (domain is not None and domain) or server_host

        self._server_addr: Tuple[str, int] = (server_host, server_port)
        self._local_addr: Tuple[str, int] = (local_host, local_port)

        self._default_response_timeout: float = default_response_timeout
        self._max_forwards: int = max_forwards

        self._register_attempts: int = register_attempts
        self._register_timeout: float = register_timeout
        self._register_expires: int = register_expires
        self._register_dialogue: Optional[SIPRegistration] = None

        self._dialogues: MutableMapping[str, SIPDialogue] = {}
        """Map of call IDs to SIP sessions."""

        self._event_loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)
        self._event_loop.set_exception_handler(self._handle_loop_exception)
        self._event_loop_thread: threading.Thread = threading.Thread(
            target=self._run_event_loop,
            name=f"{self.__class__.__name__}._run_event_loop-{id(self)}",
        )
        self._pending_futures: List[asyncio.Future] = []

        # FIXME: wouldn't it be easier to use async to handle dialogues / callbacks?
        #        we could keep threads for the UDP socket and use a queue to pass msgs
        #        to the async loop, and use async for the callbacks, or run_coroutine_threadsafe

        self._socket: Optional[socket.socket] = None
        self._socket_lock: threading.Lock = threading.Lock()

        self._registered: bool = False
        self._recv_thread: Optional[threading.Thread] = None

        self._closed: bool = True
        self._closing_event: threading.Event = threading.Event()
        self._closing_event.clear()

    @property
    def phone(self) -> AbstractVoIPPhone:
        return self._phone

    @property
    def server_addr(self) -> Tuple[str, int]:
        return self._server_addr

    @property
    def server_host(self) -> str:
        return self._server_addr[0]

    @property
    def server_port(self) -> int:
        return self._server_addr[1]

    @property
    def local_addr(self) -> Tuple[str, int]:
        return self._local_addr

    @property
    def local_host(self) -> str:
        return self._local_addr[0]

    @property
    def local_port(self) -> int:
        return self._local_addr[1]

    @property
    def server_uri(self):
        return SIPURI(
            host=self._domain,
            port=self.server_port if self.server_port != DEFAULT_SIP_PORT else None,
        )

    @property
    def _auth_uri(self):
        return dataclass_replace(self.server_uri, params={"transport": "UDP"})

    @property
    def contact_uri(self) -> SIPURI:
        """Return the contact URI for this client."""
        return dataclass_replace(self.server_uri, user=self._username)

    @property
    def contact_address(self) -> SIPAddress:
        return SIPAddress(display_name=self._display_name, uri=self.contact_uri)

    @property
    def contact(self) -> hdr.Contact:
        # TODO: should Contact: always include stuff like transport etc?
        return hdr.Contact(
            dataclass_replace(
                self.contact_address,
                uri=dataclass_replace(self.contact_uri, params={"transport": "UDP"}),
            ),
        )

    @property
    def register_attempts(self) -> int:
        return self._register_attempts

    @property
    def register_timeout(self) -> float:
        return self._register_timeout

    @property
    def register_expires(self) -> int:
        return self._register_expires

    @property
    def registered(self) -> bool:
        return bool(self._register_dialogue and self._register_dialogue.registered)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def default_response_timeout(self) -> float:
        return self._default_response_timeout

    @property
    def calls(self) -> Mapping[str, SIPDialogue]:
        return {
            call_id: dialogue
            for call_id, dialogue in self._dialogues.items()
            if isinstance(dialogue, SIPCall)
        }

    def track_dialogue(self, dialogue: SIPDialogue):
        assert dialogue.call_id not in self._dialogues
        assert dialogue.client is self
        self._dialogues[dialogue.call_id] = dialogue

    def untrack_dialogue(
        self, dialogue: Optional[SIPDialogue], call_id: Optional[str] = None
    ):
        if dialogue is None and call_id is None:
            raise ValueError("Either 'dialogue' or 'call_id' must be specified")
        if dialogue is not None and call_id is not None and dialogue.call_id != call_id:
            raise ValueError("Call ID does not match dialogue")
        if call_id is None:
            assert dialogue is not None
            call_id = dialogue.call_id
        del self._dialogues[call_id]

    def start(self):
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

    def stop(self):
        if self.registered:
            self._deregister()

        self._closing_event.set()

        # TODO: graceful shutdown of active dialogs (send bye etc)
        if threading.current_thread() is not self._event_loop_thread:
            if self._event_loop_thread.is_alive():
                self._event_loop_thread.join()

        if self._recv_thread is not None and self._recv_thread.is_alive():
            self._recv_thread.join()
        if self._socket is not None:
            self._socket.close()

        self._socket = None
        self._recv_thread = None
        self._closed = True
        self._closing_event.clear()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    # FIXME: we want errors raised in the event loop thread to stop the main loop
    def _run_event_loop(self):
        asyncio.set_event_loop(self._event_loop)
        try:
            self._event_loop.run_until_complete(self._async_monitor())
        finally:
            self._event_loop.stop()
            self._event_loop.close()
            if not self._closing_event.is_set():
                self.stop()

    async def _async_monitor(self):
        """
        Async loop that monitors pending tasks for any exceptions and makes sure
        everything is cleaned up when stopping.
        """
        terminate_asap: bool = False
        while (
            not (self._closing_event.is_set() or terminate_asap)
            or self._pending_futures
        ):
            fut: asyncio.Future
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

                elif self._closing_event.is_set() or terminate_asap:
                    fut.cancel()

            if (
                not (self._closing_event.is_set() or terminate_asap)
                and self._register_dialogue is not None
                and self._register_dialogue.closed
            ):
                _logger.error("Registration or keep-alive failed, stopping client")
                terminate_asap = True

            await asyncio.sleep(1e-2)

        await self._event_loop.shutdown_asyncgens()

    def _handle_loop_exception(
        self, loop: asyncio.AbstractEventLoop, context: Mapping[str, Any]
    ):
        """Handle exceptions in the event loop by logging as error."""
        message: str = (
            f"Exception in event loop: {context['message']}\nContext: {context!r}"
        )
        exception = context.get("exception")
        # FIXME: this does not work, will stop the async loop thread at most
        # if exception is not None and not isinstance(exception, (asyncio.CancelledError, SIPException)):
        #     raise exception
        if _logger.getEffectiveLevel() <= logging.DEBUG:
            _logger.exception(message, exc_info=exception)
        else:
            _logger.error(message)

    def _schedule(self, coro) -> asyncio.Future:
        future = asyncio.run_coroutine_threadsafe(coro, self._event_loop)
        self._pending_futures.append(future)
        return future

    def _recv_msg(self, timeout: Optional[float] = None) -> SIPMessage:
        start_time: float = time.monotonic()
        while not timeout or (time.monotonic() - start_time < timeout):
            with self._socket_lock:
                self._socket.setblocking(False)
                try:
                    data, addr = self._socket.recvfrom(8192)
                    # TODO: assert addr == self._server_addr?
                except (socket.timeout, BlockingIOError):
                    pass
                else:
                    return SIPMessage.parse(data)

            if not timeout:
                break

        raise SIPTimeout("Timed out waiting for SIP message")

    def _recv_loop(self):
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

    async def _handle_message(self, message: SIPMessage):
        call_id_hdr: Optional[hdr.CallIDHeader] = message.headers.get("Call-ID")
        if call_id_hdr is None:
            _logger.warning(f"Discarding SIP message without Call-ID: {message!r}")
            return

        call_id: str = call_id_hdr.value

        if call_id in self._dialogues:
            await self._dialogues[call_id].receive_message(message)
        elif isinstance(message, SIPRequest) and message.method == SIPMethod.INVITE:
            await self._handle_invite(message)
        else:
            _logger.warning(
                f"Discarding SIP message for untracked call ID: {message!r}"
            )
            return

    # TODO: this must be a coro
    def send_msg(self, message: SIPMessage):
        message_raw: bytes = message.serialize()
        with self._socket_lock:
            self._socket.setblocking(True)
            self._socket.sendto(message_raw, self._server_addr)
            self._socket.setblocking(False)

    def _register(self):
        if self._register_dialogue is not None:
            raise RuntimeError("Registration already active")

        self._register_dialogue: Optional[SIPRegistration] = SIPRegistration(self)

        self._schedule(self._register_dialogue.register()).result()  # wait
        _logger.debug(f"Registered with {self.server_host} with user {self._username}")

    def _deregister(self):
        if self._register_dialogue is None:
            raise RuntimeError("Registration not active")

        async def _deregister():
            await self._register_dialogue.deregister()
            self._register_dialogue = None

        try:
            self._schedule(_deregister()).result()
        except SIPException as exc:
            _logger.warning(f"Error while deregistering: {exc}")

    # TODO: should this be async? or should it be blocking?
    def invite(self, contact: Union[SIPAddress, SIPURI, str]) -> SIPCall:
        if isinstance(contact, str):
            if "@" not in contact:
                contact = SIPURI(
                    host=self.server_host, port=self.server_port, user=contact
                )
            else:
                contact = SIPAddress.parse(contact)
        elif isinstance(contact, SIPURI):
            contact = SIPAddress(uri=contact)
        elif not isinstance(contact, SIPAddress):
            raise TypeError(f"Invalid type for contact {type(contact)}: {contact!r}")

        call = SIPCall(self, to=contact)
        self._schedule(call.invite())
        return call

    # TODO: start invite

    async def _handle_invite(self, message: SIPRequest):
        # TODO: check if the call is for us

        # TODO: sanity check the message has From etc.
        _logger.debug(f"Received INVITE {message.headers['From']}: {message!r}")
        call = SIPCall.from_invite(self, message)
        await call.receive_message(message)

    def prepare_headers(
        self,
        *extra_headers: hdr.Header,
        from_address: SIPAddress,
        to_address: SIPAddress,
        call_id: str,
        cseq: int,
        cseq_method: SIPMethod,
        contact: Optional[hdr.Contact] = None,
        from_tag: Optional[str] = None,
        to_tag: Optional[str] = None,
        allow: Optional[Sequence[str]] = None,
        content_type: Optional[str] = None,
        body: Optional[SupportsStr] = None,
    ) -> hdr.Headers:
        if body and content_type is None:
            if hasattr(body, "mimetype"):
                content_type = body.mimetype
            else:
                raise ValueError("Cannot have body without content type")

        if call_id is None:  # TODO: make this mandatory?
            call_id = generate_call_id(*self.local_addr)

        if contact is None:
            contact = self.contact

        extra_headers = list(extra_headers)
        if allow is not None:
            extra_headers.append(hdr.AllowHeader(list(allow)))

        return hdr.Headers(
            hdr.ViaHeader(
                "SIP/2.0/UDP",
                self.local_host,
                self.local_port,
                branch=generate_via_branch(),
                # TODO: rport? what is it even?
            ),
            hdr.FromHeader(from_address, tag=from_tag),
            hdr.ToHeader(to_address, tag=to_tag),
            hdr.CallIDHeader(call_id),
            hdr.CSeqHeader(cseq, cseq_method),
            hdr.ContactHeader([contact]),
            hdr.MaxForwardsHeader(self._max_forwards),
            hdr.UserAgentHeader(f"{sibilant.__title__}/{sibilant.__version__}"),
            *extra_headers,
            hdr.ContentLengthHeader((body and len(str(body).encode())) or 0),
        )

    def generate_request(
        self,
        method: SIPMethod,
        uri: Optional[SIPURI] = None,
        *,
        from_address: SIPAddress,
        to_address: SIPAddress,
        call_id: str,
        cseq: int,
        cseq_method: Optional[SIPMethod] = None,
        contact: Optional[hdr.Contact] = None,
        from_tag: Optional[str] = None,
        to_tag: Optional[str] = None,
        allow: Optional[Sequence[str]] = None,
        content_type: Optional[str] = None,
        extra_headers: Sequence[hdr.Header] = (),
        body: Optional[SupportsStr] = None,
    ) -> SIPRequest:
        if uri is None:
            uri = self.contact_uri
        if cseq_method is None:
            cseq_method = method

        prepared_headers: hdr.Headers = self.prepare_headers(
            *extra_headers,
            from_address=from_address,
            to_address=to_address,
            call_id=call_id,
            cseq=cseq,
            cseq_method=cseq_method,
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
        )

    def generate_response(
        self,
        status: SIPStatus,
        *,
        from_address: SIPAddress,
        to_address: SIPAddress,
        call_id: str,
        cseq: int,
        cseq_method: SIPMethod,
        contact: Optional[hdr.Contact] = None,
        from_tag: Optional[str] = None,
        to_tag: Optional[str] = None,
        allow: Optional[Sequence[str]] = None,
        content_type: Optional[str] = None,
        extra_headers: Sequence[hdr.Header] = (),
        body: Optional[SupportsStr] = None,
    ) -> SIPResponse:
        prepared_headers: hdr.Headers = self.prepare_headers(
            *extra_headers,
            from_address=from_address,
            to_address=to_address,
            call_id=call_id,
            cseq=cseq,
            cseq_method=cseq_method,
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
        )

    def generate_response_from_request(
        self, request: SIPRequest, status: SIPStatus, **kwargs
    ) -> SIPResponse:
        def set_from_request(kwarg: str, header: str, attr: Optional[str]):
            nonlocal kwargs
            if kwarg not in kwargs:
                req_value = request.headers.get(header)
                if req_value is not None:
                    if attr is not None:
                        req_value = getattr(req_value, attr)
                    kwargs[kwarg] = req_value

        set_from_request("from_address", "From", "address")
        set_from_request("from_tag", "From", "tag")
        set_from_request("to_address", "To", "address")
        set_from_request("to_tag", "To", "tag")
        set_from_request("call_id", "Call-ID", "value")
        set_from_request("cseq", "CSeq", "sequence")
        set_from_request("cseq_method", "CSeq", "method")
        set_from_request("contact", "Contact", None)
        return self.generate_response(status, **kwargs)

    def generate_auth(self, response: SIPResponse) -> Optional[hdr.AuthorizationHeader]:
        auth_header: Optional[hdr.WWWAuthenticateHeader] = response.headers.get(
            "WWW-Authenticate"
        )
        if auth_header is None:
            raise SIPBadResponse("No WWW-Authenticate header in response")
        realm = auth_header.realm
        if not realm:
            raise SIPBadResponse("No realm in WWW-Authenticate header")
        nonce = auth_header.nonce
        if not nonce:
            raise SIPBadResponse("No nonce in WWW-Authenticate header")
        method = response.headers.get("CSeq").method

        def digest(s: str) -> str:
            return hashlib.md5(s.encode("utf-8")).hexdigest()

        ha1 = digest(f"{self._login}:{realm}:{self._password}")
        ha2 = digest(f"{method}:{self._auth_uri}")
        response = digest(f"{ha1}:{nonce}:{ha2}")
        return hdr.AuthorizationHeader(
            username=self._login,
            realm=realm,
            nonce=nonce,
            uri=str(self._auth_uri),
            response=response,
            algorithm="MD5",
        )

    def generate_sdp_session(
        self,
        session_id: int,
        rtp_profiles_by_port: Mapping[int, Sequence[rtp.RTPMediaProfiles]],
        media_flow: rtp.MediaFlowType,
    ) -> sdp.SDPSession:
        medias: List[sdp.SDPMedia] = []
        for port, profiles in rtp_profiles_by_port.items():
            media_type_set: Set[rtp.RTPMediaType] = {p.media_type for p in profiles}
            if len(media_type_set) != 1:
                raise ValueError("All RTP profiles must have the same media type")
            media_type: rtp.RTPMediaType = media_type_set.pop()
            if media_type != rtp.RTPMediaType.AUDIO:
                raise SIPUnsupportedError(f"Unsupported media type: {media_type}")

            media_attributes: List[sdp.SDPMediaAttribute] = []
            for profile in profiles:
                # noinspection PyTypeChecker
                media_attributes.append(
                    sdp.RTPMapAttribute(
                        payload_type=int(profile.payload_type),
                        encoding_name=str(profile.encoding_name),
                        clock_rate=int(profile.clock_rate),
                        encoding_parameters=str(profile.channels),
                    )
                )
                if profile == rtp.RTPMediaProfiles.TELEPHONE_EVENT:
                    # noinspection PyTypeChecker
                    media_attributes.append(
                        sdp.FMTPAttribute(int(profile.payload_type), "0-15")
                    )
                media_attributes.extend(
                    [
                        sdp.PTimeAttribute(20),
                        sdp.MaxPTimeAttribute(150),
                        sdp.get_media_flow_attribute(media_flow),
                    ]
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
                self.local_host,
            ),
            name=sdp.SDPSessionName(f"{sibilant.__title__} {sibilant.__version__}"),
            time=[sdp.SDPTime(sdp.SDPTimeTime(0, 0))],
            media=medias,
        )
