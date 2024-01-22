"""SIP messages and related structures."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from typing_extensions import Self, override

from sibilant.constants import SUPPORTED_SIP_VERSIONS
from sibilant.exceptions import (
    SIPParseError,
    SIPUnsupportedError,
    SIPUnsupportedVersion,
)
from sibilant.helpers import AutoFieldsEnum, ParseableSerializableRaw, SupportsStr
from sibilant.sdp import SDPSession
from sibilant.structures import SIPURI

from .headers import Headers


__all__ = [
    "SIPMethod",
    "SIPStatus",
    "SIPMessage",
    "SIPRequest",
    "SIPResponse",
]


class SIPMethod(AutoFieldsEnum):
    """Enum dataclass for SIP requests methods, along with their description."""

    name: str
    description: str

    @property
    def enum_value(self) -> Any:  # noqa: D102
        return self.name

    REGISTER = (
        "REGISTER",
        "Register the URI listed in the To-header field with a location server "
        "and associates it with the network address given in a Contact header field.",
    )
    INVITE = (
        "INVITE",
        "Initiate a dialog for establishing a call. The request is sent by "
        "a user agent client to a user agent server.",
    )
    ACK = (
        "ACK",
        "Confirm that an entity has received a final response to an INVITE request.",
    )
    BYE = (
        "BYE",
        "Signal termination of a dialog and end a call.",
    )
    CANCEL = (
        "CANCEL",
        "Cancel any pending request.",
    )
    UPDATE = (
        "UPDATE",
        "Modify the state of a session without changing the state of the dialog.",
    )
    REFER = (
        "REFER",
        "Ask recipient to issue a request for the purpose of call transfer.",
    )
    PRACK = (
        "PRACK",
        "Provisional acknowledgement.",
    )
    SUBSCRIBE = (
        "SUBSCRIBE",
        "Initiates a subscription for notification of events from a notifier.",
    )
    NOTIFY = (
        "NOTIFY",
        "Inform a subscriber of notifications of a new event.",
    )
    PUBLISH = (
        "PUBLISH",
        "Publish an event to a notification server.",
    )
    MESSAGE = (
        "MESSAGE",
        "Deliver a text message.",
    )
    INFO = (
        "INFO",
        "Send mid-session information that does not modify the session state.",
    )
    OPTIONS = (
        "OPTIONS",
        "Query the capabilities of an endpoint.",
    )


class SIPStatus(AutoFieldsEnum):
    """Enum dataclass for SIP responses status codes, along with their reason and description."""

    code: int
    reason: str
    description: str | None

    @property
    def enum_value(self) -> Any:  # noqa: D102
        return self.code

    def __int__(self) -> int:
        return self.code

    # 1xx Provisional Responses
    TRYING = (
        100,
        "Trying",
        "Extended search being performed may take a significant time so "
        "a forking proxy must _send a 100 Trying response.",
    )
    RINGING = (
        180,
        "Ringing",
        "Destination user agent received INVITE, and is alerting user of call.",
    )
    CALL_FORWARDED = (
        181,
        "Call is Being Forwarded",
        "Servers can optionally _send this response to indicate a call is being forwarded.",
    )
    QUEUED = (
        182,
        "Queued",
        "Indicates that the destination was temporarily unavailable, "
        "so the server has queued the call until the destination is available. "
        "A server may _send multiple 182 responses to update progress of the queue.",
    )
    SESSION_PROGRESS = (
        183,
        "Session Progress",
        "This response may be used to send extra information for a call "
        "which is still being set up.",
    )
    EARLY_DIALOG_TERMINATED = (
        199,
        "Early Dialog Terminated",
        "Can be used by User Agent Server to indicate to upstream SIP entities "
        "(including the User Agent Client (UAC)) that an early dialog has been terminated.",
    )

    # 2xx Successful Responses
    OK = (
        200,
        "OK",
        "Indicates that the request was successful.",
    )
    ACCEPTED = (
        202,
        "Accepted",
        "Indicates that the request has been accepted for processing, "
        "but the processing has not been completed. Deprecated.",
    )
    NO_NOTIFICATION = (
        204,
        "No Notification",
        "Indicates the request was successful, but the corresponding response "
        "will not be received.",
    )

    # 3xx Redirection Responses
    MULTIPLE_CHOICES = (
        300,
        "Multiple Choices",
        "The address resolved to one of several options for the user or client "
        "to choose between, which are listed in the message body "
        "or the message's Contact fields.",
    )
    MOVED_PERMANENTLY = (
        301,
        "Moved Permanently",
        "The original Request-URI is no longer valid, the new address is given "
        "in the Contact header field, and the client should update any records "
        "of the original Request-URI with the new value.",
    )
    MOVED_TEMPORARILY = (
        302,
        "Moved Temporarily",
        "The client should try at the address in the Contact field. "
        "If an Expires field is present, the client may cache the result "
        "for that period of time.",
    )
    USE_PROXY = (
        305,
        "Use Proxy",
        "The Contact field details a proxy that must be used to access the requested destination.",
    )
    ALTERNATIVE_SERVICE = (
        380,
        "Alternative Service",
        "The call failed, but alternatives are detailed in the message body.",
    )

    # 4xx Client Failure Responses
    BAD_REQUEST = (
        400,
        "Bad Request",
        "The request could not be understood due to malformed syntax.",
    )
    UNAUTHORIZED = (
        401,
        "Unauthorized",
        "The request requires user authentication. This response is issued by UASs and registrars.",
    )
    PAYMENT_REQUIRED = (
        402,
        "Payment Required",
        "Reserved for future use.",
    )
    FORBIDDEN = (
        403,
        "Forbidden",
        "The server understood the request, but is refusing to fulfill it. "
        "Sometimes (but not always) this means the call has been rejected "
        "by the receiver.",
    )
    NOT_FOUND = (
        404,
        "Not Found",
        "The server has definitive information that the user does not exist "
        "at the domain specified in the Request-URI. This status is also returned "
        "if the domain in the Request-URI does not match any of the domains "
        "handled by the recipient of the request.",
    )
    METHOD_NOT_ALLOWED = (
        405,
        "Method Not Allowed",
        "The method specified in the Request-Line is understood, but not allowed "
        "for the address identified by the Request-URI.",
    )
    NOT_ACCEPTABLE = (
        406,
        "Not Acceptable",
        "The resource identified by the request is only capable of generating "
        "response entities that have content characteristics but not acceptable "
        "according to the Accept header field sent in the request.",
    )
    PROXY_AUTHENTICATION_REQUIRED = (
        407,
        "Proxy Authentication Required",
        "The request requires user authentication. This response is issued by proxies.",
    )
    REQUEST_TIMEOUT = (
        408,
        "Request Timeout",
        "Couldn't find the user in time. The server could not produce a response "
        "within a suitable amount of time, for example, if it could not determine "
        "the location of the user in time. The client MAY repeat the request "
        "without modifications at any later time.",
    )
    CONFLICT = (
        409,
        "Conflict",
        "User already registered. "
        "Deprecated by omission from later RFCs and by non-registration with the IANA.",
    )
    GONE = (
        410,
        "Gone",
        "The user existed once, but is not available here any more.",
    )
    LENGTH_REQUIRED = (
        411,
        "Length Required",
        "The server will not accept the request without a valid Content-Length. "
        "Deprecated by omission from later RFCs and by non-registration with the IANA.",
    )
    CONDITIONAL_REQUEST_FAILED = (
        412,
        "Conditional Request Failed",
        "The given precondition has not been met.",
    )
    REQUEST_ENTITY_TOO_LARGE = (
        413,
        "Request Entity Too Large",
        "Request body too large.",
    )
    REQUEST_URI_TOO_LONG = (
        414,
        "Request-URI Too Long",
        "The server is refusing to service the request because the Request-URI "
        "is longer than the server is willing to interpret.",
    )
    UNSUPPORTED_MEDIA_TYPE = (
        415,
        "Unsupported Media Type",
        "Request body in a format not supported.",
    )
    UNSUPPORTED_URI_SCHEME = (
        416,
        "Unsupported URI Scheme",
        "Request-URI is unknown to the server.",
    )
    UNKNOWN_RESOURCE_PRIORITY = (
        417,
        "Unknown Resource-Priority",
        "There was a resource-priority option tag, but no Resource-Priority header.",
    )
    BAD_EXTENSION = (
        420,
        "Bad Extension",
        "Bad SIP Protocol Extension used, not understood by the server.",
    )
    EXTENSION_REQUIRED = (
        421,
        "Extension Required",
        "The server needs a specific extension not listed in the Supported header.",
    )
    SESSION_INTERVAL_TOO_SMALL = (
        422,
        "Session Interval Too Small",
        "The received request contains a Session-Expires header field "
        "with a duration below the minimum timer.",
    )
    INTERVAL_TOO_BRIEF = (
        423,
        "Interval Too Brief",
        "Expiration time of the resource is too short.",
    )
    BAD_LOCATION_INFORMATION = (
        424,
        "Bad Location Information",
        "The request's location content was malformed or otherwise unsatisfactory.",
    )
    BAD_ALERT_MESSAGE = (
        425,
        "Bad Alert Message",
        "The server rejected a non-interactive emergency call, "
        "indicating that the request was malformed enough that no reasonable "
        "emergency response to the alert can be determined.",
    )
    USE_IDENTITY_HEADER = (
        428,
        "Use Identity Header",
        "The server policy requires an Identity header, and one has not been provided.",
    )
    PROVIDE_REFERRER_IDENTITY = (
        429,
        "Provide Referrer Identity",
        "The server did not receive a valid Referred-By token on the request.",
    )
    FLOW_FAILED = (
        430,
        "Flow Failed",
        "A specific flow to a user agent has failed, although other flows may succeed. "
        "This response is intended for use between proxy devices, "
        "and should not be seen by an endpoint (and if it is seen by one, "
        "should be treated as a 400 Bad Request response).",
    )
    ANONYMITY_DISALLOWED = (
        433,
        "Anonymity Disallowed",
        "The request has been rejected because it was anonymous.",
    )
    BAD_IDENTITY_INFO = (
        436,
        "Bad Identity-Info",
        "The request has an Identity-Info header, and the URI scheme in that header "
        "cannot be dereferenced.",
    )
    UNSUPPORTED_CERTIFICATE = (
        437,
        "Unsupported Certificate",
        "The server was unable to validate a certificate for the domain that signed the request.",
    )
    INVALID_IDENTITY_HEADER = (
        438,
        "Invalid Identity Header",
        "The server obtained a valid certificate that the request claimed "
        "was used to sign the request, but was unable to verify that signature.",
    )
    FIRST_HOP_LACKS_OUTBOUND_SUPPORT = (
        439,
        "First Hop Lacks Outbound Support",
        "The first outbound proxy the user is attempting to register through "
        'does not support the "outbound" feature of RFC 5626, although the registrar does.',
    )
    MAX_BREADTH_EXCEEDED = (
        440,
        "Max-Breadth Exceeded",
        "If a SIP proxy determines a response context has insufficient "
        "Incoming Max-Breadth to carry out a desired parallel fork, and the proxy "
        "is unwilling/unable to compensate by forking serially or sending a redirect, "
        "that proxy MUST return a 440 response. A client receiving a 440 response "
        "can infer that its request did not reach all possible destinations.",
    )
    BAD_INFO_PACKAGE = (
        469,
        "Bad Info Package",
        "If a SIP UA receives an INFO request associated with an Info Package that "
        "the UA has not indicated willingness to receive, the UA MUST _send a "
        "469 response, which contains a Recv-Info header field with Info Packages "
        "for which the UA is willing to receive INFO requests.",
    )
    CONSENT_NEEDED = (
        470,
        "Consent Needed",
        "The source of the request did not have the permission of the recipient "
        "to make such a request.",
    )
    TEMPORARILY_UNAVAILABLE = (
        480,
        "Temporarily Unavailable",
        "Callee currently unavailable.",
    )
    CALL_TRANSACTION_DOES_NOT_EXIST = (
        481,
        "Call/Transaction Does Not Exist",
        "Server received a request that does not match any dialog or transaction.",
    )
    LOOP_DETECTED = (
        482,
        "Loop Detected",
        "Server has detected a loop.",
    )
    TOO_MANY_HOPS = (
        483,
        "Too Many Hops",
        "Max-Forwards header has reached the value '0'.",
    )
    ADDRESS_INCOMPLETE = (
        484,
        "Address Incomplete",
        "Request-URI incomplete.",
    )
    AMBIGUOUS = (
        485,
        "Ambiguous",
        "Request-URI is ambiguous.",
    )
    BUSY_HERE = (
        486,
        "Busy Here",
        "Callee is busy.",
    )
    REQUEST_TERMINATED = (
        487,
        "Request Terminated",
        "Request has terminated by bye or cancel.",
    )
    NOT_ACCEPTABLE_HERE = (
        488,
        "Not Acceptable Here",
        "Some aspect of the session description or the Request-URI is not acceptable.",
    )
    BAD_EVENT = (
        489,
        "Bad Event",
        "The server did not understand an event package specified in an Event header field.",
    )
    REQUEST_PENDING = (
        491,
        "Request Pending",
        "Server has some pending request from the same dialog.",
    )
    UNDECIPHERABLE = (
        493,
        "Undecipherable",
        "Request contains an encrypted MIME body, which recipient can not decrypt.",
    )
    SECURITY_AGREEMENT_REQUIRED = (
        494,
        "Security Agreement Required",
        "The server has received a request that requires a negotiated security mechanism, "
        "and the response contains a list of suitable security mechanisms for the requester "
        "to choose between, or a digest authentication challenge.",
    )

    # 5xx Server Failure Responses
    INTERNAL_SERVER_ERROR = (
        500,
        "Internal Server Error",
        "The server could not fulfill the request due to some unexpected condition.",
    )
    NOT_IMPLEMENTED = (
        501,
        "Not Implemented",
        "The server does not have the ability to fulfill the request, such as "
        "because it does not recognize the request method. (Compare with "
        "405 Method Not Allowed, where the server recognizes the method "
        "but does not allow or support it.)",
    )
    BAD_GATEWAY = (
        502,
        "Bad Gateway",
        "The server is acting as a gateway or proxy, and received an invalid response "
        "from a downstream server while attempting to fulfill the request.",
    )
    SERVICE_UNAVAILABLE = (
        503,
        "Service Unavailable",
        "The server is undergoing maintenance or is temporarily overloaded "
        'and so cannot process the request. A "Retry-After" header field '
        "may specify when the client may reattempt its request.",
    )
    SERVER_TIMEOUT = (
        504,
        "Server Time-out",
        "The server attempted to access another server in attempting to "
        "process the request, and did not receive a prompt response.",
    )
    VERSION_NOT_SUPPORTED = (
        505,
        "Version Not Supported",
        "The SIP protocol version in the request is not supported by the server.",
    )
    MESSAGE_TOO_LARGE = (
        513,
        "Message Too Large",
        "The request message length is longer than the server can process.",
    )
    PUSH_NOTIFICATION_SERVICE_NOT_SUPPORTED = (
        555,
        "Push Notification Service Not Supported",
        "The server does not support the push notification service identified in "
        "a 'pn-provider' SIP URI parameter",
    )
    PRECONDITION_FAILURE = (
        580,
        "Precondition Failure",
        "The server is unable or unwilling to meet some constraints specified in the offer.",
    )

    # 6xx Global Failure Responses
    BUSY_EVERYWHERE = (
        600,
        "Busy Everywhere",
        "All possible destinations are busy. Unlike the 486 response, "
        "this response indicates the destination knows there are no alternative "
        "destinations (such as a voicemail server) able to accept the call.",
    )
    DECLINE = (
        603,
        "Decline",
        "The destination does not wish to participate in the call, or cannot do so, "
        "and additionally the destination knows there are no alternative destinations "
        "(such as a voicemail server) willing to accept the call. "
        "The response may indicate a better time to call in the Retry-After header field.",
    )
    DOES_NOT_EXIST_ANYWHERE = (
        604,
        "Does Not Exist Anywhere",
        "The server has authoritative information that the requested user does not exist anywhere.",
    )
    GLOBALNOT_ACCEPTABLE = (
        606,
        "Not Acceptable",
        "The user's agent was contacted successfully but some aspects of "
        "the session description such as the requested media, bandwidth, "
        "or addressing style were not acceptable.",
    )
    UNWANTED = (
        607,
        "Unwanted",
        "The called party did not want this call from the calling party. "
        "Future attempts from the calling party are likely to be similarly rejected.",
    )
    REJECTED = (
        608,
        "Rejected",
        "An intermediary machine or process rejected the call attempt. "
        "This contrasts with the 607 (Unwanted) SIP response code in which a human, "
        "the called party, rejected the call. The intermediary rejecting the call "
        'should include a Call-Info header with "purpose" value "jwscard", '
        "with the jCard with contact details. The calling party can use this "
        "jCard if they want to dispute the rejection.",
    )


class SIPMessage(ParseableSerializableRaw, ABC):
    """
    Abstract base class for SIP messages, defined in :rfc:`3261#section-7`.

    :param version: SIP version to use in the request line / status line.
    :param headers: SIP headers of the message.
    :param body: SIP body of the message, if any.
    :param origin: Origin of the message, as a tuple of (host, port), if known.
    :param destination: Destination of the message, as a tuple of (host, port), if known.
    """

    def __init__(
        self,
        version: str,
        headers: Headers,
        body: SupportsStr | None,
        origin: tuple[str, int] | None = None,
        destination: tuple[str, int] | None = None,
    ):
        if version not in SUPPORTED_SIP_VERSIONS:
            raise SIPUnsupportedVersion(f"Unsupported SIP version: {version}")

        self.version: str = version
        self.headers: Headers = headers
        self.body: SupportsStr | None = body
        self.origin: tuple[str, int] | None = origin
        self.destination: tuple[str, int] | None = destination

        self.sdp: SDPSession | None = (
            self.body if isinstance(self.body, SDPSession) else None
        )

    @property
    @abstractmethod
    def start_line(self) -> str:
        """Start line of the SIP message."""

    @classmethod
    def parse(  # noqa: D102
        cls, data: bytes, *, origin: tuple[str, int] | None = None
    ) -> Self | SIPMessage:
        if cls is SIPMessage:
            if re.search(rb"^SIP/[\d.]+", data):
                return SIPResponse.parse(data, origin=origin)
            elif re.search(rb"^[^\r\n]+SIP/[\d.]+\r\n", data):
                return SIPRequest.parse(data, origin=origin)
            else:
                raise SIPParseError("Invalid SIP message")

        assert issubclass(cls, SIPMessage)
        assert cls is not SIPMessage

        try:
            headers_raw, *rest = data.split(b"\r\n\r\n", 1)
            body_raw = rest[0] if rest else b""
            start_line, headers_fields = headers_raw.split(b"\r\n", 1)
            start_line_kwargs: dict[str, Any] = cls._parse_start_line(start_line)
            headers: Headers = Headers.parse(headers_fields)
            body: Any = cls._parse_body(headers, body_raw)
            return cls(**start_line_kwargs, headers=headers, body=body, origin=origin)
        # FIXME: improve broad error handling
        except Exception as e:  # noqa: BLE001
            raise SIPParseError(f"Failed to parse SIP message: {e}\n{data!r}") from e

    @classmethod
    @abstractmethod
    def _parse_start_line(cls, start_line: bytes) -> dict[str, Any]:
        """Parse start line of the SIP message, return appropriate kwargs for init."""

    @classmethod
    def _parse_body(cls, headers: Headers, body: bytes) -> Any:
        """Parse body of the SIP message. It's expected to be an SDP session, or empty."""
        if "Content-Encoding" in headers:
            raise SIPUnsupportedError("Encoded SIP content is not supported")

        if "Content-Type" not in headers or not int(headers.get("Content-Length", 0)):
            return None
        content_type = headers["Content-Type"].raw_value

        if content_type == "application/sdp":
            if not body.strip():
                return None
            return SDPSession.parse(body)
        else:
            return body

    def __str__(self) -> str:
        return f"{self.start_line}\r\n{self.headers}\r\n\r\n{self.body or ''}"

    def serialize(self) -> bytes:  # noqa: D102
        return str(self).encode("utf-8")

    def __bytes__(self) -> bytes:
        return self.serialize()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}> {self.start_line}"

    @abstractmethod
    def __eq__(self, other: Any) -> bool:
        """Check if two SIP messages are equal."""


class SIPRequest(SIPMessage):
    """
    SIP requests implementation, as defined in :rfc:`3261#section-7.1`.

    :param method: SIP method of the request.
    :param uri: SIP URI of the request.
    :param version: SIP version of the request.
    :param headers: SIP headers of the request.
    :param body: SIP body of the request, if any.
    :param origin: Origin of the request, as a tuple of (host, port), if known.
    :param destination: Destination of the request, as a tuple of (host, port), if known.
    """

    def __init__(
        self,
        method: SIPMethod,
        uri: SIPURI,
        version: str,
        headers: Headers,
        body: SupportsStr | None = None,
        origin: tuple[str, int] | None = None,
        destination: tuple[str, int] | None = None,
    ):
        super().__init__(version, headers, body, origin=origin, destination=destination)
        self.method: SIPMethod = method
        self.uri: SIPURI = uri

    @property
    @override
    def start_line(self) -> str:
        return (
            f"{self.method} {self.uri.serialize(force_brackets=False)} {self.version}"
        )

    @classmethod
    @override
    def _parse_start_line(cls, start_line: bytes) -> dict[str, Any]:
        method_raw, uri_raw, version = start_line.decode("utf-8").split(" ")
        return dict(
            method=SIPMethod(method_raw), uri=SIPURI.parse(uri_raw), version=version
        )

    @override
    def __eq__(self, other: Any) -> bool:
        return isinstance(other, SIPRequest) and (
            (self.method, self.uri, self.version, self.headers, self.body)
            == (other.method, other.uri, other.version, other.headers, other.body)
        )


class SIPResponse(SIPMessage):
    """
    SIP responses implementation, as defined in :rfc:`3261#section-7.2`.

    :param status: SIP status of the response.
    :param version: SIP version of the response.
    :param headers: SIP headers of the response.
    :param body: SIP body of the response, if any.
    :param origin: Origin of the response, as a tuple of (host, port), if known.
    :param destination: Destination of the response, as a tuple of (host, port), if known.
    """

    def __init__(
        self,
        status: SIPStatus,
        version: str,
        headers: Headers,
        body: SupportsStr | None = None,
        origin: tuple[str, int] | None = None,
        destination: tuple[str, int] | None = None,
    ):
        super().__init__(version, headers, body, origin=origin, destination=destination)
        self.status: SIPStatus = status

    @property
    @override
    def start_line(self) -> str:
        return f"{self.version} {self.status.code} {self.status.reason}"

    @classmethod
    @override
    def _parse_start_line(cls, start_line: bytes) -> dict[str, Any]:
        version, code, reason = start_line.decode("utf-8").split(" ", 2)
        status: SIPStatus = SIPStatus(int(code))
        status.reason = reason
        return dict(status=status, version=version)

    @override
    def __eq__(self, other: Any) -> bool:
        return isinstance(other, SIPResponse) and (
            (self.status, self.version, self.headers, self.body)
            == (other.status, other.version, other.headers, other.body)
        )
