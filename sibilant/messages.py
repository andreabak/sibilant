from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

from .constants import SUPPORTED_SIP_VERSIONS
from .exceptions import SIPUnsupportedVersion, SIPParseError
from .structures import SIPURI
from .headers import Headers


@dataclass(frozen=True, slots=True)
class Method:
    name: str
    description: str

    def __str__(self) -> str:
        return self.name


class SIPMethod(enum.Enum):
    def __new__(cls, value: Method) -> SIPMethod:
        obj = super().__new__(cls, value)
        obj._value_ = value.name
        return obj

    def __str__(self) -> str:
        return str(self.value)

    @property
    def name(self) -> str:
        """Get the name of the SIP method."""
        return self.value.name

    @property
    def description(self) -> str:
        """Get the description of the SIP method."""
        return self.value.description

    REGISTER = Method(
        "REGISTER",
        "Register the URI listed in the To-header field with a location server "
        "and associates it with the network address given in a Contact header field.",
    )
    INVITE = Method(
        "INVITE",
        "Initiate a dialog for establishing a call. The request is sent by "
        "a user agent client to a user agent server.",
    )
    ACK = Method(
        "ACK",
        "Confirm that an entity has received a final response to an INVITE request.",
    )
    BYE = Method(
        "BYE",
        "Signal termination of a dialog and end a call.",
    )
    CANCEL = Method(
        "CANCEL",
        "Cancel any pending request.",
    )
    UPDATE = Method(
        "UPDATE",
        "Modify the state of a session without changing the state of the dialog.",
    )
    REFER = Method(
        "REFER",
        "Ask recipient to issue a request for the purpose of call transfer.",
    )
    PRACK = Method(
        "PRACK",
        "Provisional acknowledgement.",
    )
    SUBSCRIBE = Method(
        "SUBSCRIBE",
        "Initiates a subscription for notification of events from a notifier.",
    )
    NOTIFY = Method(
        "NOTIFY",
        "Inform a subscriber of notifications of a new event.",
    )
    PUBLISH = Method(
        "PUBLISH",
        "Publish an event to a notification server.",
    )
    MESSAGE = Method(
        "MESSAGE",
        "Deliver a text message.",
    )
    INFO = Method(
        "INFO",
        "Send mid-session information that does not modify the session state.",
    )
    OPTIONS = Method(
        "OPTIONS",
        "Query the capabilities of an endpoint.",
    )


@dataclass(frozen=True, slots=True)
class StatusCode:
    code: int
    reason: str
    description: Optional[str] = None

    def __int__(self) -> int:
        return self.code

    def __str__(self) -> str:
        return f"{self.code} {self.reason}"


class SIPStatus(enum.Enum):
    def __new__(cls, value: StatusCode) -> SIPStatus:
        obj = super().__new__(cls, value)
        obj._value_ = value.code
        return obj

    def __int__(self) -> int:
        return int(self.value)

    def __str__(self) -> str:
        return str(self.value)

    @property
    def code(self) -> int:
        return self.value.code

    @property
    def reason(self) -> str:
        return self.value.reason

    @property
    def description(self) -> Optional[str]:
        return self.value.description

    # 1xx Provisional Responses
    TRYING = StatusCode(
        100,
        "Trying",
        "Extended search being performed may take a significant time so "
        "a forking proxy must send a 100 Trying response.",
    )
    RINGING = StatusCode(
        180,
        "Ringing",
        "Destination user agent received INVITE, and is alerting user of call.",
    )
    CALL_FORWARDED = StatusCode(
        181,
        "Call is Being Forwarded",
        "Servers can optionally send this response to indicate a call is being forwarded.",
    )
    QUEUED = StatusCode(
        182,
        "Queued",
        "Indicates that the destination was temporarily unavailable, "
        "so the server has queued the call until the destination is available. "
        "A server may send multiple 182 responses to update progress of the queue.",
    )
    SESSION_PROGRESS = StatusCode(
        183,
        "Session Progress",
        "This response may be used to send extra information for a call which is still being set up.",
    )
    EARLY_DIALOG_TERMINATED = StatusCode(
        199,
        "Early Dialog Terminated",
        "Can be used by User Agent Server to indicate to upstream SIP entities "
        "(including the User Agent Client (UAC)) that an early dialog has been terminated.",
    )

    # 2xx Successful Responses
    OK = StatusCode(
        200,
        "OK",
        "Indicates that the request was successful.",
    )
    ACCEPTED = StatusCode(
        202,
        "Accepted",
        "Indicates that the request has been accepted for processing, "
        "but the processing has not been completed. Deprecated.",
    )
    NO_NOTIFICATION = StatusCode(
        204,
        "No Notification",
        "Indicates the request was successful, but the corresponding response will not be received.",
    )

    # 3xx Redirection Responses
    MULTIPLE_CHOICES = StatusCode(
        300,
        "Multiple Choices",
        "The address resolved to one of several options for the user or client "
        "to choose between, which are listed in the message body "
        "or the message's Contact fields.",
    )
    MOVED_PERMANENTLY = StatusCode(
        301,
        "Moved Permanently",
        "The original Request-URI is no longer valid, the new address is given "
        "in the Contact header field, and the client should update any records "
        "of the original Request-URI with the new value.",
    )
    MOVED_TEMPORARILY = StatusCode(
        302,
        "Moved Temporarily",
        "The client should try at the address in the Contact field. "
        "If an Expires field is present, the client may cache the result "
        "for that period of time.",
    )
    USE_PROXY = StatusCode(
        305,
        "Use Proxy",
        "The Contact field details a proxy that must be used to access the requested destination.",
    )
    ALTERNATIVE_SERVICE = StatusCode(
        380,
        "Alternative Service",
        "The call failed, but alternatives are detailed in the message body.",
    )

    # 4xx Client Failure Responses
    BAD_REQUEST = StatusCode(
        400,
        "Bad Request",
        "The request could not be understood due to malformed syntax.",
    )
    UNAUTHORIZED = StatusCode(
        401,
        "Unauthorized",
        "The request requires user authentication. This response is issued by UASs and registrars.",
    )
    PAYMENT_REQUIRED = StatusCode(
        402,
        "Payment Required",
        "Reserved for future use.",
    )
    FORBIDDEN = StatusCode(
        403,
        "Forbidden",
        "The server understood the request, but is refusing to fulfill it. "
        "Sometimes (but not always) this means the call has been rejected "
        "by the receiver.",
    )
    NOT_FOUND = StatusCode(
        404,
        "Not Found",
        "The server has definitive information that the user does not exist "
        "at the domain specified in the Request-URI. This status is also returned "
        "if the domain in the Request-URI does not match any of the domains "
        "handled by the recipient of the request.",
    )
    METHOD_NOT_ALLOWED = StatusCode(
        405,
        "Method Not Allowed",
        "The method specified in the Request-Line is understood, but not allowed "
        "for the address identified by the Request-URI.",
    )
    NOT_ACCEPTABLE = StatusCode(
        406,
        "Not Acceptable",
        "The resource identified by the request is only capable of generating "
        "response entities that have content characteristics but not acceptable "
        "according to the Accept header field sent in the request.",
    )
    PROXY_AUTHENTICATION_REQUIRED = StatusCode(
        407,
        "Proxy Authentication Required",
        "The request requires user authentication. This response is issued by proxies.",
    )
    REQUEST_TIMEOUT = StatusCode(
        408,
        "Request Timeout",
        "Couldn't find the user in time. The server could not produce a response "
        "within a suitable amount of time, for example, if it could not determine "
        "the location of the user in time. The client MAY repeat the request "
        "without modifications at any later time.",
    )
    CONFLICT = StatusCode(
        409,
        "Conflict",
        "User already registered. Deprecated by omission from later RFCs and by non-registration with the IANA.",
    )
    GONE = StatusCode(
        410,
        "Gone",
        "The user existed once, but is not available here any more.",
    )
    LENGTH_REQUIRED = StatusCode(
        411,
        "Length Required",
        "The server will not accept the request without a valid Content-Length. "
        "Deprecated by omission from later RFCs and by non-registration with the IANA.",
    )
    CONDITIONAL_REQUEST_FAILED = StatusCode(
        412,
        "Conditional Request Failed",
        "The given precondition has not been met.",
    )
    REQUEST_ENTITY_TOO_LARGE = StatusCode(
        413,
        "Request Entity Too Large",
        "Request body too large.",
    )
    REQUEST_URI_TOO_LONG = StatusCode(
        414,
        "Request-URI Too Long",
        "The server is refusing to service the request because the Request-URI "
        "is longer than the server is willing to interpret.",
    )
    UNSUPPORTED_MEDIA_TYPE = StatusCode(
        415,
        "Unsupported Media Type",
        "Request body in a format not supported.",
    )
    UNSUPPORTED_URI_SCHEME = StatusCode(
        416,
        "Unsupported URI Scheme",
        "Request-URI is unknown to the server.",
    )
    UNKNOWN_RESOURCE_PRIORITY = StatusCode(
        417,
        "Unknown Resource-Priority",
        "There was a resource-priority option tag, but no Resource-Priority header.",
    )
    BAD_EXTENSION = StatusCode(
        420,
        "Bad Extension",
        "Bad SIP Protocol Extension used, not understood by the server.",
    )
    EXTENSION_REQUIRED = StatusCode(
        421,
        "Extension Required",
        "The server needs a specific extension not listed in the Supported header.",
    )
    SESSION_INTERVAL_TOO_SMALL = StatusCode(
        422,
        "Session Interval Too Small",
        "The received request contains a Session-Expires header field with a duration below the minimum timer.",
    )
    INTERVAL_TOO_BRIEF = StatusCode(
        423,
        "Interval Too Brief",
        "Expiration time of the resource is too short.",
    )
    BAD_LOCATION_INFORMATION = StatusCode(
        424,
        "Bad Location Information",
        "The request's location content was malformed or otherwise unsatisfactory.",
    )
    BAD_ALERT_MESSAGE = StatusCode(
        425,
        "Bad Alert Message",
        "The server rejected a non-interactive emergency call, "
        "indicating that the request was malformed enough that no reasonable "
        "emergency response to the alert can be determined.",
    )
    USE_IDENTITY_HEADER = StatusCode(
        428,
        "Use Identity Header",
        "The server policy requires an Identity header, and one has not been provided.",
    )
    PROVIDE_REFERRER_IDENTITY = StatusCode(
        429,
        "Provide Referrer Identity",
        "The server did not receive a valid Referred-By token on the request.",
    )
    FLOW_FAILED = StatusCode(
        430,
        "Flow Failed",
        "A specific flow to a user agent has failed, although other flows may succeed. "
        "This response is intended for use between proxy devices, "
        "and should not be seen by an endpoint (and if it is seen by one, "
        "should be treated as a 400 Bad Request response).",
    )
    ANONYMITY_DISALLOWED = StatusCode(
        433,
        "Anonymity Disallowed",
        "The request has been rejected because it was anonymous.",
    )
    BAD_IDENTITY_INFO = StatusCode(
        436,
        "Bad Identity-Info",
        "The request has an Identity-Info header, and the URI scheme in that header cannot be dereferenced.",
    )
    UNSUPPORTED_CERTIFICATE = StatusCode(
        437,
        "Unsupported Certificate",
        "The server was unable to validate a certificate for the domain that signed the request.",
    )
    INVALID_IDENTITY_HEADER = StatusCode(
        438,
        "Invalid Identity Header",
        "The server obtained a valid certificate that the request claimed "
        "was used to sign the request, but was unable to verify that signature.",
    )
    FIRST_HOP_LACKS_OUTBOUND_SUPPORT = StatusCode(
        439,
        "First Hop Lacks Outbound Support",
        "The first outbound proxy the user is attempting to register through "
        'does not support the "outbound" feature of RFC 5626, although the registrar does.',
    )
    MAX_BREADTH_EXCEEDED = StatusCode(
        440,
        "Max-Breadth Exceeded",
        "If a SIP proxy determines a response context has insufficient "
        "Incoming Max-Breadth to carry out a desired parallel fork, and the proxy "
        "is unwilling/unable to compensate by forking serially or sending a redirect, "
        "that proxy MUST return a 440 response. A client receiving a 440 response "
        "can infer that its request did not reach all possible destinations.",
    )
    BAD_INFO_PACKAGE = StatusCode(
        469,
        "Bad Info Package",
        "If a SIP UA receives an INFO request associated with an Info Package that "
        "the UA has not indicated willingness to receive, the UA MUST send a "
        "469 response, which contains a Recv-Info header field with Info Packages "
        "for which the UA is willing to receive INFO requests.",
    )
    CONSENT_NEEDED = StatusCode(
        470,
        "Consent Needed",
        "The source of the request did not have the permission of the recipient to make such a request.",
    )
    TEMPORARILY_UNAVAILABLE = StatusCode(
        480,
        "Temporarily Unavailable",
        "Callee currently unavailable.",
    )
    CALL_TRANSACTION_DOES_NOT_EXIST = StatusCode(
        481,
        "Call/Transaction Does Not Exist",
        "Server received a request that does not match any dialog or transaction.",
    )
    LOOP_DETECTED = StatusCode(
        482,
        "Loop Detected",
        "Server has detected a loop.",
    )
    TOO_MANY_HOPS = StatusCode(
        483,
        "Too Many Hops",
        "Max-Forwards header has reached the value '0'.",
    )
    ADDRESS_INCOMPLETE = StatusCode(
        484,
        "Address Incomplete",
        "Request-URI incomplete.",
    )
    AMBIGUOUS = StatusCode(
        485,
        "Ambiguous",
        "Request-URI is ambiguous.",
    )
    BUSY_HERE = StatusCode(
        486,
        "Busy Here",
        "Callee is busy.",
    )
    REQUEST_TERMINATED = StatusCode(
        487,
        "Request Terminated",
        "Request has terminated by bye or cancel.",
    )
    NOT_ACCEPTABLE_HERE = StatusCode(
        488,
        "Not Acceptable Here",
        "Some aspect of the session description or the Request-URI is not acceptable.",
    )
    BAD_EVENT = StatusCode(
        489,
        "Bad Event",
        "The server did not understand an event package specified in an Event header field.",
    )
    REQUEST_PENDING = StatusCode(
        491,
        "Request Pending",
        "Server has some pending request from the same dialog.",
    )
    UNDECIPHERABLE = StatusCode(
        493,
        "Undecipherable",
        "Request contains an encrypted MIME body, which recipient can not decrypt.",
    )
    SECURITY_AGREEMENT_REQUIRED = StatusCode(
        494,
        "Security Agreement Required",
        "The server has received a request that requires a negotiated security mechanism, "
        "and the response contains a list of suitable security mechanisms for the requester "
        "to choose between, or a digest authentication challenge.",
    )

    # 5xx Server Failure Responses
    INTERNAL_SERVER_ERROR = StatusCode(
        500,
        "Internal Server Error",
        "The server could not fulfill the request due to some unexpected condition.",
    )
    NOT_IMPLEMENTED = StatusCode(
        501,
        "Not Implemented",
        "The server does not have the ability to fulfill the request, such as "
        "because it does not recognize the request method. (Compare with "
        "405 Method Not Allowed, where the server recognizes the method "
        "but does not allow or support it.)",
    )
    BAD_GATEWAY = StatusCode(
        502,
        "Bad Gateway",
        "The server is acting as a gateway or proxy, and received an invalid response "
        "from a downstream server while attempting to fulfill the request.",
    )
    SERVICE_UNAVAILABLE = StatusCode(
        503,
        "Service Unavailable",
        "The server is undergoing maintenance or is temporarily overloaded "
        'and so cannot process the request. A "Retry-After" header field '
        "may specify when the client may reattempt its request.",
    )
    SERVER_TIMEOUT = StatusCode(
        504,
        "Server Time-out",
        "The server attempted to access another server in attempting to "
        "process the request, and did not receive a prompt response.",
    )
    VERSION_NOT_SUPPORTED = StatusCode(
        505,
        "Version Not Supported",
        "The SIP protocol version in the request is not supported by the server.",
    )
    MESSAGE_TOO_LARGE = StatusCode(
        513,
        "Message Too Large",
        "The request message length is longer than the server can process.",
    )
    PUSH_NOTIFICATION_SERVICE_NOT_SUPPORTED = StatusCode(
        555,
        "Push Notification Service Not Supported",
        "The server does not support the push notification service identified in a 'pn-provider' SIP URI parameter",
    )
    PRECONDITION_FAILURE = StatusCode(
        580,
        "Precondition Failure",
        "The server is unable or unwilling to meet some constraints specified in the offer.",
    )

    # 6xx Global Failure Responses
    BUSY_EVERYWHERE = StatusCode(
        600,
        "Busy Everywhere",
        "All possible destinations are busy. Unlike the 486 response, "
        "this response indicates the destination knows there are no alternative "
        "destinations (such as a voicemail server) able to accept the call.",
    )
    DECLINE = StatusCode(
        603,
        "Decline",
        "The destination does not wish to participate in the call, or cannot do so, "
        "and additionally the destination knows there are no alternative destinations "
        "(such as a voicemail server) willing to accept the call. "
        "The response may indicate a better time to call in the Retry-After header field.",
    )
    DOES_NOT_EXIST_ANYWHERE = StatusCode(
        604,
        "Does Not Exist Anywhere",
        "The server has authoritative information that the requested user does not exist anywhere.",
    )
    GLOBALNOT_ACCEPTABLE = StatusCode(
        606,
        "Not Acceptable",
        "The user's agent was contacted successfully but some aspects of "
        "the session description such as the requested media, bandwidth, "
        "or addressing style were not acceptable.",
    )
    UNWANTED = StatusCode(
        607,
        "Unwanted",
        "The called party did not want this call from the calling party. "
        "Future attempts from the calling party are likely to be similarly rejected.",
    )
    REJECTED = StatusCode(
        608,
        "Rejected",
        "An intermediary machine or process rejected the call attempt. "
        "This contrasts with the 607 (Unwanted) SIP response code in which a human, "
        "the called party, rejected the call. The intermediary rejecting the call "
        'should include a Call-Info header with "purpose" value "jwscard", '
        "with the jCard with contact details. The calling party can use this "
        "jCard if they want to dispute the rejection.",
    )


class SIPMessage(ABC):
    def __init__(
        self, version: str, headers: Headers, body: Optional[SDPSession]
    ):
        if version not in SUPPORTED_SIP_VERSIONS:
            raise SIPUnsupportedVersion(f"Unsupported SIP version: {version}")

        self.version: str = version
        self.headers: Headers = headers
        self.body: Optional[SDPSession] = body

    @property
    @abstractmethod
    def start_line(self) -> str:
        """Start line of the SIP message."""

    @classmethod
    def parse(cls, data: bytes) -> Self:
        try:
            headers_raw, body_raw = data.split(b"\r\n\r\n", 1)
            start_line, headers_fields = headers_raw.split(b"\r\n", 1)
            start_line_kwargs: Dict[str, Any] = cls._parse_start_line(start_line)
            headers: Headers = Headers.parse(headers_fields)
            body: Optional[SDPSession] = cls._parse_body(headers, body_raw)
            return cls(**start_line_kwargs, headers=headers, body=body)
        except Exception as e:
            raise SIPParseError("Failed to parse SIP message") from e

    @classmethod
    @abstractmethod
    def _parse_start_line(cls, start_line: bytes) -> Dict[str, Any]:
        """Parse start line of the SIP message, return appropriate kwargs for init."""

    @classmethod
    def _parse_body(cls, headers: Headers, body: bytes) -> Optional[SDPSession]:
        """Parse body of the SIP message. It's expected to be an SDP session, or empty."""
        body_raw: str = body.decode("utf-8").strip()
        if not body_raw:
            return None
        return SDPSession.parse(body_raw)

    def __str__(self) -> str:
        return f"{self.start_line}\r\n{self.headers}\r\n\r\n{self.body}"


class SIPRequest(SIPMessage):
    def __init__(self, method: SIPMethod, uri: SIPURI, version: str, headers: Headers = None, body: str = None):
        super().__init__(version, headers, body)
        self.method: SIPMethod = method
        self.uri: SIPURI = uri

    @property
    def start_line(self) -> str:
        return f"{self.method} {self.uri} {self.version}"

    @classmethod
    def _parse_start_line(cls, start_line: bytes) -> Dict[str, Any]:
        method_raw, uri_raw, version = start_line.decode("utf-8").split(" ")
        return dict(method=SIPMethod(method_raw), uri=SIPURI.parse(uri_raw), version=version)


class SIPResponse(SIPMessage):
    def __init__(self, status_code: SIPStatus, version: str, headers: Headers = None, body: str = None):
        super().__init__(version, headers, body)
        self.status_code: SIPStatus = status_code

    @property
    def start_line(self) -> str:
        return f"{self.version} {self.status_code.code} {self.status_code.reason}"

    @classmethod
    def _parse_start_line(cls, start_line: bytes) -> Dict[str, Any]:
        version, code, reason = start_line.decode("utf-8").split(" ", 2)
        return dict(status_code=SIPStatus(int(code)), version=version)
