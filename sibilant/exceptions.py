"""Exception calsses for the Sibilant library."""

from __future__ import annotations

from typing import Any


class SibilantException(Exception):
    """Base class for all custom library exceptions."""


class ParseError(SibilantException, ValueError):
    """Raised when a packet cannot be parsed."""


class SIPException(SibilantException):
    """Base class for all exceptions raised by the SIP module."""


class SIPMessageException(SIPException, IOError):
    """Exceptions related to SIP messages."""

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize SIPRequestException with `request` and `response` objects."""
        response = kwargs.pop("response", None)
        self.response = response
        self.request = kwargs.pop("request", None)
        if response is not None and not self.request and hasattr(response, "request"):
            self.request = self.response.request
        super().__init__(*args, **kwargs)


class SIPUnsupportedError(SIPMessageException, NotImplementedError):
    """Exception raised when a SIP message or feature is not supported."""


class SIPUnsupportedVersion(SIPUnsupportedError):
    """The SIP version is not supported by this library."""


class SIPParseError(SIPException, ParseError):
    """Exceptions related to SIP messages / data parsing."""


class SIPTimeout(SIPException, TimeoutError):
    """Raised when a SIP transaction times out."""


class SIPBadMessage(SIPException):
    """Raised when a SIP message is malformed or invalid."""


class SIPBadRequest(SIPBadMessage):
    """Raised when a SIP request is malformed or invalid."""


class SIPBadResponse(SIPBadMessage):
    """Raised when a SIP response is malformed or invalid."""


class SIPAuthenticationError(SIPException):
    """Raised when a SIP authentication fails."""


class SDPException(SibilantException):
    """Base class for all exceptions raised by the SDP module."""


class SDPUnsupportedVersion(SDPException, NotImplementedError):
    """The SDP version is not supported by this library."""


class SDPParseError(SDPException, ParseError):
    """Exception related to SDP data parsing."""


class SDPUnknownFieldError(SDPParseError):
    """Exception raised when an unknown SDP field is encountered."""


class RTPException(SibilantException):
    """Base class for all exceptions raised by the RTP module."""


class RTPUnsupportedVersion(SIPUnsupportedError):
    """The RTP version is not supported by this library."""


class RTPParseError(RTPException, ParseError):
    """Exception related to RTP data parsing."""


class RTPMismatchedStreamError(RTPException):
    """Exception raised when a packet does not belong to the stream."""


class RTPBrokenStreamError(RTPException):
    """Exception raised when a stream is broken (e.g. too many packets are missing)."""


class RTPUnhandledPayload(RTPException, NotImplementedError):
    """Exception raised when a payload type is not handled by the library."""


class RTPUnsupportedCodec(RTPException, NotImplementedError):
    """Exception raised when a codec is not supported by this library."""


class VoIPException(SibilantException):
    """Base class for all exceptions raised by the VoIP module."""


class VoIPPhoneException(VoIPException):
    """Base class for all exceptions raised by the VoIPPhone class."""


class VoIPCallException(VoIPException):
    """Base class for all exceptions raised by the VoIPCall class."""


class VoIPCallTimeoutError(VoIPCallException, TimeoutError):
    """Raised when a VoIP call method times out."""
