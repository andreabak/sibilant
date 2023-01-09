class SibilantException(Exception):
    """Base class for all custom library exceptions"""


class ParseError(SibilantException, ValueError):
    """Raised when a packet cannot be parsed"""


class SIPException(SibilantException):
    """Base class for all exceptions raised by the SIP module."""


class SIPMessageException(SIPException, IOError):
    """Exceptions related to SIP messages."""

    def __init__(self, *args, **kwargs):
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


class RTPParseException(RTPException, ParseError):
    """Exception related to RTP data parsing."""
