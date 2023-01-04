class SIPException(Exception):
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


class SIPUnsupportedVersion(SIPMessageException, NotImplementedError):
    """The SIP version is not supported by this server."""


class SIPParseError(SIPException, ValueError):
    """Exceptions related to SIP messages / data parsing."""
