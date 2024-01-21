"""Sibilant is a pure-Python VoIP/SIP/RTP library."""

from ._package_metadata import get_metadata as _metadata


__title__ = _metadata("Name", ["project", "name"])
__description__ = _metadata("Summary", ["project", "description"])
__url__ = _metadata("Home-page", ["project", "homepage"])
__author__ = _metadata("Author", ["project", "authors", 0, "name"])
__author_email__ = _metadata("Author-email", ["project", "authors", 0, "email"])
__version__ = _metadata("Version", ["project", "version"])
__license__ = _metadata("License", ["project", "license", "text"])


from .voip import *


# TODO: fix __all__ in all modules, or see if there's better options / linters
