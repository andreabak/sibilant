from email.message import Message as _Message
import importlib.metadata as _importlib_metadata
import os.path as _osp
import toml as _toml
import warnings as _warnings


_metadata = None
try:
    _metadata = _importlib_metadata.metadata(__package__ or __name__)
except _importlib_metadata.PackageNotFoundError:
    _pyproj_toml_path = _osp.join(_osp.dirname(__file__), "..", "pyproject.toml")
    if not _osp.exists(_pyproj_toml_path):
        _warnings.warn("Didn't find distinfo nor pyproject.toml for package metadata")
    _metadata = _toml.load(_pyproj_toml_path)


def _get_metadata(distinfo_key, toml_getter):
    global _metadata
    if _metadata is None:
        return None
    if isinstance(_metadata, _Message):
        return _metadata.get(distinfo_key)
    elif isinstance(_metadata, dict):
        try:
            return toml_getter(_metadata)
        except (KeyError, IndexError):
            return None
    return None


__title__ = _get_metadata(
    "Name",
    lambda t: t["project"]["name"],
)
__description__ = _get_metadata(
    "Summary",
    lambda t: t["project"]["description"],
)
__url__ = _get_metadata(
    "Home-page",
    lambda t: t["project"]["homepage"],
)
__author__ = _get_metadata(
    "Author",
    lambda t: t["project"]["authors"][0]["name"],
)
__author_email__ = _get_metadata(
    "Author-email",
    lambda t: t["project"]["authors"][0]["email"],
)
__version__ = _get_metadata(
    "Version",
    lambda t: t["project"]["version"],
)
__license__ = _get_metadata(
    "License",
    lambda t: t["project"]["license"]["text"],
)


# TODO: fix __all__ in all modules, or see if there's better options / linters
