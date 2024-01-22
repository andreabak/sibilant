from __future__ import annotations

import importlib.metadata as importlib_metadata
import warnings
from email.message import Message
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import toml


metadata: Message | Mapping[str, Any] | None = None
# FIXME: give precedence to pyproject.toml metadata for correct info in local testing
try:
    metadata = importlib_metadata.metadata(__package__ or __name__)
except importlib_metadata.PackageNotFoundError:
    init_path = Path(__file__).resolve().parent
    for relpaths in (("..", "pyproject.toml"), ("pyproject.toml",)):
        pyproj_toml_path = Path(init_path, *relpaths)
        if pyproj_toml_path.exists():
            metadata = toml.load(pyproj_toml_path)
            break
    else:
        warnings.warn(
            "Didn't find distinfo nor pyproject.toml for package metadata", stacklevel=1
        )


def get_metadata(
    distinfo_key: str,
    toml_getter: str | int | Sequence[str | int] | Callable[[Mapping[str, Any]], Any],
) -> Any:
    global metadata
    if metadata is None:
        return None
    if isinstance(metadata, Message):
        return metadata.get(distinfo_key)
    elif isinstance(metadata, dict):
        try:
            if callable(toml_getter):
                return toml_getter(metadata)
            elif isinstance(toml_getter, (list, tuple)):
                value = metadata
                for key in toml_getter:
                    value = value[key]
                return value
            else:
                return metadata[toml_getter]
        except (KeyError, IndexError):
            return None
    return None
