from email.message import Message as Message
import importlib.metadata as importlib_metadata
import os.path as osp
import toml as toml
import warnings as warnings


metadata = None
try:
    metadata = importlib_metadata.metadata(__package__ or __name__)
except importlib_metadata.PackageNotFoundError:
    init_path = osp.dirname(osp.realpath(__file__))
    for relpaths in (("..", "pyproject.toml"), ("pyproject.toml",)):
        pyproj_toml_path = osp.join(init_path, *relpaths)
        if osp.exists(pyproj_toml_path):
            metadata = toml.load(pyproj_toml_path)
            break
    else:
        warnings.warn("Didn't find distinfo nor pyproject.toml for package metadata")


def get_metadata(distinfo_key, toml_getter):
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
