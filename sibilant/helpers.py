from __future__ import annotations

import re
import sys
import types
from abc import ABC
from collections import OrderedDict
from dataclasses import dataclass as _dtcls
from functools import wraps
from inspect import isabstract
from typing import (
    Any,
    Generic,
    MutableMapping,
    Optional,
    Type,
    TypeVar,
    cast, Mapping, ClassVar, Union, Pattern, List, Callable, get_args, get_origin,
)
from typing import Mapping

_T = TypeVar("_T")


# copied from requests.structures
class CaseInsensitiveDict(MutableMapping[str, _T]):
    """A case-insensitive ``dict``-like object.

    Implements all methods and operations of
    ``MutableMapping`` as well as dict's ``copy``. Also
    provides ``lower_items``.

    All keys are expected to be strings. The structure remembers the
    case of the last key to be set, and ``iter(instance)``,
    ``keys()``, ``items()``, ``iterkeys()``, and ``iteritems()``
    will contain case-sensitive keys. However, querying and contains
    testing is case insensitive::

        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        cid['aCCEPT'] == 'application/json'  # True
        list(cid) == ['Accept']  # True

    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header, regardless
    of how the header name was originally stored.

    If the constructor, ``.update``, or equality comparison
    operations are given keys that have equal ``.lower()``s, the
    behavior is undefined.
    """

    def __init__(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __iter__(self):
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self):
        return len(self._store)

    def lower_items(self):
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items())

    def __eq__(self, other):
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self):
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self):
        return str(dict(self.items()))


def try_unpack_optional_type(typ_) -> Any:
    """
    Unpack a type annotation that is Optional, or Union with None and a single other type.

    :param typ_: The type annotation
    :return: The original type wrapped in Optional, or the input argument if it's not Optional
    """
    args = get_args(typ_)
    origin = get_origin(typ_)
    if origin is Union and args is not None and len(args) == 2 and type(None) in args:
        return [a for a in args if a is not type(None)][0]
    return typ_


class _DefaultType:
    """Comparable and hashable sentinel for DEFAULT values"""
    # TODO: ensure singleton

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _DefaultType)

    def __hash__(self) -> int:
        return hash((self.__class__, id(self)))

    def __repr__(self) -> str:
        return "DEFAULT"


DEFAULT = _DefaultType()


_ID = TypeVar("_ID")
_RT = TypeVar("_RT", bound="Registry")
_RTc = Type[_RT]


class Registry(ABC, Generic[_ID, _RT]):
    __registry__: MutableMapping[_ID, _RTc]
    __registry_attr_name__: str
    __registry_root__: Type["Registry"]

    @classmethod
    def is_abstract(cls) -> bool:
        return isabstract(cls) or ABC in cls.__bases__

    # pylint: disable=arguments-differ
    def __init_subclass__(
        cls,
        registry: bool = False,
        registry_attr: Optional[str] = None,
        registry_attr_label: Optional[str] = None,
        registry_attr_inheritable: bool = True,
        **kwargs: Any,
    ):
        super().__init_subclass__(**kwargs)

        # Create a new registry
        if registry:
            if not registry_attr:
                raise AttributeError(f"No attr_name specified for registry class {cls.__name__}")
            if registry_attr_label is None:
                registry_attr_label = registry_attr

            cls.__registry__ = {}
            cls.__registry_attr_name__ = registry_attr
            cls.__registry_root__ = cls
            trimmed_attr_label: str = registry_attr_label.strip("_")
            setattr(
                cls,
                f"get_class_for_{trimmed_attr_label}",
                cls.__registry_get_class_for__,
            )
            setattr(cls, f"for_{trimmed_attr_label}", cls.__registry_new_for__)

        # Check registry subclass
        else:
            registry_id: Optional[str]
            try:
                if registry_attr_inheritable:
                    registry_id = getattr(cls, cls.__registry_attr_name__)
                else:
                    registry_id = cls.__dict__.get(cls.__registry_attr_name__)
            except AttributeError:
                registry_id = None
            if registry_id is None:
                if cls.is_abstract():
                    return
                raise ValueError(
                    f"Cannot register {cls.__name__} in {cls.__registry_root__.__name__}, "
                    f"no {cls.__registry_attr_name__} defined in the class body"
                )

            existing_registered_class: Optional[_RTc] = cls.__registry__.get(registry_id)
            if existing_registered_class is not None:
                raise NameError(
                    f"More than one {cls.__registry_root__.__name__} subclass with "
                    f'the same {cls.__registry_attr_name__} "{registry_id}" defined: '
                    f"{existing_registered_class.__name__} and {cls.__name__}"
                )
            cls.__registry__[registry_id] = cls

    @classmethod
    def get_registry(cls) -> types.MappingProxyType[_ID, _RTc]:
        return types.MappingProxyType(cls.__registry__)

    @classmethod
    def __registry_get_class_for__(cls, registry_id: _ID) -> _RTc:
        registered_cls: Optional[_RTc] = cls.__registry__.get(registry_id)
        if registered_cls is None:
            raise KeyError(
                f"No registered {cls.__registry_root__.__name__} subclass found "
                f'for {cls.__registry_attr_name__} == "{registry_id}"'
            )
        return registered_cls

    @classmethod
    def __registry_new_for__(cls, registry_id: _ID, *args: Any, **kwargs: Any) -> _RT:
        registered_cls: _RTc = cls.__registry_get_class_for__(registry_id)
        # noinspection PyArgumentList
        return cast(_RT, registered_cls(*args, **kwargs))
    
    
_dT = TypeVar("_dT")


@wraps(_dtcls)
def dataclass(*args, **kwargs) -> Callable[[_dT], _dT]:
    """Wrapper for dataclasses.dataclass that adds slots if supported (py3.10+)"""
    if sys.version_info >= (3, 10):
        kwargs["slots"] = True
    else:
        kwargs.pop("slots", None)
    return _dtcls(*args, **kwargs)
    

@dataclass(slots=True)
class StrValueMixin:
    value: str

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> Mapping[str, Any]:
        return dict(value=raw_value)

    def serialize(self) -> str:
        return self.value


@dataclass(slots=True)
class IntValueMixin:
    value: int

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> Mapping[str, Any]:
        return dict(value=int(raw_value))

    def serialize(self) -> str:
        return str(self.value)

    def __int__(self):
        return self.value


@dataclass(slots=True)
class ListValueMixin:
    _separator: ClassVar[str] = ", "
    _splitter: ClassVar[Union[str, Pattern[str], None]] = re.compile(r"\s*,\s*")

    values: List[str]
    raw_value: Optional[str] = None

    def __post_init__(self):
        if self.raw_value is None:
            self.raw_value = self._separator.join(self.values)

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> Mapping[str, Any]:
        value = raw_value.strip()
        splitter = cls._splitter or cls._separator
        if isinstance(splitter, str):
            values = value.split(splitter)
        elif isinstance(splitter, Pattern):
            values = splitter.split(value)
        else:
            raise TypeError(f"Invalid splitter for {cls.__name__}: {splitter!r}")
        return dict(values=values, raw_value=raw_value)

    def serialize(self) -> str:
        return self.raw_value
    


