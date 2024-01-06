from __future__ import annotations

import enum
import functools
import ipaddress
import re
import socket
import sys
import time
import types
import typing
import urllib.request
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass as _dtcls, is_dataclass
from inspect import isabstract
from typing import (
    Any,
    Generic,
    MutableMapping,
    Optional,
    Type,
    TypeVar,
    cast,
    ClassVar,
    Union,
    Pattern,
    List,
    Callable,
    get_args,
    get_origin,
    TYPE_CHECKING,
    Protocol,
)
from typing import Mapping

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self


_dT = TypeVar("_dT")


@functools.wraps(_dtcls)
def dataclass(*args, **kwargs) -> Callable[[_dT], _dT]:
    """Wrapper for dataclasses.dataclass that adds slots if supported (py3.10+)"""
    # TODO: restore slots=True default once https://github.com/python/cpython/issues/91126 is fixed
    if sys.version_info < (3, 10):
        kwargs.pop("slots", None)
    return _dtcls(*args, **kwargs)


if TYPE_CHECKING:
    from dataclasses import dataclass


@typing.runtime_checkable
class SupportsStr(Protocol):
    @abstractmethod
    def __str__(self) -> str:
        ...


class FieldsEnumDatatype:
    @property
    def enum_value(self) -> Any:
        raise NotImplementedError(
            "Must be overridden by getting the value from the field"
        )


# noinspection PyTypeChecker
class FieldsEnum(enum.Enum):
    __wrapped_type__: ClassVar[Type[FieldsEnumDatatype]]
    __allow_unknown__: ClassVar[bool] = False
    __unknown_member_name__: ClassVar[str] = "UNKNOWN"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, "__wrapped_type__", None) is None:
            raise TypeError(f"{cls.__name__} must define __wrapped_type__")
        if not issubclass(cls.__wrapped_type__, FieldsEnumDatatype):
            raise TypeError(
                f"{cls.__name__}.__wrapped_type__ must be a subclass of {FieldsEnumDatatype.__name__}"
            )

    def __new__(cls, value: Any):
        if not isinstance(value, cls.__wrapped_type__):
            raise TypeError(
                f"Expected subclass of {cls.__wrapped_type__.__name__}, got {type(value)}"
            )
        if not is_dataclass(value):
            raise TypeError(f"Expected dataclass, got {type(value)}")

        obj = object.__new__(cls)
        obj._wrapped_value_ = value

        exc = None
        for src in (obj, value):
            try:
                enum_value = src.enum_value
                break
            except (NotImplementedError, AttributeError) as exc:
                pass
        else:
            assert exc is not None
            raise exc

        obj._value_ = enum_value
        return obj

    @classmethod
    def _missing_(cls, value: Any) -> Optional[FieldsEnum]:
        if isinstance(value, cls.__wrapped_type__):
            try:
                return cls(value.enum_value)
            except Exception as e:
                if not cls.__allow_unknown__:
                    raise e

        if not cls.__allow_unknown__:
            return None

        obj = cls.__new_member__(cls, value)
        obj._name_ = cls.__unknown_member_name__
        return obj

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped_value_, name)

    def __str__(self) -> str:
        return str(self.enum_value)


_AUTO = types.new_class(
    "AUTO", bases=(FieldsEnumDatatype,)
)  # sentinel for AutoFieldsEnum wrapped type


# noinspection PyAbstractClass
# custom enum class that's tied to a dataclass and mirrors its fields on getattr
class AutoFieldsEnum(FieldsEnumDatatype, FieldsEnum):
    """
    Enum class that mirrors the fields on a dataclass.
    """

    __wrapped_type__ = _AUTO

    def __init_subclass__(cls, **kwargs):
        """
        Dynamically generate a dataclass from the enum definition, frozen, with slots,
        from the __annotations__ of this class.
        """
        dtcls = types.new_class(cls.__name__ + "Dataclass", bases=(FieldsEnumDatatype,))
        dtcls.__annotations__ = cls.__dict__.get("__annotations__", {})
        dtcls.__module__ = cls.__module__
        dtcls.__qualname__ = cls.__qualname__ + "Dataclass"
        dtcls.__doc__ = cls.__doc__
        dtcls = dataclass(frozen=True, slots=True)(dtcls)
        cls.__wrapped_type__ = dtcls

        super().__init_subclass__(**kwargs)

    def __new__(cls, *args, **kwargs):
        dtcls_value = cls.__wrapped_type__(*args, **kwargs)
        obj = FieldsEnum.__new_member__(
            cls, dtcls_value
        )  # yes, enum metaclasses make a mess of this
        obj._dtcls_value_ = dtcls_value
        return obj


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
        # noinspection PyTypeChecker
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
                raise AttributeError(
                    f"No attr_name specified for registry class {cls.__name__}"
                )
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

            conflict_cls: Optional[_RTc] = cls.__registry__.get(registry_id)
            if conflict_cls is not None:
                cls_fullname = (cls.__module__, cls.__qualname__)
                conflict_fullname = (conflict_cls.__module__, conflict_cls.__qualname__)
                if cls_fullname != conflict_fullname:  # not reinit
                    raise NameError(
                        f"More than one {cls.__registry_root__.__name__} subclass with "
                        f'the same {cls.__registry_attr_name__} "{registry_id}" defined: '
                        f"{conflict_cls.__name__} and {cls.__name__}"
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


def time_cache(expiry: float, maxsize: int = 1, typed: bool = False):
    """Simple time / expiration cache decorator, implmented atop functools.lru_cache."""

    def decorator(func: Callable[..., _RT]) -> Callable[..., _RT]:
        @functools.lru_cache(maxsize=maxsize, typed=typed)
        def wrapper(*args: Any, **kwargs: Any) -> _RT:
            return func(*args, **kwargs)

        @functools.wraps(func)
        def wrapped(*args: Any, **kwargs: Any) -> _RT:
            now = time.monotonic()
            if now > wrapper._time_cache_expiry:
                wrapper.cache_clear()
                wrapper._time_cache_expiry = now + expiry
            return wrapper(*args, **kwargs)

        wrapper._time_cache_expiry = 0.0
        return wrapped

    return decorator


@time_cache(expiry=60.0)
def get_public_ip() -> str:
    """Get the public IP address of the current machine."""
    return urllib.request.urlopen("https://ident.me").read().decode("utf8")


def get_local_ip_for_dest(host):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, 0))
        return s.getsockname()[0]


def get_external_ip_for_dest(host: str) -> str:
    """Get the IP address of the current machine relative to the given host."""
    # resolve host if it's not an IP address
    host_ip = socket.gethostbyname(host)
    is_private = ipaddress.ip_address(host_ip).is_private
    if is_private:
        return get_local_ip_for_dest(host_ip)
    else:
        return get_public_ip()
