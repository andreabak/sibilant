"""Helpers, utilities, and other miscellaneous functions and classes."""

from __future__ import annotations

import enum
import functools
import ipaddress
import logging
import re
import socket
import sys
import time
import types
import urllib.request
from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import MutableSequence
from dataclasses import dataclass as _dtcls, is_dataclass
from inspect import isabstract
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    ClassVar,
    Generic,
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    Pattern,
    Protocol,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
    overload,
    runtime_checkable,
)

import numpy as np
from typing_extensions import Self, TypeAlias, dataclass_transform

from .constants import PUBLIC_IP_RESOLVERS


if TYPE_CHECKING:
    from _typeshed import SupportsKeysAndGetItem
    from numpy.typing import NDArray


_logger = logging.getLogger(__name__)


_dT = TypeVar("_dT")


@functools.wraps(_dtcls)
@dataclass_transform()
def slots_dataclass(*args: Any, **kwargs: Any) -> Callable[[_dT], _dT]:
    """Wrapper for dataclass decorator that adds slots if supported (py3.10+)."""
    # TODO: restore slots=True default once https://github.com/python/cpython/issues/91126 is fixed
    if sys.version_info < (3, 10):
        kwargs.pop("slots", None)
    else:
        kwargs.setdefault("slots", True)
    return cast(Callable[[_dT], _dT], _dtcls(*args, **kwargs))


@runtime_checkable
class SupportsStr(Protocol):
    """Protocol for objects that support str() conversion."""

    @abstractmethod
    def __str__(self) -> str: ...


class FieldsEnumDatatype:
    """Base class for datatypes wrapped in FieldsEnums."""

    @property
    def enum_value(self) -> Any:
        """The value to use for the enum member."""
        raise NotImplementedError(
            "Must be overridden by getting the value from the field"
        )


# noinspection PyTypeChecker
class FieldsEnum(enum.Enum):
    """
    Custom enum class that's tied to a dataclass type and wraps its objects as members
    and proxies their attributes.
    """

    __wrapped_type__: ClassVar[type[FieldsEnumDatatype]]
    __allow_unknown__: ClassVar[bool] = False
    __unknown_member_name__: ClassVar[str] = "UNKNOWN"

    _wrapped_value_: Any

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls_name = cls.__name__
        if getattr(cls, "__wrapped_type__", None) is None:
            raise TypeError(f"{cls_name} must define __wrapped_type__")
        if not issubclass(cls.__wrapped_type__, FieldsEnumDatatype):
            raise TypeError(
                f"{cls_name}.__wrapped_type__ must be a subclass of {FieldsEnumDatatype.__name__}"
            )

    def __new__(cls, value: Any) -> Self:  # noqa: D102
        if not isinstance(value, cls.__wrapped_type__):
            raise TypeError(
                f"Expected subclass of {cls.__wrapped_type__.__name__}, got {type(value)}"
            )
        if not is_dataclass(value):
            raise TypeError(f"Expected dataclass, got {type(value)}")
        assert isinstance(value, cls.__wrapped_type__)

        obj = object.__new__(cls)
        obj._wrapped_value_ = value

        exc = None
        for src in (obj, value):
            try:
                enum_value = src.enum_value
                break
            except (NotImplementedError, AttributeError):
                pass
        else:
            assert exc is not None
            raise exc

        obj._value_ = enum_value
        return obj

    __new_member__: ClassVar[Callable[[type[Self], Any], Self]]

    @classmethod
    def _missing_(cls, value: Any) -> FieldsEnum | None:
        if isinstance(value, cls.__wrapped_type__):
            try:
                return cls(value.enum_value)
            except (ValueError, TypeError):
                if not cls.__allow_unknown__:
                    raise

        if not cls.__allow_unknown__:
            return None

        obj = cast(FieldsEnum, cls.__new_member__(cls, value))
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
    """Enum class that mirrors the fields on a dataclass."""

    __wrapped_type__ = _AUTO

    _dtcls_value_: Any

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """
        Dynamically generate a dataclass from the enum definition, frozen, with slots,
        from the __annotations__ of this class.
        """
        dtcls = types.new_class(cls.__name__ + "Dataclass", bases=(FieldsEnumDatatype,))
        dtcls.__annotations__ = cls.__dict__.get("__annotations__", {})
        dtcls.__module__ = cls.__module__
        dtcls.__qualname__ = cls.__qualname__ + "Dataclass"
        dtcls.__doc__ = cls.__doc__
        dtcls = slots_dataclass(frozen=True)(dtcls)
        cls.__wrapped_type__ = dtcls

        super().__init_subclass__(**kwargs)

    def __new__(cls, *args: Any, **kwargs: Any) -> Self:  # noqa: D102
        dtcls_value = cls.__wrapped_type__(*args, **kwargs)
        # yes, enum metaclasses make a mess of this
        obj = cast(Self, FieldsEnum.__new_member__(cls, dtcls_value))
        obj._dtcls_value_ = dtcls_value
        return obj


_T = TypeVar("_T")


# copied from requests.structures
class CaseInsensitiveDict(MutableMapping[str, _T]):
    """
    A case-insensitive ``dict``-like object.

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

    def __init__(
        self,
        data: SupportsKeysAndGetItem[str, _T] | Iterable[tuple[str, _T]] | None = None,
        **kwargs: _T,
    ) -> None:
        self._store: OrderedDict[str, tuple[str, _T]] = OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key: str, value: _T) -> None:
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key: str) -> _T:
        return self._store[key.lower()][1]

    def __delitem__(self, key: str) -> None:
        del self._store[key.lower()]

    def __iter__(self) -> Iterator[str]:
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self) -> int:
        return len(self._store)

    def lower_items(self) -> Iterator[tuple[str, _T]]:
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self) -> CaseInsensitiveDict[_T]:
        """Return a shallow copy of the instance."""
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self) -> str:
        # noinspection PyTypeChecker
        return str(dict(self.items()))


def try_unpack_optional_type(typ_: Any) -> Any:
    """
    Unpack a type annotation that is Optional, or Union with None and a single other type.

    :param typ_: The type annotation
    :return: The original type wrapped in Optional, or the input argument if it's not Optional.
    """
    args = get_args(typ_)
    origin = get_origin(typ_)
    if (origin is Union or origin is getattr(types, "UnionType", Union)) and (
        args is not None and len(args) == 2 and type(None) in args
    ):
        return next(a for a in args if a is not type(None))
    return typ_


class _DefaultType:
    """Comparable and hashable sentinel for DEFAULT values."""

    # TODO: ensure singleton

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _DefaultType)

    def __hash__(self) -> int:
        return hash((self.__class__, id(self)))

    def __repr__(self) -> str:
        return "DEFAULT"


DEFAULT = _DefaultType()
DefaultType: TypeAlias = _DefaultType


_ID = TypeVar("_ID")
_RT = TypeVar("_RT", bound="Registry")


class Registry(ABC, Generic[_ID, _RT]):
    """
    Abstract base class for registries of subclasses of a given class.

    Subclasses of this class can be initialized as registries, which can be then used
    to register subclasses of the given class through a specific class attribute.
    In the class declaration, some additional keyword arguments must be specified
    to properly initialize the registry:

    :param registry: whether the class is a registry or not.
    :param registry_attr: the name of the class attribute to use as the registry key.
    :param registry_attr_label: the label to use for the registry key in the generated
        methods and constructors.
    :param registry_attr_inheritable: whether the registry attribute is inheritable
        or must instead be always defined in the subclass body.

    Subclasses of "registry" classes are automatically registered in the registry
    using the value of the defined registry attribute as registry key, and can be
    retrieved through the generated :meth:`get_class_for_<attr_label>` method,
    or instantiated through the generated :meth:`for_<attr_label>` constructor.

    Abstract subclasses are not registered, only concrete ones are.
    """

    __registry__: MutableMapping[_ID, type[_RT]]
    __registry_attr_name__: str
    __registry_root__: type[Registry]

    @classmethod
    def is_abstract(cls) -> bool:
        """
        Check if the class is actually defined as abstract
        (i.e. has ABC in its bases, or abstract methods).
        """
        return isabstract(cls) or ABC in cls.__bases__

    # pylint: disable=arguments-differ
    def __init_subclass__(
        cls,
        *,
        registry: bool = False,
        registry_attr: str | None = None,
        registry_attr_label: str | None = None,
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
            registry_id: str | None
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

            conflict_cls: type[_RT] | None = cls.__registry__.get(registry_id)
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
    def get_registry(cls) -> types.MappingProxyType[_ID, type[_RT]]:
        """Get a read-only view of the registry mapping."""
        return types.MappingProxyType(cls.__registry__)

    @classmethod
    def __registry_get_class_for__(cls, registry_id: _ID) -> type[_RT]:
        registered_cls: type[_RT] | None = cls.__registry__.get(registry_id)
        if registered_cls is None:
            raise KeyError(
                f"No registered {cls.__registry_root__.__name__} subclass found "
                f'for {cls.__registry_attr_name__} == "{registry_id}"'
            )
        return registered_cls

    @classmethod
    def __registry_new_for__(cls, registry_id: _ID, *args: Any, **kwargs: Any) -> _RT:
        registered_cls: type[_RT] = cls.__registry_get_class_for__(registry_id)
        # noinspection PyArgumentList
        return cast(_RT, registered_cls(*args, **kwargs))


_sT_contra = TypeVar("_sT_contra", str, bytes, contravariant=True)
_sT_co = TypeVar("_sT_co", str, bytes, covariant=True)


@runtime_checkable
class ParseableAny(Protocol[_sT_contra]):
    """Generic protocol for parseable objects from AnyStr."""

    @classmethod
    def parse(cls, raw_value: _sT_contra) -> Self:
        """Parse a string value into an instance of this class."""


@runtime_checkable
class SerializableAny(Protocol[_sT_co]):
    """Generic protocol for objects serializable to AnyStr."""

    def serialize(self) -> _sT_co:
        """Serialize the object to a string."""


@runtime_checkable
class ParseableSerializableAny(
    ParseableAny[_sT_contra], SerializableAny[_sT_co], Protocol[_sT_contra, _sT_co]
):
    """Generic protocol for objects that are both parseable and serializable to AnyStr."""


@runtime_checkable
class Parseable(ParseableAny[str], Protocol):
    """Generic protocol for parseable objects from str."""


@runtime_checkable
class Serializable(SerializableAny[str], Protocol):
    """Generic protocol for objects serializable to str."""


@runtime_checkable
class ParseableSerializable(Parseable, Serializable, Protocol):
    """Generic protocol for objects that are both parseable and serializable to str."""


@runtime_checkable
class ParseableRaw(ParseableAny[bytes], Protocol):
    """Generic protocol for parseable objects from bytes."""

    @classmethod
    def parse(cls, raw_value: bytes) -> Self:
        """Parse a bytes value into an instance of this class."""


@runtime_checkable
class SerializableRaw(SerializableAny[bytes], Protocol):
    """Generic protocol for objects serializable to bytes."""

    def serialize(self) -> bytes:
        """Serialize the object to bytes."""


@runtime_checkable
class ParseableSerializableRaw(ParseableRaw, SerializableRaw, Protocol):
    """Generic protocol for objects that are both parseable and serializable to bytes."""


@runtime_checkable
class FieldsParser(Protocol):
    """Generic protocol for objects that can parse a string values into separate fields."""

    # FIXME: rename to e.g. parse_fields (also in subclasses, like SDP, SIP Headers, etc.)
    @classmethod
    def parse_raw_value(cls, raw_value: str) -> dict[str, Any]:
        """Parse a string value into a mapping of fields values."""


@runtime_checkable
class FieldsParserSerializer(FieldsParser, Serializable, Protocol):
    """
    Generic protocol for objects that can parse a string values into separate fields
    and serialize them back into a string.
    """


@slots_dataclass
class StrValueMixin(FieldsParserSerializer):
    """Mixin for dataclasses that have a single string field and can be parsed/serialized."""

    value: str

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> dict[str, Any]:  # noqa: D102
        return dict(value=raw_value)

    def serialize(self) -> str:  # noqa: D102
        return self.value


@slots_dataclass
class OptionalStrValueMixin(FieldsParserSerializer):
    """Mixin like :class:`StrValueMixin`, but that also accepts empty values (`None`)."""

    value: str | None

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> dict[str, Any]:  # noqa: D102
        return dict(value=raw_value)

    def serialize(self) -> str:  # noqa: D102
        return self.value or ""


@slots_dataclass
class IntValueMixin(FieldsParserSerializer):
    """Mixin for dataclasses that have a single integer field and can be parsed/serialized."""

    value: int

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> dict[str, Any]:  # noqa: D102
        return dict(value=int(raw_value))

    def serialize(self) -> str:  # noqa: D102
        return str(self.value)

    def __int__(self) -> int:
        return self.value


_ST = TypeVar("_ST", bound=Union[SupportsStr, ParseableSerializable])


@slots_dataclass
class ListValueMixin(MutableSequence, FieldsParserSerializer, Generic[_ST]):
    """
    Mixin for dataclasses that have a list of values and can be parsed/serialized.

    Also provides a list-like interface to access the values.
    """

    _values_type: ClassVar[type[_ST]]  # type: ignore[misc]
    _separator: ClassVar[str] = ", "
    _splitter: ClassVar[str | Pattern[str] | None] = re.compile(r"\s*,\s*")

    values: list[_ST]
    raw_value: str = ""

    def __post_init__(self) -> None:
        if not self.raw_value:
            self.raw_value = self._serialize()

    @classmethod
    def parse_raw_value(cls, raw_value: str) -> dict[str, Any]:  # noqa: D102
        str_value = raw_value.strip()
        splitter = cls._splitter or cls._separator
        str_values: list[str]
        if not str_value:
            str_values = []
        elif isinstance(splitter, str):
            str_values = str_value.split(splitter)
        elif isinstance(splitter, Pattern):
            str_values = splitter.split(str_value)
        else:
            raise TypeError(f"Invalid splitter for {cls.__name__}: {splitter!r}")
        vcls = cls._values_type
        values: list[_ST] = [
            vcls.parse(value) if issubclass(vcls, Parseable) else vcls(value)
            for value in str_values
        ]
        return dict(values=values, raw_value=raw_value)

    def _serialized_values(self) -> list[str]:
        return [
            value.serialize() if isinstance(value, Serializable) else str(value)
            for value in self.values
        ]

    def _serialize(self) -> str:
        return self._separator.join(self._serialized_values())

    def serialize(self) -> str:  # noqa: D102
        return self.raw_value or self._serialize()

    def insert(self, index: int, value: _ST) -> None:  # noqa: D102
        self.values.insert(index, value)

    @overload
    def __getitem__(self, index: int) -> _ST: ...

    @overload
    def __getitem__(self, index: slice) -> MutableSequence[_ST]: ...

    def __getitem__(self, index: int | slice) -> _ST | MutableSequence[_ST]:
        return self.values[index]

    @overload
    def __setitem__(self, index: int, value: _ST) -> None: ...

    @overload
    def __setitem__(self, index: slice, value: Iterable[_ST]) -> None: ...

    def __setitem__(self, index: int | slice, value: _ST | Iterable[_ST]) -> None:
        self.values[index] = value  # type: ignore[index,assignment]

    def __delitem__(self, index: int | slice) -> None:
        del self.values[index]

    def __len__(self) -> int:
        return len(self.values)


_rV_co = TypeVar("_rV_co", covariant=True)


class _TimeCachedCallable(Protocol[_rV_co]):
    _time_cache_expiry: float

    cache_info: Callable[[], Any]
    cache_clear: Callable[[], None]

    def __call__(self, *args: Any, **kwargs: Any) -> _rV_co: ...


def time_cache(
    expiry: float, *, maxsize: int = 1, typed: bool = False
) -> Callable[[Callable[..., _rV_co]], Callable[..., _rV_co]]:
    """Simple time / expiration cache decorator, implmented atop functools.lru_cache."""

    def decorator(func: Callable[..., _rV_co]) -> Callable[..., _rV_co]:
        def _wrapper(*args: Any, **kwargs: Any) -> _rV_co:
            return func(*args, **kwargs)

        wrapper = cast(
            _TimeCachedCallable[_rV_co],
            functools.lru_cache(maxsize=maxsize, typed=typed)(_wrapper),
        )

        @functools.wraps(func)
        def wrapped(*args: Any, **kwargs: Any) -> _rV_co:
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

    def try_resolver(
        url: str, extract_fn: Callable[[str], str | None] | None = None
    ) -> str:
        body = urllib.request.urlopen(url).read().decode("utf8")  # noqa: S310
        if extract_fn:
            body = extract_fn(body)
        if not body:
            raise ValueError(f"Could not extract public IP address from {url} response")
        ip = ipaddress.ip_address(body.strip())
        return str(ip)

    for url, extract_fn in PUBLIC_IP_RESOLVERS:
        try:
            return try_resolver(url, extract_fn)
        except Exception as e:  # noqa: BLE001, PERF203
            _logger.warning(f"Failed to get public IP address from: {url!r}: {e}")
    raise RuntimeError("Could not resolve public IP address")


def get_local_ip_for_dest(host: str) -> str:
    """Get the IP address of the current machine relative to the given host on the local network."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, 0))
        return cast(str, s.getsockname()[0])


def get_external_ip_for_dest(host: str) -> str:
    """Get the IP address of the current machine relative to the given host."""
    # resolve host if it's not an IP address
    host_ip = socket.gethostbyname(host)
    is_private = ipaddress.ip_address(host_ip).is_private
    if is_private:
        return get_local_ip_for_dest(host_ip)
    else:
        return get_public_ip()


@overload
def db_to_amplitude(db: float, *, ref: float = 1.0) -> float: ...


@overload
def db_to_amplitude(
    db: NDArray[np.float32], *, ref: float = 1.0
) -> NDArray[np.float32]: ...


@overload
def db_to_amplitude(
    db: float | NDArray[np.float32], *, ref: float = 1.0
) -> float | NDArray[np.float32]: ...


def db_to_amplitude(
    db: float | NDArray[np.float32], *, ref: float = 1.0
) -> float | NDArray[np.float32]:
    """Convert dB-scaled values to amplitude."""
    return ((ref**2) * np.power(10.0, db * 0.1)) ** 0.5
