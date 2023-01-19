from __future__ import annotations

import re
from abc import ABC
from typing import Optional, List, TYPE_CHECKING

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

from ..exceptions import SDPParseError
from ..helpers import dataclass
from .common import SDPField, SDPSection

if TYPE_CHECKING:
    from dataclasses import dataclass


__all__ = [
    "SDPTimeFields",
    "SDPTimeTime",
    "SDPTimeRepeat",
    "SDPTime",
]


@dataclass(slots=True)
class SDPTimeFields(SDPField, ABC, registry=True, registry_attr="_type"):
    ...


@dataclass(slots=True)
class SDPTimeTime(SDPTimeFields):
    """
    SDP time field, defined in :rfc:`4566#section-5.9`.

    Spec::
        t=<start-time> <stop-time>
    """

    _type = "t"
    _description = "time the session is active"

    start_time: int
    stop_time: int

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        start_time, stop_time = raw_value.split(" ")
        return cls(start_time=int(start_time), stop_time=int(stop_time))

    def serialize(self) -> str:
        return f"{self.start_time} {self.stop_time}"


@dataclass(slots=True)
class SDPTimeRepeat(SDPTimeFields):
    """
    SDP time repeat field, defined in :rfc:`4566#section-5.10`.

    Spec::
        r=<repeat interval> <active duration> <offsets from start-time>
    """

    _type = "r"
    _description = "zero or more repeat times"

    interval: int
    duration: int
    offsets: List[int]

    @classmethod
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        # parse the raw value. N.B. offset could be strings to denote days, hours, minutes, seconds, so they need to be converted to ints
        def parse_time(time_str: str) -> int:
            if isinstance(time_str, int):
                return time_str
            multipliers = {"d": 86400, "h": 3600, "m": 60, "s": 1}
            match = re.match(rf"(-?\d+)([{''.join(multipliers)}])", time_str)
            if not match:
                raise SDPParseError(
                    f'Invalid time string "{time_str}" in repeat field: {raw_value}'
                )
            time, unit = match.groups()
            return int(time) * multipliers[unit]

        interval, duration, *offsets = raw_value.split(" ")
        return cls(
            interval=parse_time(interval),
            duration=parse_time(duration),
            offsets=[parse_time(offset) for offset in offsets],
        )

    def serialize(self) -> str:
        return f"{self.interval} {self.duration} {' '.join(str(offset) for offset in self.offsets)}"


@dataclass(slots=True)
class SDPTime(SDPSection):
    _fields_base = SDPTimeFields
    _start_field = SDPTimeTime

    time: SDPTimeTime
    repeat: Optional[SDPTimeRepeat] = None
