"""SDP time section and fields definitions and implementations."""

from __future__ import annotations

import re
from abc import ABC

from typing_extensions import Self, override

from sibilant.exceptions import SDPParseError
from sibilant.helpers import slots_dataclass

from .common import SDPField, SDPSection


__all__ = [
    "SDPTimeFields",
    "SDPTimeTime",
    "SDPTimeRepeat",
    "SDPTime",
]


@slots_dataclass
class SDPTimeFields(SDPField, ABC, registry=True, registry_attr="_type"):
    """Base class for SDP time description fields."""


@slots_dataclass
class SDPTimeTime(SDPTimeFields):
    """
    SDP time field, defined in :rfc:`8866#section-5.9`.

    Spec::
        t=<start-time> <stop-time>
    """

    _type = "t"
    _description = "time the session is active"

    start_time: int
    stop_time: int

    @classmethod
    @override
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        start_time, stop_time = raw_value.split(" ")
        return cls(start_time=int(start_time), stop_time=int(stop_time))

    def serialize(self) -> str:  # noqa: D102
        return f"{self.start_time} {self.stop_time}"


@slots_dataclass
class SDPTimeRepeat(SDPTimeFields):
    """
    SDP time repeat field, defined in :rfc:`8866#section-5.10`.

    Spec::
        r=<repeat interval> <active duration> <offsets from start-time>
    """

    _type = "r"
    _description = "zero or more repeat times"

    interval: int
    duration: int
    offsets: list[int]

    @classmethod
    @override
    def from_raw_value(cls, field_type: str, raw_value: str) -> Self:
        # parse the raw value. N.B. offset could be strings to denote days, hours, minutes, seconds,
        # so they need to be converted to ints
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

    def serialize(self) -> str:  # noqa: D102
        return f"{self.interval} {self.duration} {' '.join(str(offset) for offset in self.offsets)}"


@slots_dataclass
class SDPTime(SDPSection):
    """SDP section for time description fields, defined in :rfc:`8866#section-5.9`."""

    _fields_base = SDPTimeFields
    _start_field = SDPTimeTime

    time: SDPTimeTime
    repeat: SDPTimeRepeat | None = None
