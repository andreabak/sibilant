"""DTMF generation and detection."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, ClassVar, Literal, Mapping, cast

import numpy as np
from cbitstruct import CompiledFormat
from typing_extensions import Self, TypeAlias

from sibilant.helpers import ParseableSerializableRaw, slots_dataclass


if TYPE_CHECKING:
    from numpy.typing import NDArray


__all__ = [
    "DTMF_MAP",
    "DTMF_TABLE",
    "DTMFCode",
    "DTMFEvent",
    "DTMFStrCode",
    "generate_dtmf",
    "tone",
]


# Originally from https://github.com/librosa/librosa/blob/d5aa7e1a/librosa/core/audio.py#L1426
# Copyright (c) 2013--2023, librosa development team.
# Tweaked to adapt to our use case.
def tone(
    frequency: float,
    *,
    rate: float,
    length: int | None = None,
    duration: float | None = None,
    phi: float | None = None,
    offset: float | None = None,
) -> NDArray[np.float32]:
    """
    Construct a pure tone (cosine) signal at a given frequency.

    :param frequency: Frequency of the signal.
    :param rate: Sample rate of the signal.
    :param length: Length of the signal in number of samples.
        Only one of ``length`` or ``duration`` can be specified.
    :param duration: Duration of the signal in seconds.
        Only one of ``length`` or ``duration`` can be specified.
    :param phi: Phase offset of the signal.
    :param offset: Time base offset of the signal.
        Acts similarly to phase offset, but scaled on rate.
    :returns: The synthesized sine tone signal.
    """
    if (duration is None) == (length is None):
        raise ValueError("Either ``length`` or ``duration`` must be specified.")

    if length is None:
        assert duration is not None
        length = int(duration * rate)

    if phi is None:
        phi = -np.pi * 0.5

    if offset is None:
        offset = 0

    y: np.ndarray = np.cos(
        2 * np.pi * frequency * (np.arange(length, dtype=np.float32) + offset) / rate
        + phi
    )
    return y


DTMFStrCode: TypeAlias = Literal[
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "#", "A", "B", "C", "D"
]


class DTMFCode(enum.IntEnum):
    """The DTMF event codes as defined in :rfc:`4733#section-3.2`."""

    DIGIT_0 = 0
    DIGIT_1 = 1
    DIGIT_2 = 2
    DIGIT_3 = 3
    DIGIT_4 = 4
    DIGIT_5 = 5
    DIGIT_6 = 6
    DIGIT_7 = 7
    DIGIT_8 = 8
    DIGIT_9 = 9
    STAR = 10
    ASTERISK = STAR
    POUND = 11
    HASH = POUND
    A = 12
    B = 13
    C = 14
    D = 15

    @classmethod
    def from_char(cls, char: DTMFStrCode) -> DTMFCode:
        """Resolve a DTMF code from its string character representation."""
        if len(char) == 1:
            if char == "*":
                return cls.STAR
            elif char == "#":
                return cls.POUND
            elif char in {"A", "B", "C", "D"}:
                return cast(DTMFCode, getattr(cls, char))
            else:
                try:
                    int(char)
                except ValueError:
                    pass
                else:
                    return cast(DTMFCode, getattr(cls, f"DIGIT_{char}"))
        raise ValueError(f"Invalid DTMF code string character: {char}")


# fmt: off
DTMF_TABLE: Mapping[int, Mapping[int, DTMFCode]] = {
    697: {1209: DTMFCode.DIGIT_1, 1336: DTMFCode.DIGIT_2, 1477: DTMFCode.DIGIT_3, 1633: DTMFCode.A},
    770: {1209: DTMFCode.DIGIT_4, 1336: DTMFCode.DIGIT_5, 1477: DTMFCode.DIGIT_6, 1633: DTMFCode.B},
    852: {1209: DTMFCode.DIGIT_7, 1336: DTMFCode.DIGIT_8, 1477: DTMFCode.DIGIT_9, 1633: DTMFCode.C},
    941: {1209: DTMFCode.STAR, 1336: DTMFCode.DIGIT_0, 1477: DTMFCode.POUND, 1633: DTMFCode.D},
}
# fmt: on
DTMF_MAP: Mapping[DTMFCode, tuple[int, int]] = {
    code: (tone_low, tone_high)
    for tone_low, row in DTMF_TABLE.items()
    for tone_high, code in row.items()
}


def generate_dtmf(
    code: DTMFCode,
    rate: float,
    length: int | None = None,
    duration: float | None = None,
    offset: float | None = None,
) -> NDArray[np.float32]:
    """
    Generate a DTMF tone.

    :param code: The DTMF code to generate.
    :param rate: Sample rate of the signal.
    :param length: Length of the signal in number of samples.
        Only one of ``length`` or ``duration`` can be specified.
    :param duration: Duration of the signal in seconds.
        Only one of ``length`` or ``duration`` can be specified.
    :param offset: Time base offset of the signal.
    :returns: The synthesized sine tone signal.
    """
    freq_low, freq_high = DTMF_MAP[code]
    tone_low = tone(
        freq_low, rate=rate, length=length, duration=duration, offset=offset
    )
    tone_high = tone(
        freq_high, rate=rate, length=length, duration=duration, offset=offset
    )
    return 0.5 * tone_low + 0.5 * tone_high


@slots_dataclass
class DTMFEvent(ParseableSerializableRaw):
    """Represents a DTMF event as defined in :rfc:`4733#section-2.3`."""

    event_code: DTMFCode
    end_of_event: bool
    volume: int
    duration: int

    _format_u32: ClassVar[CompiledFormat] = CompiledFormat("u8b1b1u6u16")

    @classmethod
    def parse(cls, data: bytes) -> Self:  # noqa: D102
        event_raw, end_of_event, r, volume_raw, duration = cls._format_u32.unpack(data)
        event_code = DTMFCode(event_raw)
        assert r == 0
        volume = -volume_raw
        return cls(event_code, end_of_event, volume, duration)

    def serialize(self) -> bytes:  # noqa: D102
        return cast(
            bytes,
            self._format_u32.pack(
                self.event_code.value, self.end_of_event, 0, -self.volume, self.duration
            ),
        )

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__}> {self.event_code.name}"
            f"{' end' if self.end_of_event else ''} volume={self.volume} duration={self.duration}"
        )
