from __future__ import annotations

import enum
from typing import Union, Optional, TYPE_CHECKING

from ..helpers import FieldsEnum, dataclass

if TYPE_CHECKING:
    from dataclasses import dataclass


class RTPMediaType(enum.Enum):
    AUDIO = "audio"
    VIDEO = "video"


@dataclass(slots=True)
class RTPMediaFormat(FieldsEnum):
    payload_type: Union[int, str]
    media_type: RTPMediaType
    encoding_name: str
    clock_rate: int
    channels: Optional[int]
    format_specific_parameters: Optional[str]

    @property
    def mimetype(self) -> str:  # TODO: is this correct?
        return f"{self.media_type.value}/{self.encoding_name}".lower()
