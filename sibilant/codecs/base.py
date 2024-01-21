"""Base classes for audio codecs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import numpy as np
    from numpy.typing import NDArray


class Codec(ABC):
    """Abstract base class for audio codecs."""

    @abstractmethod
    def encode(self, data: NDArray[np.float32]) -> bytes:
        """Encode the given audio data."""

    @abstractmethod
    def decode(self, data: bytes) -> NDArray[np.float32]:
        """Decode the given audio data."""
