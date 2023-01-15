from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np


class Codec(ABC):
    """Abstract base class for audio codecs."""

    @abstractmethod
    def encode(self, data: np.ndarray) -> bytes:
        """Encode the given audio data."""

    @abstractmethod
    def decode(self, data: bytes) -> np.ndarray:
        """Decode the given audio data."""
