"""
Audio codecs for the RTP protocol.

The unencoded audio format is float 32-bit PCM, returned as numpy arrays.
"""

from __future__ import annotations

import audioop
from typing import TYPE_CHECKING

import numpy as np
from typing_extensions import override

from .base import Codec


if TYPE_CHECKING:
    from numpy.typing import NDArray


__all__ = [
    "PCMUCodec",
    "PCMACodec",
]


# ruff: noqa: E221, E241, UP034, PLR2004


def ulaw_encode_slow(data: NDArray[np.float32]) -> NDArray[np.uint8]:
    """Encode `np.float32` [-1.0, 1.0] data to μ-law-encoded `np.uint8`."""
    data_i16: NDArray[np.int16] = (data * (2**15 - 1)).astype(np.int16)
    sign: NDArray[np.uint8] = ((data_i16 >> 8) & 0x80).astype(np.uint8)
    data_u8: NDArray[np.uint8] = (np.abs(data_i16) + 0x84).astype(np.uint8)
    exp: NDArray[np.uint8] = ulaw_comp_table.take((data_u8 >> 7) & 0xFF)
    mant: NDArray[np.uint8] = ((data_u8 >> (exp + 3)) & 0x0F).astype(np.uint8)
    return (sign | (exp << 4) | mant).astype(np.uint8)


ulaw_comp_table: NDArray[np.uint8] = np.floor(
    np.log2(np.clip(np.arange(2**8), 1, None))
).astype(np.uint8)
# fmt: off
ulaw_to_lin_i16_lut: NDArray[np.int16] = np.array([
    -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956,
    -23932, -22908, -21884, -20860, -19836, -18812, -17788, -16764,
    -15996, -15484, -14972, -14460, -13948, -13436, -12924, -12412,
    -11900, -11388, -10876, -10364,  -9852,  -9340,  -8828,  -8316,
     -7932,  -7676,  -7420,  -7164,  -6908,  -6652,  -6396,  -6140,
     -5884,  -5628,  -5372,  -5116,  -4860,  -4604,  -4348,  -4092,
     -3900,  -3772,  -3644,  -3516,  -3388,  -3260,  -3132,  -3004,
     -2876,  -2748,  -2620,  -2492,  -2364,  -2236,  -2108,  -1980,
     -1884,  -1820,  -1756,  -1692,  -1628,  -1564,  -1500,  -1436,
     -1372,  -1308,  -1244,  -1180,  -1116,  -1052,   -988,   -924,
      -876,   -844,   -812,   -780,   -748,   -716,   -684,   -652,
      -620,   -588,   -556,   -524,   -492,   -460,   -428,   -396,
      -372,   -356,   -340,   -324,   -308,   -292,   -276,   -260,
      -244,   -228,   -212,   -196,   -180,   -164,   -148,   -132,
      -120,   -112,   -104,    -96,    -88,    -80,    -72,    -64,
       -56,    -48,    -40,    -32,    -24,    -16,     -8,     -1,
     32124,  31100,  30076,  29052,  28028,  27004,  25980,  24956,
     23932,  22908,  21884,  20860,  19836,  18812,  17788,  16764,
     15996,  15484,  14972,  14460,  13948,  13436,  12924,  12412,
     11900,  11388,  10876,  10364,   9852,   9340,   8828,   8316,
      7932,   7676,   7420,   7164,   6908,   6652,   6396,   6140,
      5884,   5628,   5372,   5116,   4860,   4604,   4348,   4092,
      3900,   3772,   3644,   3516,   3388,   3260,   3132,   3004,
      2876,   2748,   2620,   2492,   2364,   2236,   2108,   1980,
      1884,   1820,   1756,   1692,   1628,   1564,   1500,   1436,
      1372,   1308,   1244,   1180,   1116,   1052,    988,    924,
       876,    844,    812,    780,    748,    716,    684,    652,
       620,    588,    556,    524,    492,    460,    428,    396,
       372,    356,    340,    324,    308,    292,    276,    260,
       244,    228,    212,    196,    180,    164,    148,    132,
       120,    112,    104,     96,     88,     80,     72,     64,
        56,     48,     40,     32,     24,     16,      8,      0,
], dtype=np.int16)
# fmt: on
ulaw_to_lin_f32_lut: NDArray[np.float32] = ulaw_to_lin_i16_lut.astype(np.float32) / (
    2**15 - 1
)
lin_u16_to_ulaw_lut: NDArray[np.uint8] = ulaw_encode_slow(
    (np.arange(-(2**13), 2**13) / 2**13)
)


def alaw_encode_slow(data: NDArray[np.float32]) -> NDArray[np.uint8]:
    """Encode `np.float32` [-1.0, 1.0] data to A-law-encoded `np.uint8`."""
    data_i16: NDArray[np.int16] = (data * (2**15 - 1)).astype(np.int16)

    cclip = 32767
    sign = np.bitwise_not(data_i16) >> 8 & 0x80
    data_i16 = np.where(sign == 0, -data_i16, data_i16)
    data_i16 = np.clip(data_i16, -cclip, cclip)

    exp: NDArray[np.uint8] = np.zeros_like(data_i16, dtype=np.uint8)
    mant: NDArray[np.uint8] = np.zeros_like(data_i16, dtype=np.uint8)

    mask = data_i16 >= 256
    exp[mask] = alaw_comp_table.take((data_i16[mask] >> 8) & 0x7F)
    mant[mask] = (data_i16[mask] >> (exp[mask] + 3)) & 0x0F

    res: NDArray[np.uint8] = np.zeros_like(data_i16, dtype=np.uint8)
    res[mask] = (exp[mask] << 4) | mant[mask]
    res[~mask] = data_i16[~mask] >> 4

    return np.bitwise_xor(res, (sign ^ 0x55))


alaw_comp_table: NDArray[np.uint8] = np.floor(
    np.log2(np.clip(np.arange(2**7), 1, None))
).astype(np.uint8)
# fmt: off
alaw_to_lin_i16_lut: NDArray[np.int16] = np.array([
     -5504,  -5248,  -6016,  -5760,  -4480,  -4224,  -4992,  -4736,
     -7552,  -7296,  -8064,  -7808,  -6528,  -6272,  -7040,  -6784,
     -2752,  -2624,  -3008,  -2880,  -2240,  -2112,  -2496,  -2368,
     -3776,  -3648,  -4032,  -3904,  -3264,  -3136,  -3520,  -3392,
    -22016, -20992, -24064, -23040, -17920, -16896, -19968, -18944,
    -30208, -29184, -32256, -31232, -26112, -25088, -28160, -27136,
    -11008, -10496, -12032, -11520,  -8960,  -8448,  -9984,  -9472,
    -15104, -14592, -16128, -15616, -13056, -12544, -14080, -13568,
      -344,   -328,   -376,   -360,   -280,   -264,   -312,   -296,
      -472,   -456,   -504,   -488,   -408,   -392,   -440,   -424,
       -88,    -72,   -120,   -104,    -24,     -8,    -56,    -40,
      -216,   -200,   -248,   -232,   -152,   -136,   -184,   -168,
     -1376,  -1312,  -1504,  -1440,  -1120,  -1056,  -1248,  -1184,
     -1888,  -1824,  -2016,  -1952,  -1632,  -1568,  -1760,  -1696,
      -688,   -656,   -752,   -720,   -560,   -528,   -624,   -592,
      -944,   -912,  -1008,   -976,   -816,   -784,   -880,   -848,
      5504,   5248,   6016,   5760,   4480,   4224,   4992,   4736,
      7552,   7296,   8064,   7808,   6528,   6272,   7040,   6784,
      2752,   2624,   3008,   2880,   2240,   2112,   2496,   2368,
      3776,   3648,   4032,   3904,   3264,   3136,   3520,   3392,
     22016,  20992,  24064,  23040,  17920,  16896,  19968,  18944,
     30208,  29184,  32256,  31232,  26112,  25088,  28160,  27136,
     11008,  10496,  12032,  11520,   8960,   8448,   9984,   9472,
     15104,  14592,  16128,  15616,  13056,  12544,  14080,  13568,
       344,    328,    376,    360,    280,    264,    312,    296,
       472,    456,    504,    488,    408,    392,    440,    424,
        88,     72,    120,    104,     24,      8,     56,     40,
       216,    200,    248,    232,    152,    136,    184,    168,
      1376,   1312,   1504,   1440,   1120,   1056,   1248,   1184,
      1888,   1824,   2016,   1952,   1632,   1568,   1760,   1696,
       688,    656,    752,    720,    560,    528,    624,    592,
       944,    912,   1008,    976,    816,    784,    880,    848
], dtype=np.int16)
# fmt: on
alaw_to_lin_f32_lut: NDArray[np.float32] = alaw_to_lin_i16_lut.astype(np.float32) / (
    2**15 - 1
)
lin_u16_to_alaw_lut: NDArray[np.uint8] = alaw_encode_slow(
    (np.arange(-(2**13), 2**13) / 2**13)
)


# FIXME: these pure-numpy implementations are slow. Consider doing something faster.
#        audioop would be 10-100x faster, but it's deprecated for removal in Python 3.13.
#        current performance:
#        - PCMUCodec.encode: ~7us / 22MB/s (on 160 B), ~100us / 1.6MB/s (on 16 kB)
#        - PCMUCodec.decode: ~3us / 55MB/s (on 160 B),  ~71us / 2.2MB/s (on 16 kB)
#        - PCMACodec.encode: ~7us / 22MB/s (on 160 B), ~100us / 1.6MB/s (on 16 kB)
#        - PCMACodec.decode: ~3us / 55MB/s (on 160 B),  ~71us / 2.2MB/s (on 16 kB)


class PCMUCodec(Codec):
    """G.711 μ-law to numpy float32 codec."""

    @override
    def encode(self, data: NDArray[np.float32]) -> bytes:
        data_bytes: bytes = (data * (2**15 - 1)).astype(np.int16).tobytes()
        return audioop.lin2ulaw(data_bytes, 2)
        # FIXME: fix and restore numpy implementations / or find better solution
        # # FIXME: clip to [-1, 1]
        # data = (data * (2**13 - 1)).astype(np.int16) + 2**13
        # return lin_u16_to_ulaw_lut.take(data).tobytes()

    @override
    def decode(self, data: bytes) -> NDArray[np.float32]:
        data_bytes: bytes = audioop.ulaw2lin(data, 2)
        return np.frombuffer(data_bytes, dtype=np.int16).astype(np.float32) / (
            2**15 - 1
        )
        # FIXME: fix and restore numpy implementations / or find better solution
        # return ulaw_to_lin_f32_lut.take(np.frombuffer(data, dtype=np.uint8))


class PCMACodec(Codec):
    """G.711 A-law to numpy float32 codec."""

    @override
    def encode(self, data: NDArray[np.float32]) -> bytes:
        data_bytes: bytes = (data * (2**15 - 1)).astype(np.int16).tobytes()
        return audioop.lin2alaw(data_bytes, 2)
        # FIXME: fix and restore numpy implementations / or find better solution
        # data = (data * (2**13 - 1)).astype(np.int16) + 2**13
        # return lin_u16_to_alaw_lut.take(data).tobytes()

    @override
    def decode(self, data: bytes) -> NDArray[np.float32]:
        data_bytes: bytes = audioop.alaw2lin(data, 2)
        return np.frombuffer(data_bytes, dtype=np.int16).astype(np.float32) / (
            2**15 - 1
        )
        # FIXME: fix and restore numpy implementations / or find better solution
        # return alaw_to_lin_f32_lut.take(np.frombuffer(data, dtype=np.uint8))
