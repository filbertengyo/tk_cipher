"""S-box dinamis TK-Cipher yang dibangkitkan dari key lewat TKRand"""

from collections.abc import Sequence
from dataclasses import dataclass

from tk_cipher.errors import InvalidKeyError
from tk_cipher.prng import TKRand

MAX_DU = 12
"""Batas atas differential uniformity yang diterima"""
MIN_NL = 90
"""Batas bawah nonlinearity yang diterima"""
KEY_SIZES = (16, 24, 32)
"""Panjang master key yang valid dalam byte"""
SEED_PREFIX = b"TKC-SBOX"
"""Prefix seed TKRand biar domain S-box terpisah dari pemakaian lain"""

_PARITY = tuple(x.bit_count() & 1 for x in range(256))


@dataclass(frozen=True)
class SBox:
    """S-box 8-bit hasil `generate_sbox` beserta statistik kualitasnya

    Attributes:
        forward (tuple[int, ...]): tabel substitusi 256 entri buat enkripsi
        inverse (tuple[int, ...]): kebalikan `forward`, `inverse[forward[x]] == x`
        differential_uniformity (int): DU tabel ini, selalu <= `MAX_DU`
        nonlinearity (int): NL tabel ini, selalu >= `MIN_NL`
        attempts (int): berapa kali shuffle sampai lolos filter

    Example:
        >>> s = generate_sbox(bytes(16))
        >>> all(s.inverse[s.forward[x]] == x for x in range(256))
        True
    """

    forward: tuple[int, ...]
    inverse: tuple[int, ...]
    differential_uniformity: int
    nonlinearity: int
    attempts: int


def differential_uniformity(s: Sequence[int]) -> int:
    """Hitung differential uniformity, maks jumlah x dengan `s[x] ^ s[x ^ a] == b`

    Makin kecil makin tahan kriptanalisis diferensial. Minimum teoretis 2, identitas 256

    Args:
        s (Sequence[int]): tabel S-box 256 entri

    Returns:
        int: nilai DU, maksimum atas semua `a != 0` dan `b`

    Raises:
        ValueError: `s` tidak tepat 256 entri

    Example:
        >>> differential_uniformity(list(range(256)))
        256
    """
    if len(s) != 256:
        raise ValueError("S-box must have 256 entries")
    best = 0
    for a in range(1, 256):
        hist = [0] * 256
        for x in range(256):
            hist[s[x] ^ s[x ^ a]] += 1
        best = max(best, max(hist))
    return best


def nonlinearity(s: Sequence[int]) -> int:
    """Hitung nonlinearity lewat fast Walsh-Hadamard transform tiap mask output

    Hasilnya `128 - max|W| // 2`. Makin besar makin tahan kriptanalisis linear,
    maksimum buat S-box 8-bit 112, identitas 0

    Args:
        s (Sequence[int]): tabel S-box 256 entri

    Returns:
        int: nilai NL

    Raises:
        ValueError: `s` tidak tepat 256 entri

    Example:
        >>> nonlinearity(list(range(256)))
        0
    """
    if len(s) != 256:
        raise ValueError("S-box must have 256 entries")
    worst = 0
    for m in range(1, 256):
        f = [1 - 2 * _PARITY[v & m] for v in s]
        h = 1
        while h < 256:
            for i in range(0, 256, 2 * h):
                for j in range(i, i + h):
                    u, v = f[j], f[j + h]
                    f[j], f[j + h] = u + v, u - v
            h *= 2
        worst = max(worst, max(map(abs, f)))
    return 128 - worst // 2


def _shuffle(rng: TKRand) -> list[int]:
    s = list(range(256))
    for i in range(255, 0, -1):
        j = rng.below(i + 1)
        s[i], s[j] = s[j], s[i]
    return s


def _fix_points(s: list[int], rng: TKRand) -> None:
    while True:
        bad = next((x for x in range(256) if s[x] == x or s[x] == x ^ 0xFF), None)
        if bad is None:
            return
        y = (bad + 1 + rng.below(255)) % 256
        s[bad], s[y] = s[y], s[bad]


def generate_sbox(key: bytes) -> SBox:
    """Bangkitkan S-box deterministik dari master key, beda key beda S-box

    Langkahnya: Fisher-Yates shuffle `[0..255]` pakai `TKRand`, buang titik tetap
    `S[x] == x` dan `S[x] == x ^ 0xFF`, lalu ulang shuffle sampai DU <= `MAX_DU` dan
    NL >= `MIN_NL`

    Args:
        key (bytes): master key 16, 24, atau 32 byte

    Returns:
        SBox: tabel forward, inverse, dan statistiknya

    Raises:
        InvalidKeyError: panjang key bukan 16, 24, atau 32 byte

    Example:
        >>> generate_sbox(bytes(16)) == generate_sbox(bytes(16))
        True
    """
    if len(key) not in KEY_SIZES:
        raise InvalidKeyError("key must be 16, 24, or 32 bytes")
    rng = TKRand(SEED_PREFIX + key + bytes([len(key)]))
    attempts = 0
    while True:
        attempts += 1
        s = _shuffle(rng)
        _fix_points(s, rng)
        du = differential_uniformity(s)
        if du > MAX_DU:
            continue
        nl = nonlinearity(s)
        if nl >= MIN_NL:
            break
    inv = [0] * 256
    for x, v in enumerate(s):
        inv[v] = x
    return SBox(tuple(s), tuple(inv), du, nl, attempts)
