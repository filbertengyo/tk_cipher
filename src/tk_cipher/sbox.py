"""S-box dinamis TK-Cipher yang dibangkitkan dari key lewat TKRand"""

from collections.abc import Sequence
from dataclasses import dataclass

from tk_cipher.errors import InvalidKeyError
from tk_cipher.prng import TKRand

MAX_DU = 12
MIN_NL = 90
KEY_SIZES = (16, 24, 32)
SEED_PREFIX = b"TKC-SBOX"

_PARITY = tuple(x.count("1") & 1 for x in range(256))


@dataclass(frozen=True)
class SBox:
    """S-box 8-bit hasil ``generate_sbox`` beserta statistiknya.

    Attributes:
        forward: Tabel substitusi, 256 entri, permutasi 0..255.
        inverse: Kebalikan ``forward``, ``inverse[forward[x]] == x``.
        differential_uniformity: Nilai DU dari ``forward``.
        nonlinearity: Nilai NL dari ``forward``.
        attempts: Jumlah shuffle sampai lolos filter kualitas.

    Example:
        >>> sbox = generate_sbox(bytes(16))
        >>> sbox.inverse[sbox.forward[42]]
        42
    """

    forward: tuple[int, ...]
    inverse: tuple[int, ...]
    differential_uniformity: int
    nonlinearity: int
    attempts: int


def differential_uniformity(s: Sequence[int]) -> int:
    """Hitung differential uniformity S-box 8-bit.

    Maksimum, atas semua ``a`` di 1..255 dan semua ``b``, dari jumlah ``x``
    dengan ``s[x] ^ s[x ^ a] == b``. Makin kecil makin tahan kriptanalisis
    diferensial.

    Args:
        s: Tabel S-box, 256 entri bernilai 0..255.

    Returns:
        Differential uniformity, antara 2 dan 256.

    Raises:
        ValueError: Kalau panjang ``s`` bukan 256.

    Example:
        >>> differential_uniformity(range(256))
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
    """Hitung nonlinearity S-box 8-bit lewat fast Walsh-Hadamard transform.

    Untuk tiap mask output ``m`` di 1..255, fungsi boolean
    ``popcount(s[x] & m) mod 2`` diubah ke bentuk ±1, di-transform, lalu
    diambil koefisien Walsh absolut terbesar. Hasilnya
    ``128 - (maksimum atas semua m) // 2``.

    Args:
        s: Tabel S-box, 256 entri bernilai 0..255.

    Returns:
        Nonlinearity, antara 0 dan 128.

    Raises:
        ValueError: Kalau panjang ``s`` bukan 256.

    Example:
        >>> nonlinearity(range(256))
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
    """Bangkitkan S-box dinamis yang deterministik dari key.

    TKRand di-seed dengan ``b"TKC-SBOX" + key + bytes([len(key)])``. Array
    0..255 diacak Fisher-Yates, titik ``S[x] == x`` dan ``S[x] == x ^ 0xFF``
    dibuang lewat swap acak, lalu dicek ``DU <= MAX_DU`` dan ``NL >= MIN_NL``.
    Kalau gagal, shuffle diulang dengan PRNG yang sama (tetap deterministik).

    Args:
        key: Key 16, 24, atau 32 byte.

    Returns:
        ``SBox`` berisi tabel forward, inverse, DU, NL, dan jumlah percobaan.

    Raises:
        InvalidKeyError: Kalau panjang ``key`` bukan 16, 24, atau 32 byte.

    Example:
        >>> sbox = generate_sbox(bytes(16))
        >>> sorted(sbox.forward) == list(range(256))
        True
        >>> sbox.differential_uniformity <= MAX_DU
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
