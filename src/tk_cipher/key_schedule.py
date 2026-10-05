"""Key schedule TK-Cipher yang menurunkan 17 round key dari master key"""

from tk_cipher.errors import InvalidKeyError
from tk_cipher.rounds import (
    column_cascade,
    diagonal_transpose,
    dynamic_sub,
    row_rotator,
)
from tk_cipher.sbox import KEY_SIZES, SBox

G = 0x9E3779B9
"""Konstanta golden ratio buat round constant"""
DEFAULT_ROUNDS = 16
"""Jumlah ronde default, jadi 17 round key"""


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF if n else x


def _round_constant(i: int) -> int:
    return _rotl32(G, (5 * i) % 32) ^ ((i * 0x01010101) & 0xFFFFFFFF)


ROUND_CONSTANTS: tuple[int, ...] = tuple(
    _round_constant(i) for i in range(DEFAULT_ROUNDS + 1)
)
"""`RC_i = rotl32(G, 5i mod 32) ^ (i * 0x01010101)` buat i = 0 sampai 16"""


def _lanes(key: bytes, sbox: SBox) -> tuple[bytes, bytes]:
    k0 = key[:16]
    if len(key) == 16:
        k1 = bytes(sbox.forward[b] for b in k0[5:] + k0[:5])
    elif len(key) == 24:
        k1 = key[16:24] + bytes(8)
    else:
        k1 = key[16:32]
    return k0, k1


def expand_key(key: bytes, sbox: SBox, rounds: int = DEFAULT_ROUNDS) -> list[bytes]:
    """Turunkan `rounds + 1` round key 16 byte dari master key lewat S-box dinamis

    Gaya sponge: `t` mulai dari nol, tiap ronde di-XOR lane key (`k0` di ronde
    genap, `k1` di ronde ganjil), disubstitusi S-box, di-XOR `RC_i`, lalu dicampur
    DiagonalTranspose, RowRotator, dan ColumnCascade

    Args:
        key (bytes): master key 16, 24, atau 32 byte
        sbox (SBox): S-box dari `generate_sbox(key)`
        rounds (int): jumlah ronde, default 16

    Returns:
        list[bytes]: `rounds + 1` round key, masing masing 16 byte

    Raises:
        InvalidKeyError: panjang key bukan 16, 24, atau 32 byte
        ValueError: `rounds` kurang dari 1

    Example:
        >>> from tk_cipher.sbox import generate_sbox
        >>> rks = expand_key(bytes(16), generate_sbox(bytes(16)))
        >>> len(rks), len(rks[0])
        (17, 16)
    """
    if len(key) not in KEY_SIZES:
        raise InvalidKeyError("key must be 16, 24, or 32 bytes")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")
    k0, k1 = _lanes(key, sbox)
    t = [0] * 16
    round_keys: list[bytes] = []
    for i in range(rounds + 1):
        lane = k0 if i % 2 == 0 else k1
        t = [x ^ k for x, k in zip(t, lane)]
        t = dynamic_sub(t, sbox.forward)
        rc = _round_constant(i).to_bytes(4, "big")
        t = [x ^ rc[j % 4] for j, x in enumerate(t)]
        t = column_cascade(row_rotator(diagonal_transpose(t)))
        round_keys.append(bytes(t))
    return round_keys
