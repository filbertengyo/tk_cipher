"""Operasi satu ronde TK-Cipher beserta inverse-nya, state 16 byte row-major"""

from collections.abc import Sequence

ROT: tuple[int, int, int, int] = (1, 3, 5, 7)
TRANSPOSE_IDX: tuple[int, ...] = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)


def add_round_key(state: list[int], rk: bytes) -> list[int]:
    """XOR state dengan round key, inverse-nya dirinya sendiri"""
    if len(rk) != 16:
        raise ValueError("round key must be 16 bytes")
    return [s ^ k for s, k in zip(state, rk)]


def diagonal_transpose(state: list[int]) -> list[int]:
    """Transpose matriks 4x4 lewat diagonal, inverse-nya dirinya sendiri"""
    return [state[j] for j in TRANSPOSE_IDX]


def dynamic_sub(state: list[int], table: Sequence[int]) -> list[int]:
    """Ganti tiap byte lewat S-box (forward buat enkripsi, inverse buat dekripsi)"""
    return [table[b] for b in state]


def _rotate_rows(state: list[int], left: bool) -> list[int]:
    out: list[int] = []
    for r in range(4):
        word = int.from_bytes(bytes(state[4 * r : 4 * r + 4]), "big")
        n = ROT[r] if left else 32 - ROT[r]
        word = ((word << n) | (word >> (32 - n))) & 0xFFFFFFFF
        out.extend(word.to_bytes(4, "big"))
    return out


def row_rotator(state: list[int]) -> list[int]:
    """Rotasi bit ke kiri tiap baris (sebagai word 32-bit) sebanyak ROT[r]"""
    return _rotate_rows(state, left=True)


def inv_row_rotator(state: list[int]) -> list[int]:
    """Kebalikan row_rotator, rotasi ke kanan"""
    return _rotate_rows(state, left=False)


def column_cascade(state: list[int]) -> list[int]:
    """Jumlahkan byte tiap kolom berantai mod 256 biar perubahan nyebar ke satu kolom"""
    out = list(state)
    for c in range(4):
        a, b, d, e = out[c], out[4 + c], out[8 + c], out[12 + c]
        b = (b + a) & 0xFF
        d = (d + b) & 0xFF
        e = (e + d) & 0xFF
        a = (a + e) & 0xFF
        out[c], out[4 + c], out[8 + c], out[12 + c] = a, b, d, e
    return out


def inv_column_cascade(state: list[int]) -> list[int]:
    """Kebalikan column_cascade, pengurangan dengan urutan dibalik"""
    out = list(state)
    for c in range(4):
        a, b, d, e = out[c], out[4 + c], out[8 + c], out[12 + c]
        a = (a - e) & 0xFF
        e = (e - d) & 0xFF
        d = (d - b) & 0xFF
        b = (b - a) & 0xFF
        out[c], out[4 + c], out[8 + c], out[12 + c] = a, b, d, e
    return out
