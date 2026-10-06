"""Operasi satu ronde TK-Cipher beserta inverse-nya

State adalah `list[int]` 16 byte row-major, `state[r][c] = b[4r + c]`. Semua fungsi
return list baru dan tidak mengubah input
"""

from collections.abc import Sequence

ROT: tuple[int, int, int, int] = (1, 3, 5, 7)
"""Rotasi bit ke kiri buat baris 0 sampai 3 di `row_rotator`"""
TRANSPOSE_IDX: tuple[int, ...] = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
"""Indeks sumber tiap posisi output `diagonal_transpose`"""


def add_round_key(state: list[int], rk: bytes) -> list[int]:
    """XOR state dengan round key byte per byte, inverse-nya dirinya sendiri

    Args:
        state (list[int]): state 16 byte
        rk (bytes): round key 16 byte

    Returns:
        list[int]: state baru `state[i] ^ rk[i]`

    Raises:
        ValueError: panjang `rk` bukan 16 byte

    Example:
        >>> add_round_key([0xFF] * 16, bytes(16)) == [0xFF] * 16
        True
    """
    if len(rk) != 16:
        raise ValueError("round key must be 16 bytes")
    return [s ^ k for s, k in zip(state, rk)]


def diagonal_transpose(state: list[int]) -> list[int]:
    """Transpose matriks 4x4 lewat diagonal utama (`out[4r + c] = in[4c + r]`), inverse-nya dirinya sendiri

    Args:
        state (list[int]): state 16 byte

    Returns:
        list[int]: state yang sudah ditranspose


    Example:
        >>> diagonal_transpose(list(range(16)))[:4]
        [0, 4, 8, 12]
    """
    return [state[j] for j in TRANSPOSE_IDX]


def dynamic_sub(state: list[int], table: Sequence[int]) -> list[int]:
    """Ganti tiap byte lewat tabel S-box (forward buat enkripsi, inverse buat dekripsi)

    Args:
        state (list[int]): state 16 byte
        table (Sequence[int]): tabel substitusi 256 entri

    Returns:
        list[int]: state baru `table[b]` untuk tiap byte

    Raises:
        IndexError: `table` kurang dari 256 entri

    Example:
        >>> dynamic_sub([1, 2], list(range(256)))
        [1, 2]
    """
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
    """Rotasi bit ke kiri tiap baris (word 32-bit big-endian) sebanyak `ROT[r]`, termasuk baris 0

    Args:
        state (list[int]): state 16 byte

    Returns:
        list[int]: state dengan semua baris dirotasi


    Example:
        >>> row_rotator([0x80] + [0] * 15)[:4]
        [0, 0, 0, 1]
    """
    return _rotate_rows(state, left=True)


def inv_row_rotator(state: list[int]) -> list[int]:
    """Kebalikan `row_rotator`, rotasi bit ke kanan sebanyak `ROT[r]`

    Args:
        state (list[int]): state 16 byte

    Returns:
        list[int]: state dengan semua baris dirotasi balik


    Example:
        >>> inv_row_rotator([0, 0, 0, 1] + [0] * 12)[:4]
        [128, 0, 0, 0]
    """
    return _rotate_rows(state, left=False)


def column_cascade(state: list[int]) -> list[int]:
    """Jumlahkan byte tiap kolom berantai mod 256 biar perubahan nyebar ke satu kolom

    Untuk kolom `(a, b, d, e)` dari baris 0 sampai 3: `b += a; d += b; e += d; a += e`

    Args:
        state (list[int]): state 16 byte

    Returns:
        list[int]: state dengan semua kolom di-cascade


    Example:
        >>> column_cascade([1] + [0] * 15)[::4]
        [2, 1, 1, 1]
    """
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
    """Kebalikan `column_cascade`, pengurangan mod 256 dengan urutan dibalik

    Untuk kolom `(a, b, d, e)`: `a -= e; e -= d; d -= b; b -= a`

    Args:
        state (list[int]): state 16 byte

    Returns:
        list[int]: state dengan cascade dibatalkan


    Example:
        >>> s = list(range(16))
        >>> inv_column_cascade(column_cascade(s)) == s
        True
    """
    out = list(state)
    for c in range(4):
        a, b, d, e = out[c], out[4 + c], out[8 + c], out[12 + c]
        a = (a - e) & 0xFF
        e = (e - d) & 0xFF
        d = (d - b) & 0xFF
        b = (b - a) & 0xFF
        out[c], out[4 + c], out[8 + c], out[12 + c] = a, b, d, e
    return out
