"""Block cipher TK-Cipher: SPN 128-bit dengan 16 ronde dan whitening di akhir

Modul ini cuma ngurus satu blok 16 byte. Buat data panjang pakai `tk_cipher.modes`,
buat file lengkap dengan MAC pakai `tk_cipher.fileformat`
"""

from tk_cipher.errors import InvalidKeyError
from tk_cipher.key_schedule import expand_key
from tk_cipher.rounds import (
    add_round_key,
    column_cascade,
    diagonal_transpose,
    dynamic_sub,
    inv_column_cascade,
    inv_row_rotator,
    row_rotator,
)
from tk_cipher.sbox import KEY_SIZES, generate_sbox

BLOCK_SIZE = 16
"""Ukuran blok dalam byte (128-bit)"""
ROUNDS = 16
"""Jumlah ronde default"""


class TKCipher:
    """Block cipher 128-bit dengan S-box dinamis dan 17 round key dari master key

    S-box dan round key dibangun sekali waktu objek dibuat, jadi satu objek bisa
    dipakai berkali kali buat banyak blok dengan key yang sama

    Args:
        key (bytes): master key 16, 24, atau 32 byte (128, 192, 256-bit)
        rounds (int): jumlah ronde, default `ROUNDS` (16). Nilai lain cuma buat analisis

    Attributes:
        rounds (int): jumlah ronde yang dipakai
        sbox (tk_cipher.sbox.SBox): S-box dinamis hasil `generate_sbox(key)`
        round_keys (list[bytes]): `rounds + 1` round key, masing masing 16 byte

    Raises:
        InvalidKeyError: panjang key bukan 16, 24, atau 32 byte

    Example:
        >>> c = TKCipher(bytes(16))
        >>> ct = c.encrypt_block(b"sixteen byte msg")
        >>> c.decrypt_block(ct)
        b'sixteen byte msg'

    Note:
        Bikin objek lumayan mahal (sekitar 40 ms) karena S-box harus lolos filter
        kualitas, jadi simpan objeknya kalau mau enkripsi banyak blok
    """

    def __init__(self, key: bytes, rounds: int = ROUNDS) -> None:
        if len(key) not in KEY_SIZES:
            raise InvalidKeyError("key must be 16, 24, or 32 bytes")
        self.rounds = rounds
        self.sbox = generate_sbox(key)
        self.round_keys = expand_key(key, self.sbox, rounds)

    def encrypt_block(self, block: bytes) -> bytes:
        """Enkripsi satu blok 16 byte

        Tiap ronde: AddRoundKey, DiagonalTranspose, DynamicSub, RowRotator,
        ColumnCascade, lalu ditutup XOR dengan round key terakhir (whitening)

        Args:
            block (bytes): plaintext tepat 16 byte

        Returns:
            bytes: ciphertext 16 byte

        Raises:
            ValueError: panjang `block` bukan 16 byte

        Example:
            >>> len(TKCipher(bytes(16)).encrypt_block(bytes(16)))
            16
        """
        _check_block(block)
        s = list(block)
        for i in range(self.rounds):
            s = add_round_key(s, self.round_keys[i])
            s = diagonal_transpose(s)
            s = dynamic_sub(s, self.sbox.forward)
            s = row_rotator(s)
            s = column_cascade(s)
        s = add_round_key(s, self.round_keys[self.rounds])
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        """Dekripsi satu blok 16 byte, kebalikan dari `encrypt_block`

        Args:
            block (bytes): ciphertext tepat 16 byte

        Returns:
            bytes: plaintext 16 byte

        Raises:
            ValueError: panjang `block` bukan 16 byte

        Example:
            >>> c = TKCipher(bytes(32))
            >>> c.decrypt_block(c.encrypt_block(bytes(16))) == bytes(16)
            True
        """
        _check_block(block)
        s = add_round_key(list(block), self.round_keys[self.rounds])
        for i in range(self.rounds - 1, -1, -1):
            s = inv_column_cascade(s)
            s = inv_row_rotator(s)
            s = dynamic_sub(s, self.sbox.inverse)
            s = diagonal_transpose(s)
            s = add_round_key(s, self.round_keys[i])
        return bytes(s)


def _check_block(block: bytes) -> None:
    if len(block) != BLOCK_SIZE:
        raise ValueError("block must be 16 bytes")
