"""TKCipher, enkripsi dan dekripsi satu blok 16 byte"""

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
ROUNDS = 16


class TKCipher:
    """Block cipher 128-bit, key 16/24/32 byte (selain itu InvalidKeyError)
    S-box dan round key dibangun sekali di sini; rounds selain 16 cuma buat analisis.
    """

    def __init__(self, key: bytes, rounds: int = ROUNDS) -> None:
        if len(key) not in KEY_SIZES:
            raise InvalidKeyError("key must be 16, 24, or 32 bytes")
        self.rounds = rounds
        self.sbox = generate_sbox(key)
        self.round_keys = expand_key(key, self.sbox, rounds)

    def encrypt_block(self, block: bytes) -> bytes:
        """Enkripsi satu blok 16 byte, blok dengan panjang lain => ValueError"""
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
        """Dekripsi satu blok 16 byte, blok dengan panjang lain => ValueError"""
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
