"""CMAC-TK buat Encrypt-then-MAC dan perbandingan tag constant time"""

from tk_cipher.cipher import BLOCK_SIZE, TKCipher

_CMAC_RB = 0x87
_BLOCK_MASK = (1 << (BLOCK_SIZE * 8)) - 1


def _double(block: bytes) -> bytes:
    """Double a 128-bit CMAC subkey in GF(2^128)."""
    value = int.from_bytes(block, "big")
    carry = value >> 127
    value = (value << 1) & _BLOCK_MASK
    if carry:
        value ^= _CMAC_RB
    return value.to_bytes(BLOCK_SIZE, "big")


def cmac(key: bytes, message: bytes) -> bytes:
    """Hitung tag CMAC (OMAC1) 16 byte pakai TK-Cipher sebagai block cipher

    Subkey K1 dan K2 diturunin dari `E_K(0)` lewat doubling di GF(2^128). Blok
    terakhir yang penuh di-XOR K1, yang tidak penuh di-pad `0x80 00..` lalu di-XOR K2

    Args:
        key (bytes): key MAC 16, 24, atau 32 byte, biasanya `k_mac` dari `derive_keys`
        message (bytes): data yang mau diautentikasi, boleh kosong

    Returns:
        bytes: tag autentikasi 16 byte

    Raises:
        InvalidKeyError: panjang `key` bukan 16, 24, atau 32 byte

    Example:
        >>> len(cmac(bytes(16), b"message"))
        16
        >>> cmac(bytes(16), b"a") == cmac(bytes(16), b"b")
        False
    """
    cipher = TKCipher(key)
    zero = bytes(BLOCK_SIZE)
    k1 = _double(cipher.encrypt_block(zero))
    k2 = _double(k1)

    block_count = max(1, (len(message) + BLOCK_SIZE - 1) // BLOCK_SIZE)
    last_start = (block_count - 1) * BLOCK_SIZE
    last = message[last_start:]

    if len(message) > 0 and len(message) % BLOCK_SIZE == 0:
        final_block = bytes(a ^ b for a, b in zip(last, k1))
    else:
        padded = last + b"\x80" + bytes(BLOCK_SIZE - len(last) - 1)
        final_block = bytes(a ^ b for a, b in zip(padded, k2))

    state = zero
    for offset in range(0, last_start, BLOCK_SIZE):
        block = message[offset : offset + BLOCK_SIZE]
        state = cipher.encrypt_block(bytes(a ^ b for a, b in zip(state, block)))
    return cipher.encrypt_block(bytes(a ^ b for a, b in zip(state, final_block)))


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Bandingin dua bytes tanpa berhenti di byte pertama yang beda

    Dipakai buat cek tag MAC supaya waktu eksekusi tidak bocorin posisi byte yang salah

    Args:
        a (bytes): bytes pertama
        b (bytes): bytes kedua

    Returns:
        bool: `True` kalau isi dan panjangnya sama, selain itu `False`

    Example:
        >>> constant_time_eq(b"tag", b"tag")
        True
        >>> constant_time_eq(b"tag", b"tah")
        False
    """
    diff = len(a) ^ len(b)
    # Iterate to the longer length, substituting zero for missing bytes, so
    # differing lengths do not cause an early exit from the comparison loop.
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        diff |= x ^ y
    return diff == 0
