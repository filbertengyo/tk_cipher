"""CMAC authentication and constant-time tag comparison for TK-Cipher."""

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
    """Compute a 16-byte CMAC (OMAC1) tag using TK-Cipher.

    Args:
        key: A 16-, 24-, or 32-byte TK-Cipher key.
        message: The bytes to authenticate.

    Returns:
        A 16-byte authentication tag.

    Raises:
        InvalidKeyError: If ``key`` has an unsupported length.

    Example:
        >>> len(cmac(bytes(16), b"message"))
        16
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
    """Compare byte strings without returning early on a mismatch.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        ``True`` when the values and lengths match, otherwise ``False``.

    Example:
        >>> constant_time_eq(b"tag", b"tag")
        True
    """
    diff = len(a) ^ len(b)
    # Iterate to the longer length, substituting zero for missing bytes, so
    # differing lengths do not cause an early exit from the comparison loop.
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        diff |= x ^ y
    return diff == 0
