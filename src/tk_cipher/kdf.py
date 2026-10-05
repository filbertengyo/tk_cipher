"""Derive purpose-specific keys from a TK-Cipher master key."""

from tk_cipher.cipher import TKCipher
from tk_cipher.sbox import KEY_SIZES

_KDF_PREFIX = b"TKC--KDF"


def derive_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """Derive encryption and MAC keys from a 128/192/256-bit master key.

    The derivation encrypts domain-separated counter blocks with TK-Cipher
    keyed by ``master_key``. Labels 0x01 and 0x02 separate the two purposes.

    Args:
        master_key: A 16-, 24-, or 32-byte TK-Cipher key.

    Returns:
        A pair ``(k_enc, k_mac)``, each the same length as ``master_key``.

    Raises:
        InvalidKeyError: If ``master_key`` has an unsupported length.

    Example:
        >>> k_enc, k_mac = derive_keys(bytes(16))
        >>> len(k_enc) == len(k_mac) == 16
        True
    """
    if len(master_key) not in KEY_SIZES:
        # Let TKCipher provide the package's standard invalid-key exception.
        TKCipher(master_key)

    cipher = TKCipher(master_key)
    length = len(master_key)

    def derive(label: int) -> bytes:
        output = bytearray()
        for counter in range(2):
            block = _KDF_PREFIX + bytes([label]) + bytes(6) + bytes([counter])
            output.extend(cipher.encrypt_block(block))
        return bytes(output[:length])

    return derive(0x01), derive(0x02)
