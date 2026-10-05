"""KDF TK-Cipher: turunin key enkripsi dan key MAC terpisah dari master key"""

from tk_cipher.cipher import TKCipher
from tk_cipher.sbox import KEY_SIZES

_KDF_PREFIX = b"TKC--KDF"


def derive_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """Turunin key enkripsi dan key MAC dari master key 128, 192, atau 256-bit

    TK-Cipher dengan key `master_key` dipakai sebagai PRF buat mengenkripsi blok
    counter `b"TKC--KDF" | label | 6 byte nol | counter`. Label 0x01 buat enkripsi
    dan 0x02 buat MAC, jadi dua key itu terpisah domainnya

    Args:
        master_key (bytes): master key 16, 24, atau 32 byte

    Returns:
        tuple[bytes, bytes]: pasangan `(k_enc, k_mac)`, panjang masing masing sama
        dengan `master_key`

    Raises:
        InvalidKeyError: panjang `master_key` bukan 16, 24, atau 32 byte

    Example:
        >>> k_enc, k_mac = derive_keys(bytes(16))
        >>> len(k_enc) == len(k_mac) == 16
        True
        >>> k_enc != k_mac
        True

    Note:
        Deterministik, master key sama selalu menghasilkan pasangan key yang sama
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
