"""Fungsi-fungsi padding dengan pkcs7"""

from tk_cipher.errors import PaddingError


def pad(data: bytes, block_size: int = 16) -> bytes:
    """Menambahkan padding standar pkcs7 berdasarkan ukuran blok"""

    if block_size < 1 or block_size > 255:
        raise ValueError("Block size must be between 1-255")

    pad_size = block_size - len(data) % block_size

    return data + pad_size.to_bytes(1, "little") * pad_size


def unpad(data: bytes, block_size: int = 16) -> bytes:
    """Menghapus padding standar pkcs7"""

    if block_size < 1 or block_size > 255:
        raise ValueError("Block size must be between 1-255")

    if len(data) <= 0:
        raise PaddingError("Data cannot be empty")

    if len(data) % block_size != 0:
        raise PaddingError("Data length has to be a multiple of block size")

    pad_size = data[-1]

    if pad_size < 1:
        raise PaddingError("Padding size (final byte) cannot be 0")

    for byte in data[-pad_size:]:
        if byte != pad_size:
            raise PaddingError("Padding bytes have to equal padding size")

    return data[:-pad_size]
