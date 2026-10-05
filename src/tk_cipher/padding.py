"""Padding PKCS#7 buat data yang panjangnya bukan kelipatan blok"""

from tk_cipher.errors import PaddingError


def pad(data: bytes, block_size: int = 16) -> bytes:
    """Tambah padding PKCS#7 sampai panjang data kelipatan `block_size`

    Selalu nambah minimal 1 byte. Data yang sudah pas kelipatan blok dapat 1 blok
    padding penuh, jadi `unpad` selalu tahu berapa byte yang harus dibuang

    Args:
        data (bytes): data asli, boleh kosong
        block_size (int): ukuran blok 1 sampai 255, default 16

    Returns:
        bytes: data plus `p` byte bernilai `p`, dengan 1 <= p <= block_size

    Raises:
        ValueError: `block_size` di luar 1 sampai 255

    Example:
        >>> pad(b"abc", 4)
        b'abc\\x01'
        >>> len(pad(bytes(16)))
        32
    """

    if block_size < 1 or block_size > 255:
        raise ValueError("Block size must be between 1-255")

    pad_size = block_size - len(data) % block_size

    return data + pad_size.to_bytes(1, "little") * pad_size


def unpad(data: bytes, block_size: int = 16) -> bytes:
    """Buang padding PKCS#7 dan cek bahwa padding-nya valid

    Args:
        data (bytes): data ber-padding, panjangnya kelipatan `block_size`
        block_size (int): ukuran blok 1 sampai 255, default 16

    Returns:
        bytes: data asli tanpa padding

    Raises:
        ValueError: `block_size` di luar 1 sampai 255
        PaddingError: data kosong, panjang bukan kelipatan blok, byte terakhir 0,
            atau byte padding tidak seragam

    Example:
        >>> unpad(b"abc\\x01", 4)
        b'abc'
        >>> unpad(pad(b"hello"))
        b'hello'
    """

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
