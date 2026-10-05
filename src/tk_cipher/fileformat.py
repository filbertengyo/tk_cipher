"""Format file terenkripsi TK-Cipher."""

import os
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

from tk_cipher.cipher import BLOCK_SIZE, TKCipher
from tk_cipher.errors import AuthenticationError, InvalidFormatError, PaddingError
from tk_cipher.kdf import derive_keys
from tk_cipher.mac import cmac, constant_time_eq
from tk_cipher.modes import Mode, decrypt, encrypt
from tk_cipher.padding import pad, unpad

_MAGIC = b"TKC1"
_VERSION = 1
_HEADER_FORMAT = ">4sBBH16sQ"
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
_TAG_SIZE = BLOCK_SIZE
_AUTHENTICATION_ERROR = "MAC verification failed: wrong key or file has been modified"


@dataclass(frozen=True)
class Header:
    """Header file: mode, IV, dan panjang plaintext asli.

    Args:
        mode: Mode enkripsi yang dipakai.
        iv: IV 16 byte; ECB memakai 16 byte nol.
        original_length: Panjang plaintext sebelum padding.
        version: Versi format file, saat ini 1.

    Raises:
        ValueError: Metadata tidak sesuai format file.

    Example:
        >>> len(Header(Mode.ECB, bytes(16), 0).pack())
        32
    """

    mode: Mode
    iv: bytes
    original_length: int
    version: int = _VERSION

    def pack(self) -> bytes:
        """Ubah header menjadi 32 byte sesuai format file.

        Returns:
            Header dalam bentuk bytes.

        Raises:
            ValueError: Versi, mode, IV, atau panjang tidak valid.
        """
        try:
            mode = Mode(self.mode)
        except (TypeError, ValueError) as exc:
            raise ValueError("Unsupported cipher mode") from exc
        if self.version != _VERSION:
            raise ValueError("Unsupported file format version")
        if len(self.iv) != BLOCK_SIZE:
            raise ValueError("IV must be exactly 16 bytes")
        if not 0 <= self.original_length < (1 << 64):
            raise ValueError("Original length must fit in an unsigned 64-bit integer")
        if mode == Mode.ECB and self.iv != bytes(BLOCK_SIZE):
            raise ValueError("ECB header IV must contain 16 zero bytes")
        return struct.pack(
            _HEADER_FORMAT,
            _MAGIC,
            self.version,
            int(mode),
            0,
            self.iv,
            self.original_length,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Header":
        """Baca header 32 byte dan validasi isinya.

        Args:
            data: Header hasil serialisasi.

        Returns:
            Objek Header dari data.

        Raises:
            InvalidFormatError: Header rusak atau format tidak didukung.
        """
        if len(data) != _HEADER_SIZE:
            raise InvalidFormatError("Header must be exactly 32 bytes")
        magic, version, mode_value, reserved, iv, original_length = struct.unpack(
            _HEADER_FORMAT, data
        )
        if magic != _MAGIC or version != _VERSION or reserved != 0:
            raise InvalidFormatError("Invalid file header")
        try:
            mode = Mode(mode_value)
        except ValueError as exc:
            raise InvalidFormatError("Unsupported cipher mode") from exc
        return cls(mode, iv, original_length, version)


def encrypt_bytes(
    plaintext: bytes, master_key: bytes, mode: Mode, iv: bytes | None = None
) -> bytes:
    """Enkripsi plaintext dan tambahkan tag CMAC.

    Args:
        plaintext: Data yang akan dienkripsi.
        master_key: Kunci utama TK-Cipher.
        mode: Mode blok yang digunakan.
        iv: IV 16 byte; dibuat acak jika tidak diberikan.

    Returns:
        Header, ciphertext, dan tag CMAC 16 byte.

    Raises:
        ValueError: Mode atau IV tidak valid.
        InvalidKeyError: Panjang master key tidak didukung.

    Example:
        >>> decrypt_bytes(encrypt_bytes(b"hello", bytes(16), Mode.CTR, bytes(16)), bytes(16))
        b'hello'
    """
    try:
        mode = Mode(mode)
    except (TypeError, ValueError) as exc:
        raise ValueError("Unsupported cipher mode") from exc

    if mode == Mode.ECB:
        if iv is not None:
            raise ValueError("ECB mode does not accept an IV")
        file_iv = bytes(BLOCK_SIZE)
        mode_iv = None
    else:
        file_iv = os.urandom(BLOCK_SIZE) if iv is None else iv
        if len(file_iv) != BLOCK_SIZE:
            raise ValueError("IV must be exactly 16 bytes")
        mode_iv = file_iv

    k_enc, k_mac = derive_keys(master_key)
    header = Header(mode, file_iv, len(plaintext)).pack()
    ciphertext = encrypt(TKCipher(k_enc), mode, pad(plaintext, BLOCK_SIZE), mode_iv)
    authenticated = header + ciphertext
    return authenticated + cmac(k_mac, authenticated)


def decrypt_bytes(blob: bytes, master_key: bytes) -> bytes:
    """Verifikasi tag sebelum mendekripsi ciphertext.

    Args:
        blob: Header, ciphertext, dan tag dari file.
        master_key: Master key TK-Cipher.

    Returns:
        Plaintext asli.

    Raises:
        InvalidFormatError: Struktur, padding, atau panjang plaintext tidak valid.
        AuthenticationError: Tag tidak cocok dengan key atau isi file.
        InvalidKeyError: Panjang master key tidak didukung.
    """
    if len(blob) < _HEADER_SIZE + BLOCK_SIZE + _TAG_SIZE:
        raise InvalidFormatError("Encrypted file is too short")
    if (len(blob) - _HEADER_SIZE - _TAG_SIZE) % BLOCK_SIZE != 0:
        raise InvalidFormatError("Ciphertext length is not block aligned")

    header_bytes = blob[:_HEADER_SIZE]
    header = Header.unpack(header_bytes)
    ciphertext = blob[_HEADER_SIZE:-_TAG_SIZE]
    tag = blob[-_TAG_SIZE:]

    k_enc, k_mac = derive_keys(master_key)
    if not constant_time_eq(tag, cmac(k_mac, header_bytes + ciphertext)):
        raise AuthenticationError(_AUTHENTICATION_ERROR)

    mode_iv = None if header.mode == Mode.ECB else header.iv
    padded_plaintext = decrypt(TKCipher(k_enc), header.mode, ciphertext, mode_iv)
    try:
        plaintext = unpad(padded_plaintext, BLOCK_SIZE)
    except PaddingError as exc:
        raise InvalidFormatError("Invalid decrypted padding") from exc
    if len(plaintext) != header.original_length:
        raise InvalidFormatError("Plaintext length does not match file header")
    return plaintext


def _atomic_write(dst: Path, data: bytes) -> None:
    """Tulis ke file sementara lalu ganti file tujuan."""
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=dst.parent, delete=False) as temporary:
            temporary_path = temporary.name
            temporary.write(data)
        os.replace(temporary_path, dst)
    except BaseException:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
        raise


def encrypt_file(
    src: Path, dst: Path, master_key: bytes, mode: Mode, iv: bytes | None = None
) -> Header:
    """Enkripsi file dan simpan hasilnya secara atomik.

    Args:
        src: Path file plaintext.
        dst: Path tujuan ciphertext.
        master_key: Master key TK-Cipher.
        mode: Mode blok yang digunakan.
        iv: IV 16 byte; dibuat acak jika tidak diberikan.

    Returns:
        Header yang disimpan bersama ciphertext.

    Raises:
        OSError: Gagal membaca atau menulis file.
        ValueError: Mode atau IV tidak valid.
        InvalidKeyError: Panjang master key tidak didukung.
    """
    blob = encrypt_bytes(src.read_bytes(), master_key, mode, iv)
    header = Header.unpack(blob[:_HEADER_SIZE])
    _atomic_write(dst, blob)
    return header


def decrypt_file(src: Path, dst: Path, master_key: bytes) -> Header:
    """Verifikasi dan dekripsi file, lalu simpan plaintext secara atomik.

    File tujuan tidak diubah jika verifikasi atau dekripsi gagal.

    Args:
        src: Path file ciphertext.
        dst: Path tujuan plaintext.
        master_key: Master key TK-Cipher.

    Returns:
        Header dari file ciphertext.

    Raises:
        OSError: Gagal membaca atau menulis file.
        InvalidFormatError: Struktur file atau plaintext tidak valid.
        AuthenticationError: Tag tidak cocok dengan key atau isi file.
        InvalidKeyError: Panjang master key tidak didukung.
    """
    blob = src.read_bytes()
    plaintext = decrypt_bytes(blob, master_key)
    header = Header.unpack(blob[:_HEADER_SIZE])
    _atomic_write(dst, plaintext)
    return header
