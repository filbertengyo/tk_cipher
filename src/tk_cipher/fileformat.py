"""Format file terenkripsi TK-Cipher yang self-describing, dengan verify-then-decrypt

Layout file: `header 32 byte | ciphertext N byte | tag CMAC 16 byte`, N kelipatan 16.
Dekripsi cukup pakai file dan master key karena mode dan IV ikut tersimpan
"""

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
    """Header 32 byte di awal file terenkripsi: mode, IV, dan panjang plaintext asli

    Layout `>4sBBH16sQ`: magic `TKC1`, version, mode, reserved 0, IV 16 byte,
    panjang plaintext uint64 big-endian

    Args:
        mode (Mode): mode enkripsi yang dipakai
        iv (bytes): IV 16 byte, ECB pakai 16 byte nol
        original_length (int): panjang plaintext sebelum padding
        version (int): versi format file, sekarang 1

    Raises:
        ValueError: metadata tidak sesuai format waktu `pack`

    Example:
        >>> len(Header(Mode.ECB, bytes(16), 0).pack())
        32
    """

    mode: Mode
    iv: bytes
    original_length: int
    version: int = _VERSION

    def pack(self) -> bytes:
        """Ubah header jadi 32 byte sesuai layout file

        Returns:
            bytes: header 32 byte

        Raises:
            ValueError: versi, mode, panjang IV, atau `original_length` tidak valid,
                atau ECB dengan IV bukan nol

        Example:
            >>> Header(Mode.CBC, bytes(16), 5).pack()[:6]
            b'TKC1\\x01\\x01'
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
        """Baca header 32 byte dan validasi magic, versi, mode, dan reserved

        Args:
            data (bytes): header 32 byte dari awal file

        Returns:
            Header: objek header hasil parsing

        Raises:
            InvalidFormatError: panjang bukan 32 byte atau field tidak valid

        Example:
            >>> h = Header(Mode.CTR, bytes(range(16)), 7)
            >>> Header.unpack(h.pack()) == h
            True
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
    """Enkripsi plaintext jadi blob `header | ciphertext | tag` (Encrypt-then-MAC)

    Key enkripsi dan key MAC diturunin dari `master_key` lewat `derive_keys`,
    plaintext di-pad PKCS#7, dienkripsi dengan `mode`, lalu header dan ciphertext
    diautentikasi pakai CMAC

    Args:
        plaintext (bytes): data yang mau dienkripsi, boleh kosong
        master_key (bytes): master key 16, 24, atau 32 byte
        mode (Mode): mode operasi
        iv (bytes | None): IV 16 byte. `None` artinya IV acak dari `os.urandom`.
            Harus `None` untuk ECB

    Returns:
        bytes: header 32 byte, ciphertext, dan tag CMAC 16 byte

    Raises:
        ValueError: mode tidak dikenal, IV dikasih buat ECB, atau panjang IV bukan 16
        InvalidKeyError: panjang master key tidak didukung

    Example:
        >>> blob = encrypt_bytes(b"hello", bytes(16), Mode.CTR, bytes(16))
        >>> len(blob)
        64
        >>> decrypt_bytes(blob, bytes(16))
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
    """Verifikasi tag dulu, baru dekripsi blob hasil `encrypt_bytes`

    Urutannya: cek struktur, turunin key, cek tag constant time, dekripsi,
    `unpad`, lalu cek panjang plaintext dengan header. Kalau tag salah tidak ada
    plaintext yang dihasilkan sama sekali

    Args:
        blob (bytes): isi file terenkripsi lengkap
        master_key (bytes): master key 16, 24, atau 32 byte

    Returns:
        bytes: plaintext asli

    Raises:
        InvalidFormatError: blob terlalu pendek, panjang tidak pas, header rusak,
            padding rusak, atau panjang plaintext beda dengan header
        AuthenticationError: tag tidak cocok, artinya key salah atau file diubah
        InvalidKeyError: panjang master key tidak didukung

    Example:
        >>> blob = encrypt_bytes(b"secret", bytes(16), Mode.CBC)
        >>> decrypt_bytes(blob, bytes(16))
        b'secret'
        >>> decrypt_bytes(blob, bytes([1]) * 16)
        Traceback (most recent call last):
        ...
        tk_cipher.errors.AuthenticationError: MAC verification failed: wrong key or file has been modified

    Note:
        Pesan error sama untuk key salah dan file rusak, biar tidak bocorin info
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
    """Enkripsi file dan tulis hasilnya secara atomik

    Baca `src` sebagai biner, panggil `encrypt_bytes`, tulis ke file sementara di
    folder `dst`, lalu `os.replace` ke `dst`

    Args:
        src (pathlib.Path): file plaintext
        dst (pathlib.Path): file tujuan ciphertext
        master_key (bytes): master key 16, 24, atau 32 byte
        mode (Mode): mode operasi
        iv (bytes | None): IV 16 byte, `None` buat IV acak, harus `None` untuk ECB

    Returns:
        Header: header yang ditulis, termasuk IV yang dipakai

    Raises:
        OSError: gagal baca atau tulis file
        ValueError: mode atau IV tidak valid
        InvalidKeyError: panjang master key tidak didukung

    Example:
        >>> import tempfile, pathlib
        >>> d = pathlib.Path(tempfile.mkdtemp())
        >>> _ = (d / "a.txt").write_bytes(b"hi")
        >>> encrypt_file(d / "a.txt", d / "a.enc", bytes(16), Mode.CBC).mode.name
        'CBC'
    """
    blob = encrypt_bytes(src.read_bytes(), master_key, mode, iv)
    header = Header.unpack(blob[:_HEADER_SIZE])
    _atomic_write(dst, blob)
    return header


def decrypt_file(src: Path, dst: Path, master_key: bytes) -> Header:
    """Verifikasi dan dekripsi file, lalu tulis plaintext secara atomik

    Kalau verifikasi atau dekripsi gagal, `dst` tidak dibuat dan file yang sudah
    ada tidak diubah

    Args:
        src (pathlib.Path): file ciphertext
        dst (pathlib.Path): file tujuan plaintext

        master_key (bytes): master key 16, 24, atau 32 byte

    Returns:
        Header: header dari file ciphertext

    Raises:
        OSError: gagal baca atau tulis file
        InvalidFormatError: struktur file atau plaintext tidak valid
        AuthenticationError: tag tidak cocok dengan key atau isi file
        InvalidKeyError: panjang master key tidak didukung

    Example:
        >>> import tempfile, pathlib
        >>> d = pathlib.Path(tempfile.mkdtemp())
        >>> _ = (d / "a.txt").write_bytes(b"hi")
        >>> _ = encrypt_file(d / "a.txt", d / "a.enc", bytes(16), Mode.OFB)
        >>> _ = decrypt_file(d / "a.enc", d / "b.txt", bytes(16))
        >>> (d / "b.txt").read_bytes()
        b'hi'
    """
    blob = src.read_bytes()
    plaintext = decrypt_bytes(blob, master_key)
    header = Header.unpack(blob[:_HEADER_SIZE])
    _atomic_write(dst, plaintext)
    return header
