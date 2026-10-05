"""Authenticated file format and file helpers for TK-Cipher."""

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
    """Metadata stored at the start of an encrypted TK-Cipher file.

    Args:
        mode: Block mode used to encrypt the file.
        iv: 16-byte initialization vector, or all zeros for ECB.
        original_length: Length of the unpadded plaintext in bytes.
        version: Format version (currently 1).

    Raises:
        ValueError: If the metadata cannot be represented by the file format.

    Example:
        >>> len(Header(Mode.ECB, bytes(16), 0).pack())
        32
    """

    mode: Mode
    iv: bytes
    original_length: int
    version: int = _VERSION

    def pack(self) -> bytes:
        """Serialize this header as the format's 32-byte big-endian header.

        Returns:
            The packed header bytes.

        Raises:
            ValueError: If the version, mode, IV, or length is invalid.
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
        """Parse and validate a 32-byte file header.

        Args:
            data: Serialized header bytes.

        Returns:
            The validated header.

        Raises:
            InvalidFormatError: If the header is malformed or unsupported.
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
    """Encrypt and authenticate plaintext in the TK-Cipher file format.

    Args:
        plaintext: Data to encrypt; empty data is supported.
        master_key: A supported TK-Cipher master key.
        mode: Block mode to use.
        iv: Optional 16-byte IV. A random IV is generated when omitted.

    Returns:
        A complete header, ciphertext, and 16-byte CMAC tag.

    Raises:
        ValueError: If the mode or IV arguments are invalid.
        InvalidKeyError: If the master key has an unsupported length.

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
    """Authenticate a file-format blob before decrypting its ciphertext.

    Args:
        blob: Complete header, ciphertext, and tag.
        master_key: The TK-Cipher master key used during encryption.

    Returns:
        The original plaintext.

    Raises:
        InvalidFormatError: If the blob structure or decrypted padding/length is invalid.
        AuthenticationError: If the tag does not match the supplied key and data.
        InvalidKeyError: If the master key has an unsupported length.
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
    """Write bytes beside the destination and atomically replace it."""
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
    """Encrypt a file and atomically write its authenticated representation.

    Args:
        src: Source plaintext path.
        dst: Destination encrypted path.
        master_key: TK-Cipher master key.
        mode: Block mode to use.
        iv: Optional 16-byte IV, generated randomly when omitted.

    Returns:
        The header written with the encrypted file.

    Raises:
        OSError: If reading or atomically writing either path fails.
        ValueError: If mode or IV arguments are invalid.
        InvalidKeyError: If the master key has an unsupported length.
    """
    blob = encrypt_bytes(src.read_bytes(), master_key, mode, iv)
    header = Header.unpack(blob[:_HEADER_SIZE])
    _atomic_write(dst, blob)
    return header


def decrypt_file(src: Path, dst: Path, master_key: bytes) -> Header:
    """Authenticate, decrypt, and atomically write a file's plaintext.

    The destination is not created or modified unless authentication and
    decryption both succeed.

    Args:
        src: Source encrypted path.
        dst: Destination plaintext path.
        master_key: TK-Cipher master key.

    Returns:
        The header read from the encrypted file.

    Raises:
        OSError: If reading or atomically writing either path fails.
        InvalidFormatError: If the input structure or decrypted data is invalid.
        AuthenticationError: If authentication fails.
        InvalidKeyError: If the master key has an unsupported length.
    """
    blob = src.read_bytes()
    plaintext = decrypt_bytes(blob, master_key)
    header = Header.unpack(blob[:_HEADER_SIZE])
    _atomic_write(dst, plaintext)
    return header
