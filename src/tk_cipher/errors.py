"""Exception hierarchy used by every module in tk_cipher."""


class TKCipherError(Exception):
    """Base class for all errors raised by tk_cipher.

    Catch this to handle any TK-Cipher failure in one place.

    Example:
        >>> try:
        ...     raise AuthenticationError("tag mismatch")
        ... except TKCipherError as exc:
        ...     print(type(exc).__name__)
        AuthenticationError
    """


class InvalidKeyError(TKCipherError):
    """The master key has a wrong length or is not valid hex.

    Raised for keys that are not 16, 24, or 32 bytes long, and for hex strings
    that cannot be parsed.
    """


class InvalidFormatError(TKCipherError):
    """The structure of a ciphertext file is wrong.

    Raised for a bad size, magic, version, mode, reserved field, or a length
    that does not match the header.
    """


class AuthenticationError(TKCipherError):
    """The MAC tag does not match.

    Raised when the key is wrong or the file was modified. No plaintext is
    produced when this happens.
    """


class PaddingError(TKCipherError):
    """The PKCS#7 padding is broken.

    Raised when unpadding data whose padding bytes are missing or inconsistent.
    """
