class TKCipherError(Exception):
    """Base class for all tk_cipher errors."""


class InvalidKeyError(TKCipherError):
    """Wrong key length or invalid hex."""


class InvalidFormatError(TKCipherError):
    """Malformed ciphertext file."""


class AuthenticationError(TKCipherError):
    """MAC tag mismatch."""


class PaddingError(TKCipherError):
    """Broken PKCS#7 padding."""
