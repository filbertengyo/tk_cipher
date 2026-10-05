"""Exception yang dipakai di seluruh package tk_cipher

Semua exception turunan `TKCipherError`, jadi caller bisa nangkep semuanya sekaligus

Example:
    >>> try:
    ...     raise AuthenticationError("tag mismatch")
    ... except TKCipherError as exc:
    ...     print(type(exc).__name__)
    AuthenticationError
"""


class TKCipherError(Exception):
    """Base class semua error tk_cipher"""


class InvalidKeyError(TKCipherError):
    """Panjang key salah atau string hex key tidak valid

    Dilempar oleh `TKCipher`, `generate_sbox`, `expand_key`, `derive_keys`, dan
    CLI (exit code 1)
    """


class InvalidFormatError(TKCipherError):
    """File ciphertext rusak: ukuran, magic, versi, mode, atau panjang plaintext tidak cocok

    Dipetakan ke exit code 2 di CLI
    """


class AuthenticationError(TKCipherError):
    """Tag CMAC tidak cocok, artinya key salah atau file sudah diubah

    Pesannya sengaja sama untuk dua kasus itu biar tidak bocorin info. Dipetakan ke
    exit code 3 di CLI
    """


class PaddingError(TKCipherError):
    """Padding PKCS#7 rusak waktu `unpad`"""
