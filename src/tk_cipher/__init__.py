"""TK-Cipher: block cipher SPN 128-bit buatan sendiri plus program enkripsi file

Modul utama:

- `tk_cipher.fileformat`: enkripsi dan dekripsi bytes atau file lengkap dengan MAC,
  ini yang paling sering dipakai
- `tk_cipher.cipher`: `TKCipher`, block cipher satu blok 16 byte
- `tk_cipher.modes`: mode ECB, CBC, CFB, OFB, CTR
- `tk_cipher.padding`: padding PKCS#7
- `tk_cipher.kdf` dan `tk_cipher.mac`: KDF dan CMAC-TK buat Encrypt-then-MAC
- `tk_cipher.sbox`, `tk_cipher.key_schedule`, `tk_cipher.rounds`, `tk_cipher.prng`:
  komponen internal cipher
- `tk_cipher.cli`: command line `tk-cipher`
- `tk_cipher.errors`: semua exception

Example:
    >>> from tk_cipher.fileformat import encrypt_bytes, decrypt_bytes
    >>> from tk_cipher.modes import Mode
    >>> key = bytes(16)
    >>> decrypt_bytes(encrypt_bytes(b"halo", key, Mode.CBC), key)
    b'halo'

Note:
    Semua kriptografi ditulis sendiri, tanpa `hashlib`, `hmac`, atau library crypto lain
"""

__version__ = "0.1.0"
