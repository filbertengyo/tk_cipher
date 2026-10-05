# Test Vector TK-Cipher

Dihasilkan dari `TKCipher` (16 ronde). Sumber: `tests/vectors.json`, dicek oleh `tests/test_cipher.py` (T-04).

| Key | Plaintext | Ciphertext | DU | NL | Attempts |
| --- | --- | --- | --- | --- | --- |
| 128-bit `000102030405060708090a0b0c0d0e0f` | `00112233445566778899aabbccddeeff` | `9dc8f80581c878ae5f95b6ffc2d3b86b` | 12 | 94 | 1 |
| 192-bit `000102030405060708090a0b0c0d0e0f1011121314151617` | `00112233445566778899aabbccddeeff` | `ea4f7ee0b96f039fb5a74f5bb2b64afa` | 12 | 94 | 1 |
| 256-bit `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` | `00112233445566778899aabbccddeeff` | `fae80ec4357c9a7c027afd53f3747b32` | 12 | 96 | 1 |
