from enum import IntEnum

from tk_cipher.cipher import BLOCK_SIZE, TKCipher


class Mode(IntEnum):
    ECB = 0
    CBC = 1
    CFB = 2
    OFB = 3
    CTR = 4


def encrypt_ecb(cipher: TKCipher, data: bytes) -> bytes:
    """Encrypts bytes using ECB block mode"""

    ciphertext = b""

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        ciphertext += cipher.encrypt_block(block)

    return ciphertext


def decrypt_ecb(cipher: TKCipher, data: bytes) -> bytes:
    """Decrypts bytes using ECB block mode"""

    plaintext = b""

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        plaintext += cipher.decrypt_block(block)

    return plaintext


def encrypt_cbc(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Encrypts bytes using CBC block mode"""

    ciphertext = b""
    previous_ciphertext = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = bytes([a ^ b for a, b in zip(block, previous_ciphertext)])
        previous_ciphertext = cipher.encrypt_block(intermediate_text)
        ciphertext += previous_ciphertext

    return ciphertext


def decrypt_cbc(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Decrypts bytes using CBC block mode"""

    plaintext = b""
    previous_ciphertext = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.decrypt_block(block)
        plaintext += bytes(
            [a ^ b for a, b in zip(intermediate_text, previous_ciphertext)]
        )
        previous_ciphertext = block

    return plaintext


def encrypt_cfb(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Encrypts bytes using CFB block mode"""

    ciphertext = b""
    previous_ciphertext = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(previous_ciphertext)
        previous_ciphertext = bytes([a ^ b for a, b in zip(intermediate_text, block)])
        ciphertext += previous_ciphertext

    return ciphertext


def decrypt_cfb(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Decrypts bytes using CFB block mode"""

    plaintext = b""
    previous_ciphertext = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(previous_ciphertext)
        plaintext += bytes([a ^ b for a, b in zip(intermediate_text, block)])
        previous_ciphertext = block

    return plaintext


def encrypt_ofb(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Encrypts bytes using OFB block mode"""

    ciphertext = b""
    previous_vector = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(previous_vector)
        previous_vector = intermediate_text
        ciphertext += bytes([a ^ b for a, b in zip(intermediate_text, block)])

    return ciphertext


def decrypt_ofb(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Decrypts bytes using OFB block mode"""

    plaintext = b""
    previous_vector = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(previous_vector)
        previous_vector = intermediate_text
        plaintext += bytes([a ^ b for a, b in zip(intermediate_text, block)])

    return plaintext


def encrypt_ctr(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Encrypts bytes using CTR block mode"""

    ciphertext = b""
    counter = int.from_bytes(iv, "big")

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(counter.to_bytes(BLOCK_SIZE, "big"))
        ciphertext += bytes([a ^ b for a, b in zip(intermediate_text, block)])
        counter = (counter + 1) % (1 << (BLOCK_SIZE * 8))

    return ciphertext


def decrypt_ctr(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Decrypts bytes using CTR block mode"""

    plaintext = b""
    counter = int.from_bytes(iv, "big")

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(counter.to_bytes(BLOCK_SIZE, "big"))
        plaintext += bytes([a ^ b for a, b in zip(intermediate_text, block)])
        counter = (counter + 1) % (1 << (BLOCK_SIZE * 8))

    return plaintext


def encrypt(cipher: TKCipher, mode: Mode, data: bytes, iv: bytes | None) -> bytes:
    """Encrypts bytes using the specified block mode"""

    if len(data) % BLOCK_SIZE != 0 or len(data) == 0:
        raise ValueError(f"Data not aligned to cipher block size ({BLOCK_SIZE} bytes)")

    if mode == Mode.ECB:
        if iv != None:
            raise ValueError("Encryption with ECB does not use iv")
        return encrypt_ecb(cipher, data)

    if iv == None:
        raise ValueError(f"Encryption with {mode.name} requires iv")

    if len(iv) != BLOCK_SIZE:
        raise ValueError(
            f"IV value must be the same as block size ({BLOCK_SIZE} bytes)"
        )

    match mode:
        case Mode.CBC:
            return encrypt_cbc(cipher, data, iv)
        case Mode.CFB:
            return encrypt_cfb(cipher, data, iv)
        case Mode.OFB:
            return encrypt_ofb(cipher, data, iv)
        case Mode.CTR:
            return encrypt_ctr(cipher, data, iv)


def decrypt(cipher: TKCipher, mode: Mode, data: bytes, iv: bytes | None) -> bytes:
    """Decrypts bytes using the specified block mode"""

    if len(data) % BLOCK_SIZE != 0 or len(data) == 0:
        raise ValueError(f"Data not aligned to cipher block size ({BLOCK_SIZE} bytes)")

    if mode == Mode.ECB:
        if iv != None:
            raise ValueError("Decryption with ECB does not use iv")
        return decrypt_ecb(cipher, data)

    if iv == None:
        raise ValueError(f"Decryption with {mode.name} requires iv")

    if len(iv) != BLOCK_SIZE:
        raise ValueError(
            f"IV value must be the same as block size ({BLOCK_SIZE} bytes)"
        )

    match mode:
        case Mode.CBC:
            return decrypt_cbc(cipher, data, iv)
        case Mode.CFB:
            return decrypt_cfb(cipher, data, iv)
        case Mode.OFB:
            return decrypt_ofb(cipher, data, iv)
        case Mode.CTR:
            return decrypt_ctr(cipher, data, iv)
