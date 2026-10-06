"""Lima mode operasi TK-Cipher: ECB, CBC, CFB, OFB, CTR, semua full block 128-bit"""

from enum import IntEnum

from tk_cipher.cipher import BLOCK_SIZE, TKCipher


class Mode(IntEnum):
    """Mode operasi, nilainya sama dengan byte mode di header file

    Example:
        >>> Mode(1).name
        'CBC'
    """

    ECB = 0
    CBC = 1
    CFB = 2
    OFB = 3
    CTR = 4


def encrypt_ecb(cipher: TKCipher, data: bytes) -> bytes:
    """Enkripsi data pakai mode ECB, tiap blok diproses sendiri sendiri

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): plaintext, panjang kelipatan 16 byte

    Returns:
        bytes: ciphertext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `encrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> decrypt_ecb(c, encrypt_ecb(c, bytes(32))) == bytes(32)
        True

    Note:
        Tidak butuh IV. Pola plaintext bocor, jangan dipakai buat data berpola
    """

    ciphertext = b""

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        ciphertext += cipher.encrypt_block(block)

    return ciphertext


def decrypt_ecb(cipher: TKCipher, data: bytes) -> bytes:
    """Dekripsi data pakai mode ECB, tiap blok diproses sendiri sendiri

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): ciphertext, panjang kelipatan 16 byte

    Returns:
        bytes: plaintext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `decrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> encrypt_ecb(c, decrypt_ecb(c, bytes(32))) == bytes(32)
        True

    Note:
        Tidak butuh IV. Pola plaintext bocor, jangan dipakai buat data berpola
    """

    plaintext = b""

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        plaintext += cipher.decrypt_block(block)

    return plaintext


def encrypt_cbc(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Enkripsi data pakai mode CBC: `C_i = E(P_i ^ C_{i-1})` dengan `C_{-1} = iv`

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): plaintext, panjang kelipatan 16 byte
        iv (bytes): IV 16 byte

    Returns:
        bytes: ciphertext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `encrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> decrypt_cbc(c, encrypt_cbc(c, bytes(32), bytes(16)), bytes(16)) == bytes(32)
        True

    Note:
        IV harus acak dan tidak dipakai ulang
    """

    ciphertext = b""
    previous_ciphertext = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = bytes([a ^ b for a, b in zip(block, previous_ciphertext)])
        previous_ciphertext = cipher.encrypt_block(intermediate_text)
        ciphertext += previous_ciphertext

    return ciphertext


def decrypt_cbc(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Dekripsi data pakai mode CBC: `C_i = E(P_i ^ C_{i-1})` dengan `C_{-1} = iv`

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): ciphertext, panjang kelipatan 16 byte
        iv (bytes): IV 16 byte

    Returns:
        bytes: plaintext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `decrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> encrypt_cbc(c, decrypt_cbc(c, bytes(32), bytes(16)), bytes(16)) == bytes(32)
        True

    Note:
        IV harus acak dan tidak dipakai ulang
    """

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
    """Enkripsi data pakai mode CFB: `C_i = P_i ^ E(C_{i-1})` dengan `C_{-1} = iv`

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): plaintext, panjang kelipatan 16 byte
        iv (bytes): IV 16 byte

    Returns:
        bytes: ciphertext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `encrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> decrypt_cfb(c, encrypt_cfb(c, bytes(32), bytes(16)), bytes(16)) == bytes(32)
        True

    Note:
        Cuma butuh `encrypt_block`, dekripsi juga pakai enkripsi blok
    """

    ciphertext = b""
    previous_ciphertext = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(previous_ciphertext)
        previous_ciphertext = bytes([a ^ b for a, b in zip(intermediate_text, block)])
        ciphertext += previous_ciphertext

    return ciphertext


def decrypt_cfb(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Dekripsi data pakai mode CFB: `C_i = P_i ^ E(C_{i-1})` dengan `C_{-1} = iv`

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): ciphertext, panjang kelipatan 16 byte
        iv (bytes): IV 16 byte

    Returns:
        bytes: plaintext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `decrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> encrypt_cfb(c, decrypt_cfb(c, bytes(32), bytes(16)), bytes(16)) == bytes(32)
        True

    Note:
        Cuma butuh `encrypt_block`, dekripsi juga pakai enkripsi blok
    """

    plaintext = b""
    previous_ciphertext = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(previous_ciphertext)
        plaintext += bytes([a ^ b for a, b in zip(intermediate_text, block)])
        previous_ciphertext = block

    return plaintext


def encrypt_ofb(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Enkripsi data pakai mode OFB, keystream `O_i = E(O_{i-1})` dari `iv` di-XOR ke data

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): plaintext, panjang kelipatan 16 byte
        iv (bytes): IV 16 byte

    Returns:
        bytes: ciphertext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `encrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> decrypt_ofb(c, encrypt_ofb(c, bytes(32), bytes(16)), bytes(16)) == bytes(32)
        True

    Note:
        Keystream tidak bergantung plaintext, IV yang sama dengan key sama bikin keystream bocor
    """

    ciphertext = b""
    previous_vector = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(previous_vector)
        previous_vector = intermediate_text
        ciphertext += bytes([a ^ b for a, b in zip(intermediate_text, block)])

    return ciphertext


def decrypt_ofb(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Dekripsi data pakai mode OFB, keystream `O_i = E(O_{i-1})` dari `iv` di-XOR ke data

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): ciphertext, panjang kelipatan 16 byte
        iv (bytes): IV 16 byte

    Returns:
        bytes: plaintext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `decrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> encrypt_ofb(c, decrypt_ofb(c, bytes(32), bytes(16)), bytes(16)) == bytes(32)
        True

    Note:
        Keystream tidak bergantung plaintext, IV yang sama dengan key sama bikin keystream bocor
    """

    plaintext = b""
    previous_vector = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(previous_vector)
        previous_vector = intermediate_text
        plaintext += bytes([a ^ b for a, b in zip(intermediate_text, block)])

    return plaintext


def encrypt_ctr(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Enkripsi data pakai mode CTR: `C_i = P_i ^ E(iv + i mod 2^128)`, counter big-endian

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): plaintext, panjang kelipatan 16 byte
        iv (bytes): IV 16 byte (counter awal)

    Returns:
        bytes: ciphertext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `encrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> decrypt_ctr(c, encrypt_ctr(c, bytes(32), bytes(16)), bytes(16)) == bytes(32)
        True

    Note:
        `iv` adalah counter awal, counter `ff..ff` wrap ke `00..00`
    """

    ciphertext = b""
    counter = int.from_bytes(iv, "big")

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(counter.to_bytes(BLOCK_SIZE, "big"))
        ciphertext += bytes([a ^ b for a, b in zip(intermediate_text, block)])
        counter = (counter + 1) % (1 << (BLOCK_SIZE * 8))

    return ciphertext


def decrypt_ctr(cipher: TKCipher, data: bytes, iv: bytes) -> bytes:
    """Dekripsi data pakai mode CTR: `C_i = P_i ^ E(iv + i mod 2^128)`, counter big-endian

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        data (bytes): ciphertext, panjang kelipatan 16 byte
        iv (bytes): IV 16 byte (counter awal)

    Returns:
        bytes: plaintext dengan panjang sama

    Raises:
        ValueError: blok tidak 16 byte. Fungsi ini tidak cek panjang data dan IV,
            pakai `decrypt` buat validasi lengkap

    Example:
        >>> c = TKCipher(bytes(16))
        >>> encrypt_ctr(c, decrypt_ctr(c, bytes(32), bytes(16)), bytes(16)) == bytes(32)
        True

    Note:
        `iv` adalah counter awal, counter `ff..ff` wrap ke `00..00`
    """

    plaintext = b""
    counter = int.from_bytes(iv, "big")

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        intermediate_text = cipher.encrypt_block(counter.to_bytes(BLOCK_SIZE, "big"))
        plaintext += bytes([a ^ b for a, b in zip(intermediate_text, block)])
        counter = (counter + 1) % (1 << (BLOCK_SIZE * 8))

    return plaintext


def encrypt(cipher: TKCipher, mode: Mode, data: bytes, iv: bytes | None) -> bytes:
    """Enkripsi data pakai mode yang dipilih, dengan validasi panjang data dan IV

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        mode (Mode): salah satu `Mode.ECB`, `CBC`, `CFB`, `OFB`, `CTR`
        data (bytes): plaintext, panjang kelipatan 16 byte dan tidak kosong. Pakai
            `tk_cipher.padding.pad` dulu kalau panjangnya belum pas
        iv (bytes | None): IV atau counter awal 16 byte, harus `None` untuk ECB

    Returns:
        bytes: ciphertext dengan panjang sama

    Raises:
        ValueError: data kosong atau bukan kelipatan 16, IV dikasih buat ECB, IV
            tidak ada buat mode lain, atau panjang IV bukan 16 byte

    Example:
        >>> c = TKCipher(bytes(16))
        >>> ct = encrypt(c, Mode.CTR, bytes(32), bytes(16))
        >>> decrypt(c, Mode.CTR, ct, bytes(16)) == bytes(32)
        True
    """

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
    """Dekripsi data pakai mode yang dipilih, dengan validasi panjang data dan IV

    Args:
        cipher (TKCipher): cipher yang sudah dibuat dengan key
        mode (Mode): salah satu `Mode.ECB`, `CBC`, `CFB`, `OFB`, `CTR`
        data (bytes): ciphertext, panjang kelipatan 16 byte dan tidak kosong. Pakai
            `tk_cipher.padding.pad` dulu kalau panjangnya belum pas
        iv (bytes | None): IV atau counter awal 16 byte, harus `None` untuk ECB

    Returns:
        bytes: plaintext dengan panjang sama

    Raises:
        ValueError: data kosong atau bukan kelipatan 16, IV dikasih buat ECB, IV
            tidak ada buat mode lain, atau panjang IV bukan 16 byte

    Example:
        >>> c = TKCipher(bytes(16))
        >>> ct = encrypt(c, Mode.CTR, bytes(32), bytes(16))
        >>> decrypt(c, Mode.CTR, ct, bytes(16)) == bytes(32)
        True
    """

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
