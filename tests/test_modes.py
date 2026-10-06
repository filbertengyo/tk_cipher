import pytest

from tk_cipher.modes import Mode, decrypt, encrypt


class DummyCipher:
    """Mock TKCipher yang cuma geser byte +1 buat enkripsi dan -1 buat dekripsi"""

    def encrypt_block(self, block: bytes) -> bytes:
        return bytes((b + 1) % 256 for b in block)

    def decrypt_block(self, block: bytes) -> bytes:
        return bytes((b - 1) % 256 for b in block)


class SpyCipher(DummyCipher):
    """Spy buat ngecek CFB, OFB, CTR tidak pernah manggil decrypt_block"""

    def __init__(self):
        self.encrypt_calls = 0
        self.decrypt_calls = 0

    def encrypt_block(self, block: bytes) -> bytes:
        self.encrypt_calls += 1
        return super().encrypt_block(block)

    def decrypt_block(self, block: bytes) -> bytes:
        self.decrypt_calls += 1
        return super().decrypt_block(block)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR dua byte string"""
    return bytes(x ^ y for x, y in zip(a, b))


@pytest.fixture
def cipher():
    return DummyCipher()


@pytest.mark.parametrize("mode", [Mode.ECB, Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR])
@pytest.mark.parametrize("length", [16, 32, 48, 160])
@pytest.mark.parametrize("key_size", [128, 192, 256])
def test_round_trip(cipher, mode, length, key_size):
    data = bytes(i % 256 for i in range(length))
    iv = None if mode == Mode.ECB else bytes((i * 3) % 256 for i in range(16))

    ct = encrypt(cipher, mode, data, iv)
    pt = decrypt(cipher, mode, ct, iv)

    assert pt == data, f"Round-trip gagal untuk {mode.name} dengan panjang {length}"


def test_manual_calculation_cbc(cipher):
    p1, p2, p3 = b"\x11" * 16, b"\x22" * 16, b"\x33" * 16
    iv = b"\x00" * 16
    data = p1 + p2 + p3

    c1 = cipher.encrypt_block(xor_bytes(p1, iv))
    c2 = cipher.encrypt_block(xor_bytes(p2, c1))
    c3 = cipher.encrypt_block(xor_bytes(p3, c2))
    expected_ct = c1 + c2 + c3

    assert encrypt(cipher, Mode.CBC, data, iv) == expected_ct

    d1 = xor_bytes(cipher.decrypt_block(c1), iv)
    d2 = xor_bytes(cipher.decrypt_block(c2), c1)
    d3 = xor_bytes(cipher.decrypt_block(c3), c2)
    expected_pt = d1 + d2 + d3

    assert decrypt(cipher, Mode.CBC, expected_ct, iv) == expected_pt


def test_manual_calculation_cfb(cipher):
    p1, p2, p3 = b"\x11" * 16, b"\x22" * 16, b"\x33" * 16
    iv = b"\xaa" * 16
    data = p1 + p2 + p3

    c1 = xor_bytes(p1, cipher.encrypt_block(iv))
    c2 = xor_bytes(p2, cipher.encrypt_block(c1))
    c3 = xor_bytes(p3, cipher.encrypt_block(c2))
    expected_ct = c1 + c2 + c3

    assert encrypt(cipher, Mode.CFB, data, iv) == expected_ct

    d1 = xor_bytes(c1, cipher.encrypt_block(iv))
    d2 = xor_bytes(c2, cipher.encrypt_block(c1))
    d3 = xor_bytes(c3, cipher.encrypt_block(c2))
    expected_pt = d1 + d2 + d3

    assert decrypt(cipher, Mode.CFB, expected_ct, iv) == expected_pt


def test_manual_calculation_ofb(cipher):
    p1, p2, p3 = b"\x11" * 16, b"\x22" * 16, b"\x33" * 16
    iv = b"\xbb" * 16
    data = p1 + p2 + p3

    o1 = cipher.encrypt_block(iv)
    c1 = xor_bytes(p1, o1)
    o2 = cipher.encrypt_block(o1)
    c2 = xor_bytes(p2, o2)
    o3 = cipher.encrypt_block(o2)
    c3 = xor_bytes(p3, o3)
    expected_ct = c1 + c2 + c3

    assert encrypt(cipher, Mode.OFB, data, iv) == expected_ct
    assert (
        decrypt(cipher, Mode.OFB, expected_ct, iv) == data
    )  # Enkripsi & Dekripsi OFB sama


def test_manual_calculation_ctr(cipher):
    p1, p2, p3 = b"\x11" * 16, b"\x22" * 16, b"\x33" * 16
    iv = b"\x00" * 15 + b"\x05"
    data = p1 + p2 + p3

    c1 = xor_bytes(p1, cipher.encrypt_block((5).to_bytes(16, "big")))
    c2 = xor_bytes(p2, cipher.encrypt_block((6).to_bytes(16, "big")))
    c3 = xor_bytes(p3, cipher.encrypt_block((7).to_bytes(16, "big")))
    expected_ct = c1 + c2 + c3

    assert encrypt(cipher, Mode.CTR, data, iv) == expected_ct
    assert decrypt(cipher, Mode.CTR, expected_ct, iv) == data


def test_ctr_wraparound(cipher):
    iv = b"\xff" * 16
    p1, p2 = b"\xaa" * 16, b"\xbb" * 16
    data = p1 + p2

    ct = encrypt(cipher, Mode.CTR, data, iv)

    c1 = xor_bytes(p1, cipher.encrypt_block(b"\xff" * 16))
    c2 = xor_bytes(p2, cipher.encrypt_block(b"\x00" * 16))

    assert ct == c1 + c2

    pt = decrypt(cipher, Mode.CTR, ct, iv)
    assert pt == data


def test_validation_errors(cipher):
    with pytest.raises(ValueError):
        encrypt(cipher, Mode.ECB, b"", None)

    with pytest.raises(ValueError):
        encrypt(cipher, Mode.CBC, b"\x00" * 17, b"\x00" * 16)

    with pytest.raises(ValueError):
        encrypt(cipher, Mode.ECB, b"\x00" * 16, b"\x00" * 16)

    with pytest.raises(ValueError):
        encrypt(cipher, Mode.CBC, b"\x00" * 16, None)

    for mode in [Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR]:
        with pytest.raises(ValueError, match="16"):  # pastikan pesan error nyebut 16
            encrypt(cipher, mode, b"\x00" * 16, b"\x00" * 15)
        with pytest.raises(ValueError, match="16"):
            encrypt(cipher, mode, b"\x00" * 16, b"\x00" * 17)


@pytest.mark.parametrize("mode", [Mode.CFB, Mode.OFB, Mode.CTR])
def test_stream_modes_never_call_decrypt_block(mode):
    spy = SpyCipher()
    iv = b"\x00" * 16
    data = b"\x12" * 48

    ct = encrypt(spy, mode, data, iv)
    assert spy.decrypt_calls == 0, f"Enkripsi {mode.name} memanggil decrypt_block!"

    pt = decrypt(spy, mode, ct, iv)
    assert spy.decrypt_calls == 0, f"Dekripsi {mode.name} memanggil decrypt_block!"
    assert pt == data


def test_ecb_cbc_identical_blocks(cipher):
    pt = b"A" * 16 + b"A" * 16

    ct_ecb = encrypt(cipher, Mode.ECB, pt, None)
    assert ct_ecb[:16] == ct_ecb[16:]

    ct_cbc = encrypt(cipher, Mode.CBC, pt, b"\x00" * 16)
    assert ct_cbc[:16] != ct_cbc[16:]
