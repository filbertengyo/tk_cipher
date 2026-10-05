import json
import pathlib
import random

import pytest

from tk_cipher.cipher import BLOCK_SIZE, TKCipher
from tk_cipher.errors import InvalidKeyError

RNG = random.Random(3456)
CIPHERS = {
    n: TKCipher(bytes(RNG.randrange(256) for _ in range(n))) for n in (16, 24, 32)
}
BLOCKS = [bytes(RNG.randrange(256) for _ in range(BLOCK_SIZE)) for _ in range(1000)]
VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "vectors.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("n", CIPHERS)
def test_round_trip(n):
    c = CIPHERS[n]
    for block in BLOCKS:
        assert c.decrypt_block(c.encrypt_block(block)) == block


@pytest.mark.parametrize("n", CIPHERS)
def test_deterministic(n):
    key = bytes(range(n))
    assert TKCipher(key).encrypt_block(BLOCKS[0]) == TKCipher(key).encrypt_block(
        BLOCKS[0]
    )


def test_wrong_key_does_not_decrypt():
    ct = CIPHERS[16].encrypt_block(BLOCKS[0])
    assert TKCipher(bytes(16)).decrypt_block(ct) != BLOCKS[0]


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: f"{v['key_bits']}-bit")
def test_vectors(v):
    c = TKCipher(bytes.fromhex(v["key"]))
    pt, ct = bytes.fromhex(v["plaintext"]), bytes.fromhex(v["ciphertext"])
    assert c.encrypt_block(pt) == ct
    assert c.decrypt_block(ct) == pt
    assert c.sbox.differential_uniformity == v["sbox"]["differential_uniformity"]
    assert c.sbox.nonlinearity == v["sbox"]["nonlinearity"]
    assert c.sbox.attempts == v["sbox"]["attempts"]


def test_vectors_cover_all_key_sizes():
    assert sorted(v["key_bits"] for v in VECTORS) == [128, 192, 256]


@pytest.mark.parametrize("length", [15, 17])
def test_rejects_bad_block_length(length):
    with pytest.raises(ValueError):
        CIPHERS[16].encrypt_block(bytes(length))
    with pytest.raises(ValueError):
        CIPHERS[16].decrypt_block(bytes(length))


def test_rejects_bad_key_length():
    with pytest.raises(InvalidKeyError):
        TKCipher(bytes(20))


def test_reduced_rounds_round_trip():
    c = TKCipher(bytes(range(16)), rounds=4)
    assert len(c.round_keys) == 5
    for block in BLOCKS[:100]:
        assert c.decrypt_block(c.encrypt_block(block)) == block
