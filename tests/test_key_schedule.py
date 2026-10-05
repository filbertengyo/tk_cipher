import random

import pytest

from tk_cipher.errors import InvalidKeyError
from tk_cipher.key_schedule import ROUND_CONSTANTS, _lanes, expand_key
from tk_cipher.sbox import generate_sbox

RNG = random.Random(9012)
KEYS = {n: bytes(RNG.randrange(256) for _ in range(n)) for n in (16, 24, 32)}
SBOXES = {n: generate_sbox(k) for n, k in KEYS.items()}


def flip_bit(key: bytes, bit: int) -> bytes:
    out = bytearray(key)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


def test_round_constants_known():
    assert len(ROUND_CONSTANTS) >= 17
    assert ROUND_CONSTANTS[0] == 0x9E3779B9
    assert ROUND_CONSTANTS[1] == 0xC7EE3632


@pytest.mark.parametrize("n", KEYS)
def test_default_gives_17_round_keys(n):
    rks = expand_key(KEYS[n], SBOXES[n])
    assert len(rks) == 17
    assert all(isinstance(rk, bytes) and len(rk) == 16 for rk in rks)


@pytest.mark.parametrize("n", KEYS)
def test_custom_rounds(n):
    assert len(expand_key(KEYS[n], SBOXES[n], rounds=4)) == 5


@pytest.mark.parametrize("n", KEYS)
def test_deterministic(n):
    assert expand_key(KEYS[n], SBOXES[n]) == expand_key(KEYS[n], SBOXES[n])


@pytest.mark.parametrize("n", KEYS)
def test_round_keys_all_distinct(n):
    assert len(set(expand_key(KEYS[n], SBOXES[n]))) == 17


@pytest.mark.parametrize("n", KEYS)
def test_one_bit_key_change_differs_every_round(n):
    key = KEYS[n]
    base = expand_key(key, SBOXES[n])
    for bit in range(0, n * 8, 7):
        other_key = flip_bit(key, bit)
        other = expand_key(other_key, generate_sbox(other_key))
        assert all(a != b for a, b in zip(base, other))


def test_lanes_192_pads_with_zero():
    k0, k1 = _lanes(KEYS[24], SBOXES[24])
    assert k0 == KEYS[24][:16]
    assert k1 == KEYS[24][16:] + bytes(8)


def test_lanes_256_uses_second_half():
    assert _lanes(KEYS[32], SBOXES[32])[1] == KEYS[32][16:]


def test_lanes_128_uses_sbox_of_rotated_key():
    k0, k1 = _lanes(KEYS[16], SBOXES[16])
    rotated = k0[5:] + k0[:5]
    assert k1 == bytes(SBOXES[16].forward[b] for b in rotated)


def test_rejects_bad_key_length():
    with pytest.raises(InvalidKeyError):
        expand_key(bytes(15), SBOXES[16])


def test_rejects_zero_rounds():
    with pytest.raises(ValueError):
        expand_key(KEYS[16], SBOXES[16], rounds=0)
