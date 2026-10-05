import random

import pytest

from tk_cipher.errors import InvalidKeyError
from tk_cipher.prng import TKRand
from tk_cipher.sbox import (
    MAX_DU,
    MIN_NL,
    differential_uniformity,
    generate_sbox,
    nonlinearity,
)

RNG = random.Random(5678)
KEYS = [
    bytes(RNG.randrange(256) for _ in range(RNG.choice((16, 24, 32))))
    for _ in range(20)
]


def test_tkrand_deterministic():
    a, b = TKRand(b"same seed"), TKRand(b"same seed")
    assert [a.next32() for _ in range(100)] == [b.next32() for _ in range(100)]


def test_tkrand_seed_sensitive():
    a, b = TKRand(b"seed-a"), TKRand(b"seed-b")
    assert [a.next32() for _ in range(10)] != [b.next32() for _ in range(10)]


def test_next32_range():
    rng = TKRand(b"range")
    for _ in range(1000):
        assert 0 <= rng.next32() < 2**32


def test_below_range_and_coverage():
    rng = TKRand(b"below")
    values = [rng.below(7) for _ in range(1000)]
    assert all(0 <= v < 7 for v in values)
    assert set(values) == set(range(7))


@pytest.mark.parametrize("n", [0, -1, 2**32 + 1])
def test_below_invalid(n):
    with pytest.raises(ValueError):
        TKRand(b"x").below(n)


def test_sbox_deterministic():
    key = bytes(range(16))
    assert generate_sbox(key) == generate_sbox(key)


@pytest.mark.parametrize("key", KEYS)
def test_sbox_properties(key):
    sbox = generate_sbox(key)
    s = sbox.forward
    assert sorted(s) == list(range(256))
    assert all(s[x] != x and s[x] != x ^ 0xFF for x in range(256))
    assert sbox.differential_uniformity == differential_uniformity(s) <= MAX_DU
    assert sbox.nonlinearity == nonlinearity(s) >= MIN_NL
    assert sbox.attempts >= 1
    assert all(sbox.inverse[s[x]] == x for x in range(256))


def test_sbox_key_length_matters():
    key16 = bytes(range(16))
    key24 = key16 + bytes(range(100, 108))
    assert generate_sbox(key16).forward != generate_sbox(key24).forward


@pytest.mark.parametrize("length", [0, 15, 17, 33])
def test_sbox_invalid_key(length):
    with pytest.raises(InvalidKeyError):
        generate_sbox(bytes(length))


def test_identity_metrics():
    identity = list(range(256))
    assert differential_uniformity(identity) == 256
    assert nonlinearity(identity) == 0


def test_metrics_reject_wrong_length():
    with pytest.raises(ValueError):
        differential_uniformity(range(255))
    with pytest.raises(ValueError):
        nonlinearity(range(255))
