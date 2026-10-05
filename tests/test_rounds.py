import random

import pytest

from tk_cipher import rounds

RNG = random.Random(1234)
STATES = [[RNG.randrange(256) for _ in range(16)] for _ in range(1000)]
KEYS = [bytes(RNG.randrange(256) for _ in range(16)) for _ in range(1000)]


def single(index: int, value: int) -> list[int]:
    state = [0] * 16
    state[index] = value
    return state


def test_row_rotator_inverse():
    for s in STATES:
        assert rounds.inv_row_rotator(rounds.row_rotator(s)) == s
        assert rounds.row_rotator(rounds.inv_row_rotator(s)) == s


def test_column_cascade_inverse():
    for s in STATES:
        assert rounds.inv_column_cascade(rounds.column_cascade(s)) == s
        assert rounds.column_cascade(rounds.inv_column_cascade(s)) == s


def test_diagonal_transpose_involution():
    for s in STATES:
        assert rounds.diagonal_transpose(rounds.diagonal_transpose(s)) == s


def test_add_round_key_involution():
    for s, k in zip(STATES, KEYS):
        assert rounds.add_round_key(rounds.add_round_key(s, k), k) == s


def test_diagonal_transpose_known():
    assert rounds.diagonal_transpose(list(range(16))) == list(rounds.TRANSPOSE_IDX)


def test_row_rotator_single_bit_crosses_row():
    assert rounds.row_rotator(single(0, 0x80)) == single(3, 0x01)


def test_row_rotator_rotates_row_zero():
    assert rounds.row_rotator(single(3, 0x80))[:4] == [0, 0, 1, 0]


def test_column_cascade_top_byte():
    out = rounds.column_cascade(single(0, 1))
    assert out[0::4] == [2, 1, 1, 1]
    assert out[1::4] == out[2::4] == out[3::4] == [0, 0, 0, 0]


def test_column_cascade_bottom_byte():
    assert rounds.column_cascade(single(12, 1))[0::4] == [1, 0, 0, 1]


def test_column_cascade_wraps_mod_256():
    out = rounds.column_cascade(single(0, 0xFF))
    assert all(0 <= b < 256 for b in out)
    assert out[0::4] == [0xFE, 0xFF, 0xFF, 0xFF]


def test_dynamic_sub_identity():
    for s in STATES:
        assert rounds.dynamic_sub(s, list(range(256))) == s


def test_dynamic_sub_applies_table():
    table = [(b + 1) & 0xFF for b in range(256)]
    assert rounds.dynamic_sub([0, 255, 7], table) == [1, 0, 8]


def test_add_round_key_rejects_bad_length():
    with pytest.raises(ValueError):
        rounds.add_round_key([0] * 16, bytes(15))


@pytest.mark.parametrize(
    "func",
    [
        rounds.diagonal_transpose,
        rounds.row_rotator,
        rounds.inv_row_rotator,
        rounds.column_cascade,
        rounds.inv_column_cascade,
        lambda s: rounds.add_round_key(s, bytes(range(16))),
        lambda s: rounds.dynamic_sub(s, list(range(255, -1, -1))),
    ],
)
def test_input_not_mutated(func):
    state = list(range(16))
    snapshot = list(state)
    out = func(state)
    assert state == snapshot
    assert out is not state
    assert len(out) == 16
