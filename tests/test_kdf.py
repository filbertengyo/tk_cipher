import pytest

from tk_cipher.errors import InvalidKeyError
from tk_cipher.kdf import derive_keys


@pytest.mark.parametrize("size", [16, 24, 32])
def test_derive_keys_is_deterministic_separate_and_correct_length(size):
    key = bytes(range(size))
    first = derive_keys(key)
    assert first == derive_keys(key)
    assert len(first[0]) == len(first[1]) == size
    assert first[0] != first[1]


@pytest.mark.parametrize("size", [16, 24, 32])
def test_changed_master_key_changes_derived_keys(size):
    key = bytearray(range(size))
    original = derive_keys(bytes(key))
    key[0] ^= 1
    changed = derive_keys(bytes(key))
    assert original[0] != changed[0]
    assert original[1] != changed[1]


def test_derive_keys_rejects_unsupported_key_length():
    with pytest.raises(InvalidKeyError):
        derive_keys(bytes(20))
