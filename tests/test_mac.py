import pytest

from tk_cipher.errors import InvalidKeyError
from tk_cipher.mac import cmac, constant_time_eq


@pytest.mark.parametrize("length", [0, 16, 17, 48])
def test_cmac_handles_empty_partial_and_complete_messages(length):
    tag = cmac(bytes(range(16)), bytes(range(length)))
    assert len(tag) == 16


def test_cmac_changes_with_message_or_key():
    key = bytes(range(16))
    message = b"a message to authenticate"
    tag = cmac(key, message)
    changed_message = bytearray(message)
    changed_message[0] ^= 1

    assert cmac(key, bytes(changed_message)) != tag
    assert cmac(bytes(reversed(key)), message) != tag
    assert cmac(key, b"") != cmac(key, b"\x80")


def test_cmac_rejects_unsupported_key_length():
    with pytest.raises(InvalidKeyError):
        cmac(bytes(20), b"message")


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (b"same", b"same", True),
        (b"\x00bc", b"\x01bc", False),
        (b"abc\x00", b"abcd", False),
        (b"short", b"longer", False),
        (b"", b"", True),
    ],
)
def test_constant_time_eq(a, b, expected):
    assert constant_time_eq(a, b) is expected
