from importlib.metadata import version

import pytest

import tk_cipher
from tk_cipher import errors

SUBCLASSES = [
    errors.InvalidKeyError,
    errors.InvalidFormatError,
    errors.AuthenticationError,
    errors.PaddingError,
]


def test_version_matches_metadata():
    assert tk_cipher.__version__ == version("tk-cipher")


@pytest.mark.parametrize("exc", SUBCLASSES)
def test_error_derives_from_base(exc):
    assert issubclass(exc, errors.TKCipherError)


def test_base_error_catches_subclass():
    with pytest.raises(errors.TKCipherError):
        raise errors.AuthenticationError("tag mismatch")
