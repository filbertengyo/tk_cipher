"""Smoke tests: the package imports and the exception hierarchy is intact."""

from importlib.metadata import version

import pytest

import tk_cipher
from tk_cipher import errors


def test_package_version_matches_metadata() -> None:
    assert isinstance(tk_cipher.__version__, str)
    assert tk_cipher.__version__ == version("tk-cipher")


def test_base_error_is_an_exception() -> None:
    assert issubclass(errors.TKCipherError, Exception)


@pytest.mark.parametrize(
    "name",
    [
        "InvalidKeyError",
        "InvalidFormatError",
        "AuthenticationError",
        "PaddingError",
    ],
)
def test_specific_errors_derive_from_base(name: str) -> None:
    assert issubclass(getattr(errors, name), errors.TKCipherError)


def test_specific_error_is_caught_as_base() -> None:
    with pytest.raises(errors.TKCipherError):
        raise errors.AuthenticationError("tag mismatch")
