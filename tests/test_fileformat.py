import pytest

from tk_cipher.errors import AuthenticationError, InvalidFormatError
from tk_cipher.fileformat import (
    Header,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
)
from tk_cipher.modes import Mode


@pytest.mark.parametrize("mode", list(Mode))
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 33, 1000])
def test_bytes_round_trip(mode: Mode, length: int) -> None:
    key = bytes(range(16))
    plaintext = bytes(i % 256 for i in range(length))
    iv = None if mode == Mode.ECB else bytes(range(16))

    blob = encrypt_bytes(plaintext, key, mode, iv)

    assert len(blob[:32]) == 32
    assert decrypt_bytes(blob, key) == plaintext


def test_iv_is_persisted_and_randomized_when_omitted() -> None:
    key = bytes(16)
    supplied_iv = bytes(range(16))
    blob = encrypt_bytes(b"data", key, Mode.CBC, supplied_iv)
    assert Header.unpack(blob[:32]).iv == supplied_iv

    first = encrypt_bytes(b"data", key, Mode.CBC)
    second = encrypt_bytes(b"data", key, Mode.CBC)
    assert Header.unpack(first[:32]).iv != Header.unpack(second[:32]).iv


@pytest.mark.parametrize("offset", [8, 24, 32, -1])
def test_authenticated_fields_cannot_be_modified(offset: int) -> None:
    blob = bytearray(encrypt_bytes(b"authenticated", bytes(16), Mode.ECB))
    blob[offset] ^= 1
    with pytest.raises(AuthenticationError):
        decrypt_bytes(bytes(blob), bytes(16))


def test_structure_is_validated_before_authentication() -> None:
    with pytest.raises(InvalidFormatError):
        decrypt_bytes(bytes(63), bytes(16))
    with pytest.raises(InvalidFormatError):
        decrypt_bytes(bytes(65), bytes(16))
    with pytest.raises(InvalidFormatError):
        decrypt_bytes(b"NOPE" + bytes(60), bytes(16))


def test_wrong_key_fails_authentication() -> None:
    blob = encrypt_bytes(b"secret", bytes(16), Mode.CTR, bytes(16))
    with pytest.raises(
        AuthenticationError, match="wrong key or file has been modified"
    ):
        decrypt_bytes(blob, bytes([1]) * 16)


def test_file_round_trip_and_failed_decrypt_preserves_destination(tmp_path) -> None:
    src = tmp_path / "plain.bin"
    encrypted = tmp_path / "cipher.bin"
    output = tmp_path / "output.bin"
    key = bytes(16)
    src.write_bytes(b"file contents")

    written_header = encrypt_file(src, encrypted, key, Mode.CFB, bytes(16))
    output.write_bytes(b"existing destination")
    corrupted = bytearray(encrypted.read_bytes())
    corrupted[-1] ^= 1
    encrypted.write_bytes(corrupted)

    with pytest.raises(AuthenticationError):
        decrypt_file(encrypted, output, key)
    assert output.read_bytes() == b"existing destination"

    encrypted.write_bytes(encrypt_bytes(b"file contents", key, Mode.CFB, bytes(16)))
    read_header = decrypt_file(encrypted, output, key)
    assert read_header == written_header
    assert output.read_bytes() == b"file contents"


def test_ecb_rejects_user_iv() -> None:
    with pytest.raises(ValueError):
        encrypt_bytes(b"data", bytes(16), Mode.ECB, bytes(16))


@pytest.mark.parametrize("mode", list(Mode))
def test_flipped_header_prefix_bit_is_rejected(mode: Mode) -> None:
    key = bytes(16)
    iv = None if mode == Mode.ECB else bytes(range(16))
    blob = encrypt_bytes(b"header prefix", key, mode, iv)
    for offset in range(8):
        for bit in range(8):
            tampered = bytearray(blob)
            tampered[offset] ^= 1 << bit
            with pytest.raises((InvalidFormatError, AuthenticationError)):
                decrypt_bytes(bytes(tampered), key)


def test_failed_decrypt_file_creates_no_output(tmp_path) -> None:
    encrypted = tmp_path / "cipher.bin"
    output = tmp_path / "output.bin"
    blob = bytearray(encrypt_bytes(b"file contents", bytes(16), Mode.CBC))
    blob[-1] ^= 1
    encrypted.write_bytes(blob)

    with pytest.raises(AuthenticationError):
        decrypt_file(encrypted, output, bytes(16))

    assert not output.exists()
    assert [p.name for p in tmp_path.iterdir()] == ["cipher.bin"]
