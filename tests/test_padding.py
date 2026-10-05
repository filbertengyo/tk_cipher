import pytest

from tk_cipher.errors import PaddingError
from tk_cipher.padding import pad, unpad


@pytest.mark.parametrize(
    "input_len, pad_byte, expected_len",
    [
        (0, 0x10, 16),
        (1, 0x0F, 16),
        (15, 0x01, 16),
        (16, 0x10, 32),
        (17, 0x0F, 32),
        (31, 0x01, 32),
        (32, 0x10, 48),
        (33, 0x0F, 48),
    ],
)
def test_pad_table_cases(input_len: int, pad_byte: int, expected_len: int):
    """Memastikan panjang dan isi pad sesuai dengan tabel spesifikasi."""
    data: bytes = b"A" * input_len
    padded = pad(data, block_size=16)

    assert len(padded) == expected_len
    pad_len = expected_len - input_len
    assert padded[-pad_len:] == bytes([pad_byte] * pad_len)


@pytest.mark.parametrize("input_len", [0, 1, 15, 16, 17, 31, 32, 33, 255])
def test_unpad_pad_roundtrip(input_len: int):
    """Memastikan unpad(pad(x)) == x untuk berbagai panjang data."""
    data = bytes([i % 256 for i in range(input_len)])
    assert unpad(pad(data, block_size=16), block_size=16) == data


def test_unpad_empty_input_fails():
    """unpad gagal (PaddingError) untuk input kosong."""
    with pytest.raises(PaddingError):
        _ = unpad(b"", block_size=16)


def test_unpad_invalid_length_fails():
    """unpad gagal (PaddingError) untuk panjang bukan kelipatan block_size (misal 15)."""
    with pytest.raises(PaddingError):
        _ = unpad(b"A" * 15, block_size=16)


def test_unpad_last_byte_zero_fails():
    """unpad gagal (PaddingError) untuk byte terakhir 0x00."""
    data = b"A" * 15 + b"\x00"
    with pytest.raises(PaddingError):
        _ = unpad(data, block_size=16)


def test_unpad_last_byte_out_of_bounds_fails():
    """unpad gagal (PaddingError) untuk byte terakhir 0x11 (p > block_size) pada blok 16."""
    data = b"A" * 15 + b"\x11"
    with pytest.raises(PaddingError):
        _ = unpad(data, block_size=16)


def test_unpad_non_uniform_padding_fails():
    """unpad gagal (PaddingError) untuk byte pad yang tidak seragam."""
    data = b"A" * 13 + b"\x03\x02\x03"
    with pytest.raises(PaddingError):
        _ = unpad(data, block_size=16)


def test_data_ending_in_01_intact():
    """Data yang kebetulan diakhiri 0x01 tetap balik utuh setelah pad lalu unpad."""
    data = b"A" * 15 + b"\x01"
    padded = pad(data, block_size=16)
    unpadded = unpad(padded, block_size=16)
    assert unpadded == data
    assert unpadded[-1] == 0x01
