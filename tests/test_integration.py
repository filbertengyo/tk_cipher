import ast
import os
import pathlib
import subprocess
import sys

import pytest

from tk_cipher.errors import AuthenticationError, InvalidFormatError
from tk_cipher.fileformat import decrypt_file, encrypt_file
from tk_cipher.modes import Mode

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
SRC = ROOT / "src"
DATA_FILES = sorted(
    p.name
    for p in DATA.iterdir()
    if p.is_file() and p.suffix not in (".py", ".md") and p.name != ".gitkeep"
)
KEYS = {bits: bytes(range(bits // 8)) for bits in (128, 192, 256)}
FAST_FILE = "text_small.txt"
FORBIDDEN = {
    "hashlib",
    "hmac",
    "secrets",
    "random",
    "Crypto",
    "cryptography",
    "numpy",
    "matplotlib",
}
CORRUPT_ERRORS = (InvalidFormatError, AuthenticationError)


def iv_for(mode: Mode) -> bytes | None:
    return None if mode == Mode.ECB else bytes(range(16, 32))


def round_trip_params():
    for name in DATA_FILES:
        for mode in Mode:
            for bits in KEYS:
                slow = not (name == FAST_FILE and bits == 128)
                marks = [pytest.mark.slow] if slow else []
                yield pytest.param(
                    name, mode, bits, marks=marks, id=f"{name}-{mode.name}-{bits}"
                )


@pytest.mark.parametrize("name, mode, bits", list(round_trip_params()))
def test_file_round_trip(name, mode, bits, tmp_path):
    src = DATA / name
    enc, back = tmp_path / "file.enc", tmp_path / "file.out"
    encrypt_file(src, enc, KEYS[bits], mode, iv_for(mode))
    decrypt_file(enc, back, KEYS[bits])
    assert back.read_bytes() == src.read_bytes()


@pytest.fixture
def encrypted(tmp_path):
    src = tmp_path / "plain.bin"
    src.write_bytes(bytes(range(256)) * 4)
    enc = tmp_path / "plain.enc"
    encrypt_file(src, enc, KEYS[128], Mode.CBC, iv_for(Mode.CBC))
    return enc


def regions(size: int) -> dict[str, int]:
    ct_len = size - 48
    return {
        "magic": 0,
        "version": 4,
        "mode": 5,
        "reserved": 6,
        "iv": 8,
        "original_length": 24,
        "ciphertext_start": 32,
        "ciphertext_middle": 32 + ct_len // 2,
        "ciphertext_end": 32 + ct_len - 1,
        "tag": size - 1,
    }


@pytest.mark.parametrize("region", list(regions(1072)))
def test_tamper_each_region_is_rejected(region, encrypted, tmp_path):
    data = bytearray(encrypted.read_bytes())
    data[regions(len(data))[region]] ^= 0x01
    encrypted.write_bytes(data)
    out = tmp_path / "out.bin"
    with pytest.raises(CORRUPT_ERRORS):
        decrypt_file(encrypted, out, KEYS[128])
    assert not out.exists()


@pytest.mark.parametrize("kind", ["one_bit", "random"])
def test_wrong_key_is_rejected(kind, encrypted, tmp_path):
    if kind == "one_bit":
        key = bytearray(KEYS[128])
        key[0] ^= 0x01
        key = bytes(key)
    else:
        key = os.urandom(16)
    out = tmp_path / "out.bin"
    with pytest.raises(AuthenticationError):
        decrypt_file(encrypted, out, key)
    assert not out.exists()


@pytest.mark.parametrize("size", [0, 63, 72, 65])
def test_corrupt_file_is_rejected(size, tmp_path):
    bad = tmp_path / "bad.enc"
    bad.write_bytes(bytes(size))
    out = tmp_path / "out.bin"
    with pytest.raises(InvalidFormatError):
        decrypt_file(bad, out, KEYS[128])
    assert not out.exists()


def imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_src_has_no_forbidden_imports():
    files = list(SRC.rglob("*.py"))
    assert files
    found = {str(p.relative_to(ROOT)): imported_modules(p) & FORBIDDEN for p in files}
    assert {k: v for k, v in found.items() if v} == {}


@pytest.mark.parametrize("mode", [m.name.lower() for m in Mode])
def test_cli_subprocess_round_trip(mode, tmp_path):
    src = DATA / FAST_FILE
    enc, back = tmp_path / "file.enc", tmp_path / "file.out"
    key = KEYS[128].hex()
    base = [sys.executable, "-m", "tk_cipher"]
    enc_cmd = [*base, "enc", "-i", str(src), "-o", str(enc), "-k", key, "-m", mode]
    dec_cmd = [*base, "dec", "-i", str(enc), "-o", str(back), "-k", key]
    for cmd in (enc_cmd, dec_cmd):
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr
    assert back.read_bytes() == src.read_bytes()
