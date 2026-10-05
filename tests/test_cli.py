import subprocess
import sys

import pytest

from tk_cipher.cli import main

KEY = "00112233445566778899aabbccddeeff"
IV = "0f0e0d0c0b0a09080706050403020100"
MODES = ["ecb", "cbc", "cfb", "ofb", "ctr"]


@pytest.fixture
def plain(tmp_path):
    path = tmp_path / "plain.bin"
    path.write_bytes(bytes(range(256)) * 3 + b"tail")
    return path


def enc(plain, out, mode="cbc", *extra):
    return main(
        ["enc", "-i", str(plain), "-o", str(out), "-k", KEY, "-m", mode, *extra]
    )


@pytest.mark.parametrize("mode", MODES)
def test_round_trip_every_mode(mode, plain, tmp_path):
    cipher, back = tmp_path / "c.enc", tmp_path / "back.bin"
    assert enc(plain, cipher, mode) == 0
    assert main(["dec", "-i", str(cipher), "-o", str(back), "-k", KEY]) == 0
    assert back.read_bytes() == plain.read_bytes()


def test_enc_prints_random_iv_and_differs(plain, tmp_path, capsys):
    a, b = tmp_path / "a.enc", tmp_path / "b.enc"
    assert enc(plain, a) == 0
    first = capsys.readouterr().err
    assert enc(plain, b) == 0
    second = capsys.readouterr().err
    assert "mode: cbc" in first and "iv: " in first
    assert first != second
    assert a.read_bytes() != b.read_bytes()


def test_enc_uses_given_iv(plain, tmp_path, capsys):
    assert enc(plain, tmp_path / "c.enc", "ctr", "--iv", IV) == 0
    assert f"iv: {IV}" in capsys.readouterr().err


def test_key_accepts_uppercase_and_spaces(plain, tmp_path):
    spaced = " ".join(KEY.upper()[i : i + 8] for i in range(0, 32, 8))
    cipher = tmp_path / "c.enc"
    assert (
        main(["enc", "-i", str(plain), "-o", str(cipher), "-k", spaced, "-m", "cbc"])
        == 0
    )
    assert main(["dec", "-i", str(cipher), "-o", str(tmp_path / "b"), "-k", KEY]) == 0


def test_key_file(plain, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text(KEY + "\n")
    cipher, back = tmp_path / "c.enc", tmp_path / "back.bin"
    assert (
        main(
            [
                "enc",
                "-i",
                str(plain),
                "-o",
                str(cipher),
                "--key-file",
                str(key_file),
                "-m",
                "cfb",
            ]
        )
        == 0
    )
    assert (
        main(["dec", "-i", str(cipher), "-o", str(back), "--key-file", str(key_file)])
        == 0
    )
    assert back.read_bytes() == plain.read_bytes()


def test_iv_rejected_for_ecb(plain, tmp_path):
    assert enc(plain, tmp_path / "c.enc", "ecb", "--iv", IV) == 1


@pytest.mark.parametrize("bad_key", [KEY[:31], KEY + "0", "zz" * 16, ""])
def test_invalid_key_exits_1(bad_key, plain, tmp_path):
    argv = [
        "enc",
        "-i",
        str(plain),
        "-o",
        str(tmp_path / "c"),
        "-k",
        bad_key,
        "-m",
        "cbc",
    ]
    assert main(argv) == 1


def test_invalid_iv_exits_1(plain, tmp_path):
    assert enc(plain, tmp_path / "c.enc", "cbc", "--iv", "abcd") == 1


def test_missing_input_exits_1(tmp_path):
    argv = [
        "enc",
        "-i",
        str(tmp_path / "nope"),
        "-o",
        str(tmp_path / "c"),
        "-k",
        KEY,
        "-m",
        "cbc",
    ]
    assert main(argv) == 1


def test_output_same_as_input_exits_1(plain):
    before = plain.read_bytes()
    assert enc(plain, plain) == 1
    assert plain.read_bytes() == before


def test_key_and_key_file_are_exclusive(plain, tmp_path):
    argv = [
        "enc",
        "-i",
        str(plain),
        "-o",
        str(tmp_path / "c"),
        "-k",
        KEY,
        "--key-file",
        "x",
        "-m",
        "cbc",
    ]
    assert main(argv) == 1


def test_missing_key_exits_1(plain, tmp_path):
    assert main(["enc", "-i", str(plain), "-o", str(tmp_path / "c"), "-m", "cbc"]) == 1


def test_missing_key_file_exits_1(plain, tmp_path):
    argv = [
        "enc",
        "-i",
        str(plain),
        "-o",
        str(tmp_path / "c"),
        "--key-file",
        str(tmp_path / "none"),
        "-m",
        "cbc",
    ]
    assert main(argv) == 1


def test_no_command_exits_1():
    assert main([]) == 1


def test_tampered_file_exits_3(plain, tmp_path):
    cipher = tmp_path / "c.enc"
    enc(plain, cipher)
    data = bytearray(cipher.read_bytes())
    data[40] ^= 1
    cipher.write_bytes(data)
    out = tmp_path / "out"
    assert main(["dec", "-i", str(cipher), "-o", str(out), "-k", KEY]) == 3
    assert not out.exists()


def test_wrong_key_exits_3(plain, tmp_path):
    cipher = tmp_path / "c.enc"
    enc(plain, cipher)
    other = "ff" * 16
    assert (
        main(["dec", "-i", str(cipher), "-o", str(tmp_path / "out"), "-k", other]) == 3
    )


def test_short_garbage_exits_2(tmp_path):
    junk = tmp_path / "junk.enc"
    junk.write_bytes(b"too short")
    assert main(["dec", "-i", str(junk), "-o", str(tmp_path / "out"), "-k", KEY]) == 2


@pytest.mark.parametrize("bits", [128, 192, 256])
def test_keygen_length(bits, capsys):
    assert main(["keygen", "--bits", str(bits)]) == 0
    out = capsys.readouterr().out.strip()
    assert len(out) == bits // 4
    bytes.fromhex(out)


def test_keygen_default_is_128_bit_and_random(capsys):
    main(["keygen"])
    first = capsys.readouterr().out.strip()
    main(["keygen"])
    second = capsys.readouterr().out.strip()
    assert len(first) == 32
    assert first != second


def test_errors_are_one_line_without_traceback(plain, tmp_path, capsys):
    enc(plain, tmp_path / "c", "cbc", "--iv", "abcd")
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert len(err.strip().splitlines()) == 1


def test_python_dash_m_runs():
    result = subprocess.run(
        [sys.executable, "-m", "tk_cipher", "keygen", "--bits", "256"],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0
    assert len(result.stdout.strip()) == 64
