"""CLI `tk-cipher` buat enkripsi, dekripsi, dan bikin key

Pemakaian:

    tk-cipher enc -i <in> -o <out> (-k <hex> | --key-file <path>) -m {ecb,cbc,cfb,ofb,ctr} [--iv <32 hex>]
    tk-cipher dec -i <in> -o <out> (-k <hex> | --key-file <path>)
    tk-cipher keygen [--bits {128,192,256}]

Exit code: 0 sukses, 1 argumen atau key salah, 2 file rusak, 3 MAC gagal
"""

import argparse
import os
import sys
from pathlib import Path

from tk_cipher.errors import (
    AuthenticationError,
    InvalidFormatError,
    InvalidKeyError,
    PaddingError,
)
from tk_cipher.fileformat import decrypt_file, encrypt_file
from tk_cipher.modes import Mode

KEY_HEX_LENGTHS = (32, 48, 64)
"""Panjang key hex yang valid (128, 192, 256-bit)"""
IV_HEX_LENGTH = 32
"""Panjang IV hex (16 byte)"""
MODES = tuple(m.name.lower() for m in Mode)
"""Nama mode buat opsi `-m`"""

EXIT_OK = 0
"""Exit code sukses"""
EXIT_USAGE = 1
"""Exit code argumen salah, key invalid, atau file input tidak ada"""
EXIT_FORMAT = 2
"""Exit code `InvalidFormatError` atau `PaddingError`"""
EXIT_AUTH = 3
"""Exit code `AuthenticationError`"""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        print(f"tk-cipher: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


def parse_hex(text: str, lengths: tuple[int, ...], what: str) -> bytes:
    """Ubah string hex jadi bytes, spasi diabaikan dan huruf besar kecil boleh

    Args:
        text (str): string hex dari argumen atau isi key file
        lengths (tuple[int, ...]): panjang hex yang diterima
        what (str): nama nilai buat pesan error, misalnya `"key"` atau `"iv"`

    Returns:
        bytes: hasil decode hex

    Raises:
        InvalidKeyError: panjang tidak ada di `lengths` atau bukan hex valid

    Example:
        >>> parse_hex("00 11 AA ff", (8,), "key")
        b'\\x00\\x11\\xaa\\xff'
    """
    cleaned = "".join(text.split())
    if len(cleaned) not in lengths:
        expected = ", ".join(str(n) for n in lengths)
        raise InvalidKeyError(f"{what} must be {expected} hex characters")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise InvalidKeyError(f"{what} is not valid hex") from None


def _load_key(args: argparse.Namespace) -> bytes:
    if args.key_file is not None:
        text = Path(args.key_file).read_text(encoding="utf-8")
    else:
        text = args.key
    return parse_hex(text, KEY_HEX_LENGTHS, "key")


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="tk-cipher", description="TK-Cipher file encryption")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    for name, help_text in (("enc", "encrypt a file"), ("dec", "decrypt a file")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("-i", "--input", required=True, help="input file")
        p.add_argument("-o", "--output", required=True, help="output file")
        group = p.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "-k", "--key", help="master key in hex (32, 48, or 64 chars)"
        )
        group.add_argument("--key-file", help="file that contains the key in hex")
        if name == "enc":
            p.add_argument("-m", "--mode", required=True, choices=MODES, type=str.lower)
            p.add_argument(
                "--iv", help="IV or initial counter, 32 hex chars (not for ecb)"
            )

    keygen = sub.add_parser("keygen", help="print a random key in hex")
    keygen.add_argument("--bits", type=int, choices=(128, 192, 256), default=128)
    return parser


def _check_paths(src: Path, dst: Path) -> None:
    if not src.is_file():
        raise FileNotFoundError(f"input file not found: {src}")
    if dst.exists() and src.resolve() == dst.resolve():
        raise ValueError("output must be different from input")


def _run_enc(args: argparse.Namespace) -> None:
    mode = Mode[args.mode.upper()]
    if args.iv is not None and mode == Mode.ECB:
        raise ValueError("ecb does not use an IV")
    iv = None if args.iv is None else parse_hex(args.iv, (IV_HEX_LENGTH,), "iv")
    key = _load_key(args)
    src, dst = Path(args.input), Path(args.output)
    _check_paths(src, dst)
    header = encrypt_file(src, dst, key, mode, iv)
    used_iv = "none" if mode == Mode.ECB else header.iv.hex()
    print(f"mode: {args.mode}", file=sys.stderr)
    print(f"iv: {used_iv}", file=sys.stderr)


def _run_dec(args: argparse.Namespace) -> None:
    key = _load_key(args)
    src, dst = Path(args.input), Path(args.output)
    _check_paths(src, dst)
    decrypt_file(src, dst, key)


def main(argv: list[str] | None = None) -> int:
    """Jalankan CLI dengan argumen yang dikasih dan return exit code

    Error dicetak satu baris ke stderr tanpa traceback. `enc` juga mencetak mode
    dan IV yang dipakai ke stderr biar IV acak bisa dicatat

    Args:
        argv (list[str] | None): argumen tanpa nama program, `None` pakai `sys.argv[1:]`

    Returns:
        int: 0 sukses, 1 argumen atau key salah, 2 file rusak, 3 MAC gagal


    Example:
        >>> main(["dec", "-i", "missing.enc", "-o", "out.bin", "-k", "00" * 16])
        1
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    try:
        if args.command == "keygen":
            print(os.urandom(args.bits // 8).hex())
        elif args.command == "enc":
            _run_enc(args)
        else:
            _run_dec(args)
    except AuthenticationError as exc:
        return _fail(exc, EXIT_AUTH)
    except (InvalidFormatError, PaddingError) as exc:
        return _fail(exc, EXIT_FORMAT)
    except (InvalidKeyError, ValueError, OSError) as exc:
        return _fail(exc, EXIT_USAGE)
    return EXIT_OK


def _fail(exc: Exception, code: int) -> int:
    print(f"tk-cipher: error: {exc}", file=sys.stderr)
    return code
