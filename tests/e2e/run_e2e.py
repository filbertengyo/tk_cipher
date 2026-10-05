"""End-to-end test tk-cipher lewat subprocess, target python -m tk_cipher atau executable

Jalankan:
    uv run python tests/e2e/run_e2e.py
    uv run python tests/e2e/run_e2e.py --exe dist/tk-cipher-linux
    uv run python tests/e2e/run_e2e.py --exe dist/tk-cipher-windows.exe
"""

import argparse
import itertools
import os
import pathlib
import platform
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA = ROOT / "tests" / "data"
RESULTS = ROOT / "tests" / "results"
MODES = ["ecb", "cbc", "cfb", "ofb", "ctr"]
IV = "000102030405060708090a0b0c0d0e0f"


@dataclass
class Result:
    name: str
    ok: bool
    detail: str


def data_files(skip_large: bool) -> list[pathlib.Path]:
    """Semua file sample di tests/data kecuali skrip dan readme"""
    files = [
        p
        for p in sorted(DATA.iterdir())
        if p.is_file() and p.suffix not in (".py", ".md") and not p.name.startswith(".")
    ]
    return [p for p in files if not (skip_large and p.name == "large.bin")]


class Runner:
    """Jalanin perintah tk-cipher ke target yang dipilih di folder kerja sementara"""

    def __init__(self, base: list[str], work: pathlib.Path, key: str) -> None:
        self.base = base
        self.work = work
        self.key = key
        self._ids = itertools.count(1)

    def path(self, name: str) -> pathlib.Path:
        return self.work / f"{next(self._ids)}_{name}"

    def run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [*self.base, *args], capture_output=True, text=True, check=False
        )

    def enc(self, src, dst, mode, *extra, key=None) -> subprocess.CompletedProcess:
        key_args = (
            list(extra) if "--key-file" in extra else ["-k", key or self.key, *extra]
        )
        return self.run("enc", "-i", str(src), "-o", str(dst), "-m", mode, *key_args)

    def dec(self, src, dst, key=None, key_file=None) -> subprocess.CompletedProcess:
        key_args = (
            ["--key-file", str(key_file)] if key_file else ["-k", key or self.key]
        )
        return self.run("dec", "-i", str(src), "-o", str(dst), *key_args)


def round_trip(r: Runner, src: pathlib.Path, mode: str, iv: str | None) -> Result:
    name = f"round trip {src.name} {mode}" + (" --iv" if iv else "")
    enc, back = r.path(f"{src.name}.{mode}.enc"), r.path(f"{src.name}.{mode}.out")
    extra = ["--iv", iv] if iv else []
    p = r.enc(src, enc, mode, *extra)
    if p.returncode != 0:
        return Result(name, False, f"enc exit {p.returncode}: {p.stderr.strip()}")
    p = r.dec(enc, back)
    if p.returncode != 0:
        return Result(name, False, f"dec exit {p.returncode}: {p.stderr.strip()}")
    same = back.read_bytes() == src.read_bytes()
    return Result(
        name, same, f"{src.stat().st_size} byte identik" if same else "isi beda"
    )


def expect_exit(
    name: str, p: subprocess.CompletedProcess, code: int, out=None
) -> Result:
    ok = p.returncode == code and (out is None or not out.exists())
    detail = f"exit {p.returncode} (harus {code})"
    if out is not None and out.exists():
        detail += ", file output terbentuk"
    return Result(name, ok, detail)


def scenarios(r: Runner, files: list[pathlib.Path]) -> list:
    """Daftar skenario sebagai callable tanpa argumen yang return Result"""
    jobs = []

    for bits in (128, 192, 256):

        def keygen(bits=bits):
            p = r.run("keygen", "--bits", str(bits))
            out = p.stdout.strip()
            try:
                valid = len(bytes.fromhex(out)) * 8 == bits
            except ValueError:
                valid = False
            ok = p.returncode == 0 and valid and len(out) == bits // 4
            return Result(f"keygen --bits {bits}", ok, f"{len(out)} karakter hex")

        jobs.append(keygen)

    small = r.path("empty.bin")
    small.write_bytes(b"")
    seventeen = r.path("17.bin")
    seventeen.write_bytes(bytes(range(17)))
    for src in [*files, small, seventeen]:
        for mode in MODES:
            jobs.append(lambda src=src, mode=mode: round_trip(r, src, mode, None))
            if mode in ("cbc", "ctr"):
                jobs.append(lambda src=src, mode=mode: round_trip(r, src, mode, IV))

    def key_file():
        kf = r.path("key.txt")
        kf.write_text(r.key + "\n")
        src = DATA / "text_small.txt"
        enc, back = r.path("kf.enc"), r.path("kf.out")
        p1 = r.enc(src, enc, "cbc", "--key-file", str(kf))
        p2 = r.dec(enc, back, key_file=kf)
        ok = (
            p1.returncode == 0
            and p2.returncode == 0
            and back.read_bytes() == src.read_bytes()
        )
        return Result(
            "key lewat --key-file", ok, f"exit enc {p1.returncode}, dec {p2.returncode}"
        )

    jobs.append(key_file)

    def encrypted_sample() -> pathlib.Path:
        enc = r.path("sample.enc")
        r.enc(DATA / "text_small.txt", enc, "cbc")
        return enc

    def tamper():
        enc = encrypted_sample()
        data = bytearray(enc.read_bytes())
        data[40] ^= 0x01
        enc.write_bytes(data)
        out = r.path("tamper.out")
        return expect_exit("tamper 1 byte ciphertext", r.dec(enc, out), 3, out)

    def wrong_key():
        enc = encrypted_sample()
        out = r.path("wrong.out")
        other = os.urandom(16).hex()
        return expect_exit("dec pakai key lain", r.dec(enc, out, key=other), 3, out)

    def truncated():
        enc = encrypted_sample()
        enc.write_bytes(enc.read_bytes()[:40])
        out = r.path("trunc.out")
        return expect_exit("file terpotong 40 byte", r.dec(enc, out), 2, out)

    def iv_on_ecb():
        out = r.path("ecb.enc")
        p = r.enc(DATA / "text_small.txt", out, "ecb", "--iv", IV)
        return expect_exit("--iv di ECB", p, 1, out)

    def short_key():
        out = r.path("short.enc")
        p = r.enc(DATA / "text_small.txt", out, "cbc", key=r.key[:31])
        return expect_exit("key 31 karakter hex", p, 1, out)

    def missing_input():
        out = r.path("missing.enc")
        return expect_exit(
            "file input tidak ada", r.enc(r.work / "nope.bin", out, "cbc"), 1, out
        )

    def same_path():
        src = r.path("same.bin")
        src.write_bytes(b"jangan ditimpa")
        p = r.enc(src, src, "cbc")
        res = expect_exit("-o sama dengan -i", p, 1)
        if src.read_bytes() != b"jangan ditimpa":
            res.ok, res.detail = False, res.detail + ", input berubah"
        return res

    jobs += [
        tamper,
        wrong_key,
        truncated,
        iv_on_ecb,
        short_key,
        missing_input,
        same_path,
    ]
    return jobs


def write_report(results: list[Result], target: str, path: pathlib.Path) -> None:
    passed = sum(r.ok for r in results)
    lines = [
        f"# E2E {platform.system()} {target}",
        "",
        f"- OS: {platform.system()} {platform.release()} ({platform.machine()})",
        f"- Python runner: {platform.python_version()}",
        f"- Target: `{target}`",
        f"- Hasil: {passed} dari {len(results)} skenario lulus",
        "",
        "| Skenario | Hasil | Detail |",
        "| --- | --- | --- |",
    ]
    lines += [
        f"| {r.name} | {'lulus' if r.ok else 'GAGAL'} | {r.detail} |" for r in results
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--exe", help="path executable, default python -m tk_cipher")
    parser.add_argument("--skip-large", action="store_true", help="lewati large.bin")
    parser.add_argument("--workers", type=int, default=os.cpu_count())
    args = parser.parse_args()

    if args.exe:
        exe = pathlib.Path(args.exe).resolve()
        if not exe.is_file():
            print(f"executable tidak ditemukan: {exe}", file=sys.stderr)
            return 1
        base, target = [str(exe)], exe.stem
    else:
        base, target = [sys.executable, "-m", "tk_cipher"], "python"

    with tempfile.TemporaryDirectory() as tmp:
        runner = Runner(base, pathlib.Path(tmp), os.urandom(16).hex())
        jobs = scenarios(runner, data_files(args.skip_large))
        with ThreadPoolExecutor(args.workers) as pool:
            results = list(pool.map(lambda job: job(), jobs))

    width = max(len(r.name) for r in results)
    for r in results:
        print(f"{'PASS' if r.ok else 'FAIL'}  {r.name:<{width}}  {r.detail}")
    passed = sum(r.ok for r in results)
    print(f"\n{passed}/{len(results)} lulus")

    RESULTS.mkdir(parents=True, exist_ok=True)
    report = RESULTS / f"e2e_{platform.system().lower()}_{target}.md"
    write_report(results, target, report)
    print(f"laporan: {report.relative_to(ROOT)}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
