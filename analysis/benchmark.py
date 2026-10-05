"""A-08: benchmark throughput enc dan dec file kecil, sedang, besar x 5 mode plus waktu key setup"""

import argparse
import csv
import os
import pathlib
import platform
import random
import statistics
import tempfile
import time

from tk_cipher.cipher import TKCipher
from tk_cipher.fileformat import decrypt_file, encrypt_file
from tk_cipher.modes import Mode

SEED = 20261006
ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
RESULTS = ROOT / "tests" / "results"
SMALL_LIMIT = 100 * 1024
REPEATS = {"kecil": 5, "sedang": 3, "besar": 1}
KEY_SETUP_SAMPLES = 20


def cpu_name() -> str:
    """Nama CPU dari /proc/cpuinfo kalau ada, selain itu dari platform"""
    info = pathlib.Path("/proc/cpuinfo")
    if info.exists():
        for line in info.read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def sample_files() -> list[tuple[str, pathlib.Path]]:
    """File uji per kategori, kecil itu semua file sample di bawah 100 KB"""
    files = []
    for p in sorted(DATA.iterdir()):
        if p.suffix in (".py", ".md") or p.name.startswith(".") or not p.is_file():
            continue
        if p.stat().st_size < SMALL_LIMIT:
            files.append(("kecil", p))
    files.append(("sedang", DATA / "medium.bin"))
    files.append(("besar", DATA / "large.bin"))
    return files


def time_file(
    src: pathlib.Path,
    mode: Mode,
    key: bytes,
    iv: bytes,
    repeats: int,
    work: pathlib.Path,
) -> dict:
    """Median waktu encrypt_file dan decrypt_file, sekalian cek round trip"""
    enc, back = work / "bench.enc", work / "bench.out"
    use_iv = None if mode == Mode.ECB else iv
    enc_times, dec_times = [], []
    for _ in range(repeats):
        start = time.perf_counter()
        encrypt_file(src, enc, key, mode, use_iv)
        enc_times.append(time.perf_counter() - start)
        start = time.perf_counter()
        decrypt_file(enc, back, key)
        dec_times.append(time.perf_counter() - start)
    size = src.stat().st_size
    enc_s, dec_s = statistics.median(enc_times), statistics.median(dec_times)
    return {
        "file": src.name,
        "size_bytes": size,
        "mode": mode.name,
        "repeats": repeats,
        "enc_s": round(enc_s, 4),
        "dec_s": round(dec_s, 4),
        "enc_kib_s": round(size / 1024 / enc_s, 2),
        "dec_kib_s": round(size / 1024 / dec_s, 2),
        "round_trip_ok": back.read_bytes() == src.read_bytes(),
    }


def time_key_setup(rng: random.Random) -> list[dict]:
    """Median waktu TKCipher(key) buat key 128, 192, 256-bit"""
    rows = []
    for size in (16, 24, 32):
        times = []
        for _ in range(KEY_SETUP_SAMPLES):
            key = rng.randbytes(size)
            start = time.perf_counter()
            TKCipher(key)
            times.append(time.perf_counter() - start)
        rows.append(
            {
                "key_bits": size * 8,
                "samples": KEY_SETUP_SAMPLES,
                "median_ms": round(statistics.median(times) * 1000, 2),
                "min_ms": round(min(times) * 1000, 2),
                "max_ms": round(max(times) * 1000, 2),
            }
        )
    return rows


def machine() -> dict:
    return {
        "OS": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "CPU": f"{cpu_name()}, {os.cpu_count()} logical core",
        "Python": f"{platform.python_implementation()} {platform.python_version()}",
    }


def write_outputs(rows: list[dict], keys: list[dict], seed: int) -> None:
    with open(RESULTS / "benchmark.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# Benchmark (A-08)",
        "",
        f"Seed: `{seed}`. Dibuat oleh `analysis/benchmark.py`.",
        "",
    ]
    lines += ["## Mesin", ""] + [f"- {k}: {v}" for k, v in machine().items()]
    lines += [
        "",
        "## Throughput file",
        "",
        "Waktu `encrypt_file` dan `decrypt_file` (termasuk KDF, MAC, dan I/O), median dari beberapa ulangan.",
        "",
        "| Kategori | File | Ukuran | Mode | Ulangan | Enc (s) | Dec (s) | Enc KiB/s | Dec KiB/s | Round trip |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        lines.append(
            f"| {r['category']} | {r['file']} | {r['size_bytes']:,} | {r['mode']} | {r['repeats']} | "
            f"{r['enc_s']} | {r['dec_s']} | {r['enc_kib_s']} | {r['dec_kib_s']} | {'OK' if r['round_trip_ok'] else 'GAGAL'} |"
        )
    lines += [
        "",
        "## Key setup",
        "",
        "Waktu `TKCipher(key)`, yaitu bikin S-box dinamis plus 17 round key.",
        "",
        "| Key | Sampel | Median (ms) | Min (ms) | Max (ms) |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines += [
        f"| {k['key_bits']}-bit | {k['samples']} | {k['median_ms']} | {k['min_ms']} | {k['max_ms']} |"
        for k in keys
    ]
    (RESULTS / "benchmark.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    if not (DATA / "large.bin").exists():
        print(
            "large.bin belum ada, jalankan dulu: uv run python tests/data/make_large.py"
        )
        return 1

    rng = random.Random(args.seed)
    key, iv = rng.randbytes(16), rng.randbytes(16)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for category, path in sample_files():
            for mode in Mode:
                row = time_file(
                    path, mode, key, iv, REPEATS[category], pathlib.Path(tmp)
                )
                rows.append({"category": category, **row})
                print(
                    f"{category:6} {path.name:16} {mode.name}  enc {row['enc_kib_s']} KiB/s"
                )
    keys = time_key_setup(rng)
    RESULTS.mkdir(parents=True, exist_ok=True)
    write_outputs(rows, keys, args.seed)
    ok = all(r["round_trip_ok"] for r in rows)
    print(f"round trip {'OK' if ok else 'GAGAL'}, hasil di tests/results/benchmark.md")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
