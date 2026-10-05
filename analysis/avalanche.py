"""A-01 dan A-02: avalanche flip 1 bit plaintext dan flip 1 bit key di kelima mode

Jalankan: uv run python analysis/avalanche.py [--seed N] [--workers N]
"""

import argparse
import csv
import pathlib
import random
import statistics
from multiprocessing import Pool

from tk_cipher.cipher import BLOCK_SIZE, TKCipher
from tk_cipher.fileformat import encrypt_bytes
from tk_cipher.modes import Mode, encrypt
from tk_cipher.sbox import KEY_SIZES

SEED = 20261006
PT_SAMPLES = 1000
KEY_SAMPLES = 300
FULL_SAMPLES = 50
BLOCKS = 4
PT_LEN = BLOCKS * BLOCK_SIZE
BITS = BLOCK_SIZE * 8
ONE_BIT_PCT = 100.0 / BITS
RESULTS = pathlib.Path(__file__).resolve().parent.parent / "tests" / "results"
MODES = list(Mode)


def flip(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


def block_pcts(a: bytes, b: bytes) -> list[float]:
    """Persen bit yang beda per blok 16 byte antara dua ciphertext"""
    pcts = []
    for i in range(0, len(a), BLOCK_SIZE):
        diff = int.from_bytes(a[i : i + BLOCK_SIZE], "big") ^ int.from_bytes(
            b[i : i + BLOCK_SIZE], "big"
        )
        pcts.append(diff.bit_count() * 100.0 / BITS)
    return pcts


def total_pct(a: bytes, b: bytes) -> float:
    diff = int.from_bytes(a, "big") ^ int.from_bytes(b, "big")
    return diff.bit_count() * 100.0 / (len(a) * 8)


def plaintext_task(task: tuple) -> dict:
    mode, sample, key, pt, iv, bit = task
    cipher = TKCipher(key)
    base = encrypt(cipher, mode, pt, iv)
    changed = encrypt(cipher, mode, flip(pt, bit), iv)
    blocks = block_pcts(base, changed)
    return {
        "mode": mode.name,
        "sample": sample,
        "flip_bit": bit,
        "flip_block": bit // BITS,
        "total_pct": total_pct(base, changed),
        **{f"block{i}_pct": p for i, p in enumerate(blocks)},
    }


def key_task(task: tuple) -> dict:
    path, mode, sample, key, pt, iv, bit = task
    other = flip(key, bit)
    if path == "cipher":
        base = encrypt(TKCipher(key), mode, pt, iv)
        changed = encrypt(TKCipher(other), mode, pt, iv)
    else:
        base = encrypt_bytes(pt, key, mode, iv)[32:-BLOCK_SIZE]
        changed = encrypt_bytes(pt, other, mode, iv)[32:-BLOCK_SIZE]
    row = {
        "path": path,
        "mode": mode.name,
        "sample": sample,
        "key_bits": len(key) * 8,
        "flip_bit": bit,
        "total_pct": total_pct(base, changed),
    }
    blocks = block_pcts(base, changed)[:BLOCKS]
    row.update({f"block{i}_pct": p for i, p in enumerate(blocks)})
    return row


def make_tasks(rng: random.Random) -> tuple[list, list]:
    pt_tasks, key_tasks = [], []
    for mode in MODES:
        for n in range(PT_SAMPLES):
            key = rng.randbytes(16)
            pt = rng.randbytes(PT_LEN)
            iv = None if mode == Mode.ECB else rng.randbytes(BLOCK_SIZE)
            pt_tasks.append((mode, n, key, pt, iv, rng.randrange(PT_LEN * 8)))
        for path, count in (("cipher", KEY_SAMPLES), ("full", FULL_SAMPLES)):
            for n in range(count):
                key = rng.randbytes(KEY_SIZES[n % len(KEY_SIZES)])
                pt = rng.randbytes(PT_LEN)
                iv = None if mode == Mode.ECB else rng.randbytes(BLOCK_SIZE)
                key_tasks.append(
                    (path, mode, n, key, pt, iv, rng.randrange(len(key) * 8))
                )
    return pt_tasks, key_tasks


def stats(values: list[float]) -> dict:
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "min": min(values),
        "max": max(values),
        "std": statistics.pstdev(values),
    }


def fmt(s: dict) -> str:
    return f"{s['mean']:.2f} | {s['min']:.2f} | {s['max']:.2f} | {s['std']:.2f}"


def write_csv(rows: list[dict], path: pathlib.Path) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {k: round(v, 4) if isinstance(v, float) else v for k, v in row.items()}
            )


def relation_values(rows: list[dict], mode: Mode) -> dict[str, list[float]]:
    """Kelompokkan persen per blok jadi sebelum, sama dengan, dan sesudah blok yang di-flip"""
    groups: dict[str, list[float]] = {"before": [], "same": [], "after": []}
    for r in rows:
        if r["mode"] != mode.name:
            continue
        for i in range(BLOCKS):
            rel = (
                "before"
                if i < r["flip_block"]
                else "same"
                if i == r["flip_block"]
                else "after"
            )
            groups[rel].append(r[f"block{i}_pct"])
    return groups


def check_plaintext(mode: Mode, groups: dict[str, list[float]]) -> list[str]:
    """Bandingkan hasil dengan tabel ekspektasi, return daftar penyimpangan"""
    notes = []

    def near_half(values: list[float]) -> bool:
        return 48.0 <= statistics.fmean(values) <= 52.0

    def one_bit(values: list[float]) -> bool:
        return all(abs(v - ONE_BIT_PCT) < 1e-9 for v in values)

    if not all(v == 0 for v in groups["before"]):
        notes.append("blok sebelum blok yang di-flip berubah")
    if mode == Mode.ECB:
        if not near_half(groups["same"]):
            notes.append("blok yang di-flip tidak sekitar 50%")
        if not all(v == 0 for v in groups["after"]):
            notes.append("blok sesudahnya berubah")
    elif mode == Mode.CBC:
        if not near_half(groups["same"] + groups["after"]):
            notes.append("blok i dan sesudahnya tidak sekitar 50%")
    elif mode == Mode.CFB:
        if not one_bit(groups["same"]):
            notes.append("blok i tidak tepat 1 bit")
        if not near_half(groups["after"]):
            notes.append("blok sesudahnya tidak sekitar 50%")
    else:
        if not one_bit(groups["same"]):
            notes.append("blok i tidak tepat 1 bit")
        if not all(abs(v) < 1e-9 for v in groups["after"]):
            notes.append("blok sesudahnya berubah")
    return notes


def write_summary(
    pt_rows: list[dict], key_rows: list[dict], seed: int, path: pathlib.Path
) -> None:
    lines = [
        "# Avalanche plaintext dan key",
        "",
        f"Seed: `{seed}`. Semua nilai dalam persen bit ciphertext yang berubah, ideal sekitar 50%.",
        "Dibuat oleh `analysis/avalanche.py`, data mentah di `avalanche_plaintext.csv` dan `avalanche_key.csv`.",
        "",
        "## A-01 Flip 1 bit plaintext",
        "",
        f"{PT_SAMPLES} sampel per mode, key 128-bit acak, plaintext {BLOCKS} blok, IV sama untuk dua run.",
        "",
        "### Statistik per blok ciphertext",
        "",
        "| Mode | Blok | Mean | Min | Max | Std |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for mode in MODES:
        rows = [r for r in pt_rows if r["mode"] == mode.name]
        for i in range(BLOCKS):
            lines.append(
                f"| {mode.name} | {i} | {fmt(stats([r[f'block{i}_pct'] for r in rows]))} |"
            )
        lines.append(
            f"| {mode.name} | total | {fmt(stats([r['total_pct'] for r in rows]))} |"
        )
    lines += [
        "",
        "### Blok ciphertext relatif terhadap blok plaintext yang di-flip",
        "",
        "| Mode | Posisi | Mean | Min | Max | Std |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    deviations: list[str] = []
    for mode in MODES:
        groups = relation_values(pt_rows, mode)
        for rel, label in (
            ("before", "sebelum"),
            ("same", "sama"),
            ("after", "sesudah"),
        ):
            lines.append(f"| {mode.name} | {label} | {fmt(stats(groups[rel]))} |")
        deviations += [f"{mode.name}: {n}" for n in check_plaintext(mode, groups)]
    lines += ["", "Satu bit dari 128 bit adalah " + f"{ONE_BIT_PCT:.2f}%.", ""]

    lines += [
        "## A-02 Flip 1 bit key",
        "",
        "Plaintext dan IV sama, master key beda 1 bit. Ukuran key bergantian 128, 192, 256-bit.",
        f"Jalur `cipher` adalah `TKCipher` plus mode ({KEY_SAMPLES} sampel per mode), jalur `full` adalah",
        f"`encrypt_bytes` lengkap dengan KDF dan MAC, hanya bagian ciphertext yang dibandingkan ({FULL_SAMPLES} sampel per mode).",
        "",
        "| Jalur | Mode | Mean | Min | Max | Std |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for path_name in ("cipher", "full"):
        for mode in MODES:
            rows = [
                r for r in key_rows if r["path"] == path_name and r["mode"] == mode.name
            ]
            s = stats([r["total_pct"] for r in rows])
            lines.append(f"| {path_name} | {mode.name} | {fmt(s)} |")
            if not 48.0 <= s["mean"] <= 52.0:
                deviations.append(
                    f"key {path_name} {mode.name}: mean {s['mean']:.2f}% di luar 48 sampai 52"
                )
    lines += ["", "## Kesesuaian dengan ekspektasi", ""]
    if deviations:
        lines += [f"- {d}" for d in deviations]
    else:
        lines += [
            "Semua hasil sesuai tabel ekspektasi: ECB hanya mengubah blok yang di-flip, CBC mengubah blok itu dan",
            "semua blok sesudahnya, CFB mengubah tepat 1 bit di blok itu lalu sekitar 50% di blok sesudahnya,",
            "OFB dan CTR hanya mengubah tepat 1 bit, dan flip 1 bit key mengubah sekitar 50% ciphertext di semua mode.",
        ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--workers", type=int, default=None)
    args = parser.parse_args()

    pt_tasks, key_tasks = make_tasks(random.Random(args.seed))
    with Pool(args.workers) as pool:
        pt_rows = pool.map(plaintext_task, pt_tasks, chunksize=20)
        key_rows = pool.map(key_task, key_tasks, chunksize=10)

    RESULTS.mkdir(parents=True, exist_ok=True)
    write_csv(pt_rows, RESULTS / "avalanche_plaintext.csv")
    write_csv(key_rows, RESULTS / "avalanche_key.csv")
    write_summary(pt_rows, key_rows, args.seed, RESULTS / "avalanche_summary.md")
    print(f"seed {args.seed}, {len(pt_rows)} plaintext rows, {len(key_rows)} key rows")


if __name__ == "__main__":
    main()
