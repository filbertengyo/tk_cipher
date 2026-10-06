"""A-07: statistik S-box dinamis (DU, NL, attempts, waktu) dan review threshold"""

import argparse
import csv
import pathlib
import random
import statistics
import time
from collections import Counter

from tk_cipher.prng import TKRand
from tk_cipher.sbox import (
    KEY_SIZES,
    MAX_DU,
    MIN_NL,
    SEED_PREFIX,
    _fix_points,
    _shuffle,
    differential_uniformity,
    generate_sbox,
    nonlinearity,
)

SEED = 20261006
KEYS_PER_SIZE = 100
CANDIDATES_PER_KEY = 2  # kandidat sebelum filter, dari stream TKRand yang sama
RESULTS = pathlib.Path(__file__).resolve().parent.parent / "tests" / "results"
# pasangan (max DU, min NL) yang dibandingin, yang pertama threshold sekarang
THRESHOLDS = [(MAX_DU, MIN_NL), (14, 88), (12, 92), (10, 90), (10, 92)]


def generate_stats(keys: list[bytes]) -> list[dict]:
    rows = []
    for key in keys:
        start = time.perf_counter()
        sbox = generate_sbox(key)
        ms = (time.perf_counter() - start) * 1000
        rows.append(
            {
                "key_bits": len(key) * 8,
                "key": key.hex(),
                "differential_uniformity": sbox.differential_uniformity,
                "nonlinearity": sbox.nonlinearity,
                "attempts": sbox.attempts,
                "time_ms": round(ms, 3),
            }
        )
    return rows


def candidate_stats(keys: list[bytes]) -> list[dict]:
    """Ukur kandidat S-box sebelum filter kualitas, persis kayak generate_sbox"""
    rows = []
    for key in keys:
        rng = TKRand(SEED_PREFIX + key + bytes([len(key)]))
        for i in range(CANDIDATES_PER_KEY):
            start = time.perf_counter()
            s = _shuffle(rng)
            _fix_points(s, rng)
            du, nl = differential_uniformity(s), nonlinearity(s)
            ms = (time.perf_counter() - start) * 1000
            rows.append(
                {
                    "key": key.hex(),
                    "candidate": i + 1,
                    "differential_uniformity": du,
                    "nonlinearity": nl,
                    "time_ms": round(ms, 3),
                }
            )
    return rows


def write_csv(rows: list[dict], seed: int, path: pathlib.Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["seed", *rows[0]])
        writer.writeheader()
        writer.writerows({"seed": seed, **row} for row in rows)


def describe(values: list[float]) -> str:
    stats = min(values), max(values), statistics.mean(values), statistics.median(values)
    return " | ".join(f"{v:.2f}".rstrip("0").rstrip(".") for v in stats)


def histogram(values: list[int], label: str) -> list[str]:
    counts = Counter(values)
    total = len(values)
    lines = [f"| {label} | Jumlah | % | |", "| ---: | ---: | ---: | :--- |"]
    for v in sorted(counts):
        pct = counts[v] * 100 / total
        bar = "#" * max(1, round(pct / 2))
        lines.append(f"| {v} | {counts[v]} | {pct:.1f}% | `{bar}` |")
    return lines


def threshold_table(cands: list[dict]) -> tuple[list[str], dict]:
    eval_ms = statistics.mean(c["time_ms"] for c in cands)
    lines = [
        "| Threshold | Lolos | Ekspektasi attempts | Estimasi waktu generate |",
        "| :--- | ---: | ---: | ---: |",
    ]
    expected = {}
    for du, nl in THRESHOLDS:
        passed = sum(
            c["differential_uniformity"] <= du and c["nonlinearity"] >= nl
            for c in cands
        )
        rate = passed / len(cands)
        attempts = 1 / rate if rate else float("inf")
        expected[(du, nl)] = attempts
        mark = " (sekarang)" if (du, nl) == (MAX_DU, MIN_NL) else ""
        lines.append(
            f"| DU <= {du}, NL >= {nl}{mark} | {rate * 100:.1f}% "
            f"| {attempts:.2f} | ~{attempts * eval_ms:.0f} ms |"
        )
    return lines, expected


def write_summary(
    gen: list[dict], cands: list[dict], seed: int, path: pathlib.Path
) -> None:
    attempts = [r["attempts"] for r in gen]
    table, expected = threshold_table(cands)
    current = expected[(MAX_DU, MIN_NL)]
    stricter = expected[(10, 90)]
    nl92 = expected[(12, 92)]
    weak_du = sum(c["differential_uniformity"] > MAX_DU for c in cands)
    weak_nl = sum(c["nonlinearity"] < MIN_NL for c in cands)

    lines = [
        "# Statistik S-box Dinamis (A-07)",
        "",
        (
            f"Skrip: `analysis/sbox_stats.py`, seed `{seed}`. Data: "
            "`sbox_stats.csv` (per key) dan `sbox_candidates.csv` (kandidat "
            "sebelum filter)."
        ),
        "",
        "## Metode",
        "",
        (
            f"- {KEYS_PER_SIZE} key acak per ukuran (128, 192, 256-bit), total "
            f"{len(gen)} key, masing-masing lewat `generate_sbox`."
        ),
        (
            "- Dicatat DU, NL, `attempts`, dan waktu generate (ms) per key. DU, NL, "
            "dan attempts deterministik per seed; waktu tergantung mesin."
        ),
        (
            f"- Untuk review threshold, {CANDIDATES_PER_KEY} kandidat pertama per key "
            f"(total {len(cands)}) diukur **sebelum** filter, memakai shuffle dan "
            "fix-up yang sama dengan `generate_sbox`."
        ),
        "",
        "## S-box yang dihasilkan (sesudah filter)",
        "",
        "| Statistik | min | max | mean | median |",
        "| :--- | ---: | ---: | ---: | ---: |",
        f"| DU | {describe([r['differential_uniformity'] for r in gen])} |",
        f"| NL | {describe([r['nonlinearity'] for r in gen])} |",
        f"| attempts | {describe(attempts)} |",
        f"| waktu (ms) | {describe([r['time_ms'] for r in gen])} |",
        "",
        *histogram([r["differential_uniformity"] for r in gen], "DU"),
        "",
        *histogram([r["nonlinearity"] for r in gen], "NL"),
        "",
        *histogram(attempts, "attempts"),
        "",
        "## Kandidat sebelum filter",
        "",
        *histogram([c["differential_uniformity"] for c in cands], "DU"),
        "",
        *histogram([c["nonlinearity"] for c in cands], "NL"),
        "",
        "## Perbandingan threshold",
        "",
        *table,
        "",
        "## Keputusan",
        "",
    ]
    if current <= 2 and stricter >= 2 * current:
        lines += [
            f"**Threshold dipertahankan: DU <= {MAX_DU}, NL >= {MIN_NL}.**",
            "",
            (
                f"- Threshold ini membuang ekor terlemah kandidat: "
                f"{weak_du * 100 / len(cands):.1f}% kandidat punya DU > {MAX_DU} "
                f"dan {weak_nl * 100 / len(cands):.1f}% punya NL < {MIN_NL}."
            ),
            (
                f"- Biayanya kecil: rata-rata {statistics.mean(attempts):.2f} attempts "
                f"per key (ekspektasi {current:.2f})."
            ),
            (
                f"- Memperketat ke DU <= 10 butuh ~{stricter:.1f} attempts "
                f"({stricter / current:.1f}x lebih lama) untuk satu tingkat DU, "
                "padahal S-box acak 8-bit memang umumnya di DU 10 sampai 12, jauh "
                "dari S-box aljabar seperti AES (DU 4, NL 112). Keamanan TK-Cipher "
                "bertumpu pada 16 ronde (margin 4x di atas full diffusion, "
                "`round_diffusion.md`), bukan pada S-box yang optimal."
            ),
            (
                f"- NL >= 92 memang murah (~{nl92:.2f} attempts), tapi hanya "
                "menurunkan bias linear maksimum dari 38/256 ke 36/256. Selisih "
                "sekecil itu tidak "
                "sebanding dengan mengganti semua test vector."
            ),
            (
                "- Karena threshold tidak berubah, test vector di `tests/vectors.json` "
                "tetap berlaku."
            ),
        ]
    else:
        lines += [
            (
                "**Threshold perlu ditinjau ulang:** biaya threshold sekarang "
                f"({current:.2f} attempts) atau selisihnya dengan DU <= 10 "
                f"({stricter:.2f} attempts) tidak sesuai asumsi. Diskusikan di issue "
                "#18 sebelum mengubah `MAX_DU` / `MIN_NL`."
            ),
        ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=SEED)
    seed = parser.parse_args().seed

    rng = random.Random(seed)
    keys = [rng.randbytes(n) for n in KEY_SIZES for _ in range(KEYS_PER_SIZE)]

    gen = generate_stats(keys)
    cands = candidate_stats(keys)

    RESULTS.mkdir(parents=True, exist_ok=True)
    write_csv(gen, seed, RESULTS / "sbox_stats.csv")
    write_csv(cands, seed, RESULTS / "sbox_candidates.csv")
    write_summary(gen, cands, seed, RESULTS / "sbox_stats.md")
    print((RESULTS / "sbox_stats.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
