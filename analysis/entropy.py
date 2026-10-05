"""A-04 dan A-06: entropi Shannon plaintext vs ciphertext dan chi-square byte ciphertext

Jalankan: uv run python analysis/entropy.py [--seed N] [--include-large]
"""

import argparse
import csv
import pathlib
import random

import numpy as np

from tk_cipher.cipher import BLOCK_SIZE
from tk_cipher.fileformat import encrypt_bytes
from tk_cipher.modes import Mode

SEED = 20261006
ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
RESULTS = ROOT / "tests" / "results"
SKIP = {".gitkeep", "README.md", "make_large.py"}
HEADER_SIZE = 32
TAG_SIZE = BLOCK_SIZE
CHI2_CRITICAL = 293.248  # df 255, alpha 0.05


def sample_files(include_large: bool) -> list[pathlib.Path]:
    skip = SKIP if include_large else SKIP | {"large.bin"}
    return sorted(p for p in DATA.iterdir() if p.is_file() and p.name not in skip)


def byte_counts(data: bytes) -> np.ndarray:
    return np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)


def shannon_entropy(data: bytes) -> float:
    """Entropi Shannon dalam bit per byte, maksimum 8"""
    counts = byte_counts(data)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def chi_square(data: bytes) -> float:
    """Chi-square uniformitas 256 nilai byte, df 255"""
    expected = len(data) / 256
    return float(((byte_counts(data) - expected) ** 2 / expected).sum())


def repeated_blocks(ciphertext: bytes) -> int:
    """Jumlah blok 16 byte yang merupakan duplikat blok lain (tanda kebocoran ECB)"""
    blocks = [ciphertext[i : i + BLOCK_SIZE] for i in range(0, len(ciphertext), 16)]
    return len(blocks) - len(set(blocks))


def measure(
    files: list[pathlib.Path], key: bytes, iv: bytes
) -> tuple[list[dict], list[dict]]:
    entropy_rows, chi_rows = [], []
    for path in files:
        plaintext = path.read_bytes()
        h_pt = shannon_entropy(plaintext)
        for mode in Mode:
            blob = encrypt_bytes(plaintext, key, mode, None if mode == Mode.ECB else iv)
            ciphertext = blob[HEADER_SIZE:-TAG_SIZE]
            chi2 = chi_square(ciphertext)
            entropy_rows.append(
                {
                    "file": path.name,
                    "mode": mode.name,
                    "plaintext_bytes": len(plaintext),
                    "entropy_plaintext": round(h_pt, 6),
                    "entropy_ciphertext": round(shannon_entropy(ciphertext), 6),
                }
            )
            chi_rows.append(
                {
                    "file": path.name,
                    "mode": mode.name,
                    "ciphertext_bytes": len(ciphertext),
                    "chi2": round(chi2, 3),
                    "critical": CHI2_CRITICAL,
                    "lolos": chi2 <= CHI2_CRITICAL,
                    "repeated_blocks": repeated_blocks(ciphertext),
                }
            )
            h_ct = entropy_rows[-1]["entropy_ciphertext"]
            print(f"{path.name:16s} {mode.name}  H={h_ct:.4f}  chi2={chi2:.1f}")
    return entropy_rows, chi_rows


def write_csv(rows: list[dict], seed: int, path: pathlib.Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["seed", *rows[0]])
        writer.writeheader()
        writer.writerows({"seed": seed, **row} for row in rows)


def write_summary(
    entropy_rows: list[dict],
    chi_rows: list[dict],
    seed: int,
    key: bytes,
    iv: bytes,
    path: pathlib.Path,
) -> None:
    lines = [
        "# Entropi dan Chi-square (A-04, A-06)",
        "",
        (
            f"Skrip: `analysis/entropy.py`, seed `{seed}` (key `{key.hex()}`, IV "
            f"`{iv.hex()}`). Data: `entropy.csv` dan `chi_square.csv`."
        ),
        "",
        "## Metode",
        "",
        (
            "- Tiap file di `tests/data/` dienkripsi dengan `encrypt_bytes` di 5 mode, "
            "key dan IV tetap (ECB tanpa IV). Yang diukur hanya bagian ciphertext, "
            "tanpa header 32 byte dan tag 16 byte."
        ),
        "- Entropi Shannon: `H = -sum(p_i * log2(p_i))` atas 256 nilai byte, maks 8.",
        (
            "- Chi-square: `sum((O_i - E)^2 / E)`, `E = jumlah_byte / 256`, df 255. "
            f"Lolos kalau `chi2 <= {CHI2_CRITICAL}` (alpha 0.05)."
        ),
        "",
        "## Hasil",
        "",
        "| File | Mode | H plaintext | H ciphertext | chi2 | Lolos | Blok berulang |",
        "| :--- | :--- | ---: | ---: | ---: | :---: | ---: |",
    ]
    for e, c in zip(entropy_rows, chi_rows):
        lines.append(
            f"| {e['file']} | {e['mode']} | {e['entropy_plaintext']:.4f} "
            f"| {e['entropy_ciphertext']:.4f} | {c['chi2']:.1f} "
            f"| {'ya' if c['lolos'] else 'tidak'} | {c['repeated_blocks']} |"
        )

    ecb = next(
        (e, c)
        for e, c in zip(entropy_rows, chi_rows)
        if e["file"] == "repetitive.bin" and e["mode"] == "ECB"
    )
    others = [
        (e, c)
        for e, c in zip(entropy_rows, chi_rows)
        if e["file"] == "repetitive.bin" and e["mode"] != "ECB"
    ]
    ecb_leaks = [
        (e, c)
        for e, c in zip(entropy_rows, chi_rows)
        if e["mode"] == "ECB" and e["file"] != "repetitive.bin" and c["repeated_blocks"]
    ]
    ecb_clean = [
        e["file"]
        for e, c in zip(entropy_rows, chi_rows)
        if e["mode"] == "ECB" and not c["repeated_blocks"]
    ]
    chained = [(e, c) for e, c in zip(entropy_rows, chi_rows) if e["mode"] != "ECB"]
    failed = [
        f"{e['file']} {e['mode']} (chi2 {c['chi2']:.1f})"
        for e, c in chained
        if not c["lolos"]
    ]
    lines += [
        "",
        "## Kesimpulan",
        "",
        (
            f"**ECB pada `repetitive.bin` gagal total:** entropi ciphertext cuma "
            f"{ecb[0]['entropy_ciphertext']:.4f} bit/byte (plaintext "
            f"{ecb[0]['entropy_plaintext']:.4f}) dan chi2 {ecb[1]['chi2']:.0f}, jauh "
            f"di atas {CHI2_CRITICAL}. File ini pola 16 byte yang sama diulang, dan "
            "ECB mengenkripsi tiap blok sendiri-sendiri, jadi blok plaintext yang "
            "identik selalu jadi blok ciphertext yang identik: "
            f"{ecb[1]['repeated_blocks']} dari {ecb[1]['ciphertext_bytes'] // 16} "
            "blok ciphertext adalah duplikat. Polanya bocor utuh."
        ),
        "",
        (
            "Mode lain pada file yang sama (CBC, CFB, OFB, CTR) mencapai entropi "
            f"{min(e['entropy_ciphertext'] for e, _ in others):.4f} sampai "
            f"{max(e['entropy_ciphertext'] for e, _ in others):.4f}, lolos "
            "chi-square, dan tidak punya blok berulang, karena tiap blok dicampur "
            "dengan IV, ciphertext sebelumnya, atau counter."
        ),
        "",
    ]
    if ecb_leaks:
        leak_text = " dan ".join(
            f"`{e['file']}` ({c['repeated_blocks']} blok berulang, H "
            f"{e['entropy_ciphertext']:.4f}, chi2 {c['chi2']:.1f})"
            for e, c in ecb_leaks
        )
        lines += [
            (
                f"Kebocoran yang sama terlihat di ECB pada {leak_text}: plaintext-nya "
                "punya blok 16 byte yang kembar (area warna solid di gambar, potongan "
                "kalimat yang terulang di teks). ECB pada "
                f"{' dan '.join(f'`{f}`' for f in ecb_clean)} lolos karena "
                "plaintext-nya tidak punya blok kembar, bukan karena ECB aman."
            ),
            "",
        ]
    lines.append(
        "Mode CBC, CFB, OFB, dan CTR punya entropi ciphertext >= "
        f"{min(e['entropy_ciphertext'] for e, _ in chained):.4f} bit/byte di semua "
        "file, termasuk teks dan gambar yang entropi plaintext-nya jauh di bawah 8. "
        + (
            f"Semua {len(chained)} kombinasinya lolos chi-square."
            if not failed
            else (
                f"{len(chained) - len(failed)} dari {len(chained)} lolos chi-square; "
                f"yang tidak: {', '.join(failed)}, tanpa blok berulang. Dengan alpha "
                "0.05, data yang benar-benar acak pun diharapkan gagal sekitar 5% "
                f"(~{len(chained) * 0.05:.0f} dari {len(chained)}), jadi ini fluktuasi "
                "statistik, bukan pola."
            )
        )
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument(
        "--include-large", action="store_true", help="ikutkan large.bin (lama)"
    )
    args = parser.parse_args()

    rng = random.Random(args.seed)
    key = rng.randbytes(16)
    iv = rng.randbytes(BLOCK_SIZE)

    entropy_rows, chi_rows = measure(sample_files(args.include_large), key, iv)

    RESULTS.mkdir(parents=True, exist_ok=True)
    write_csv(entropy_rows, args.seed, RESULTS / "entropy.csv")
    write_csv(chi_rows, args.seed, RESULTS / "chi_square.csv")
    write_summary(
        entropy_rows, chi_rows, args.seed, key, iv, RESULTS / "entropy_summary.md"
    )


if __name__ == "__main__":
    main()
