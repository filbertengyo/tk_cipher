"""A-03: avalanche dan dependency bit per jumlah ronde 1..16 untuk justifikasi 16 ronde

Jalankan: uv run python analysis/round_diffusion.py [--seed N]
"""

import argparse
import csv
import pathlib
import random

import matplotlib.pyplot as plt
import numpy as np

from tk_cipher.cipher import BLOCK_SIZE, ROUNDS, TKCipher

SEED = 20261005
N_KEYS = 8
PT_PER_KEY = 8  # tiap plaintext di-flip di semua 128 bit => 64 sampel per bit input
BITS = BLOCK_SIZE * 8
AVALANCHE_TOL = 1.0  # full diffusion: |mean - 50| <= 1 poin persen
RESULTS = pathlib.Path(__file__).resolve().parent.parent / "tests" / "results"

BLUE = "#2a78d6"
INK = "#0b0b0b"
MUTED = "#52514e"
GRID = "#e4e3df"


def flip(block: bytes, bit: int) -> bytes:
    out = bytearray(block)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


def measure(rounds: int, keys: list[bytes], plaintexts: list[list[bytes]]) -> dict:
    diffs = np.empty((N_KEYS * PT_PER_KEY, BITS, BLOCK_SIZE), dtype=np.uint8)
    n = 0
    for key, pts in zip(keys, plaintexts):
        c = TKCipher(key, rounds=rounds)
        for pt in pts:
            base = np.frombuffer(c.encrypt_block(pt), dtype=np.uint8)
            for i in range(BITS):
                ct = np.frombuffer(c.encrypt_block(flip(pt, i)), dtype=np.uint8)
                diffs[n, i] = base ^ ct
            n += 1
    bits = np.unpackbits(diffs, axis=2)  # (sampel, bit input, bit output)
    avalanche = bits.sum(axis=2).ravel() * 100.0 / BITS
    pair_prob = bits.mean(axis=0)  # peluang bit output j berubah saat bit i di-flip
    pairs = int((pair_prob > 0).sum())
    mean = float(avalanche.mean())
    return {
        "rounds": rounds,
        "samples": avalanche.size,
        "avalanche_mean": round(mean, 4),
        "avalanche_min": round(float(avalanche.min()), 4),
        "avalanche_max": round(float(avalanche.max()), 4),
        "avalanche_std": round(float(avalanche.std()), 4),
        "dependency_pairs": pairs,
        "dependency_pct": round(pairs * 100.0 / BITS**2, 4),
        "sac_min": round(float(pair_prob.min()), 4),
        "sac_max": round(float(pair_prob.max()), 4),
        "full_diffusion": pairs == BITS**2 and abs(mean - 50) <= AVALANCHE_TOL,
    }


def plot(rows: list[dict], full: int | None, seed: int, path: pathlib.Path) -> None:
    r = [row["rounds"] for row in rows]
    mean = np.array([row["avalanche_mean"] for row in rows])
    std = np.array([row["avalanche_std"] for row in rows])
    dep = [row["dependency_pct"] for row in rows]

    plt.rcParams.update({"font.size": 10, "text.color": INK, "axes.labelcolor": MUTED})
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2), sharex=True)
    panels = [
        (ax1, mean, "Avalanche plaintext (% bit ciphertext berubah)", 50, "50% ideal"),
        (ax2, dep, "Dependency bit (% dari 128 x 128 pasangan)", 100, "100%"),
    ]
    for ax, ys, title, ref, ref_label in panels:
        ax.axhline(ref, color=MUTED, lw=1, ls="--", zorder=1)
        ax.annotate(
            ref_label, (16, ref), xytext=(0, 4), textcoords="offset points",
            ha="right", va="bottom", color=MUTED, fontsize=9,
        )
        if full is not None:
            ax.axvline(full, color=MUTED, lw=1, ls=":", zorder=1)
        ax.plot(r, ys, color=BLUE, lw=2, marker="o", ms=5, zorder=3)
        ax.set_title(title, loc="left", fontsize=11, color=INK)
        ax.set_xlabel("Jumlah ronde")
        ax.set_xticks(range(1, ROUNDS + 1))
        ax.set_ylim(0, 105)
        ax.grid(axis="y", color=GRID, lw=0.8)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(GRID)
        ax.tick_params(colors=MUTED)
    ax1.fill_between(r, mean - std, mean + std, color=BLUE, alpha=0.15, lw=0)
    ax1.annotate(
        "~1 std", (2, mean[1] + std[1]), xytext=(4, 2), textcoords="offset points",
        color=MUTED, fontsize=9,
    )
    if full is not None:
        ax2.annotate(
            f"full diffusion: ronde {full}", (full, 50), xytext=(6, 0),
            textcoords="offset points", color=INK, fontsize=9,
        )
    n = rows[0]["samples"]
    fig.suptitle(
        f"TK-Cipher round diffusion  ·  {n} sampel per ronde  ·  seed {seed}",
        x=0.01, ha="left", fontsize=12, color=INK,
    )
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor="white")
    plt.close(fig)


def write_summary(
    rows: list[dict], full: int | None, seed: int, path: pathlib.Path
) -> None:
    n = rows[0]["samples"]
    lines = [
        "# Round Diffusion (A-03)",
        "",
        f"Skrip: `analysis/round_diffusion.py`, seed `{seed}`. Data: "
        "`round_diffusion.csv`, grafik: `round_diffusion.png`.",
        "",
        "## Metode",
        "",
        f"- {N_KEYS} key 128-bit acak x {PT_PER_KEY} plaintext acak per key. Tiap "
        f"plaintext di-flip di **semua** {BITS} bit satu per satu, jadi {n} sampel "
        f"per ronde dan {N_KEYS * PT_PER_KEY} sampel per bit input.",
        "- Avalanche: persen bit ciphertext yang berubah per sampel.",
        "- Dependency: pasangan (bit input i, bit output j) yang pernah berubah, "
        f"dari maksimum {BITS**2}.",
        "- SAC min/max: peluang terkecil/terbesar bit output j berubah saat bit i "
        "di-flip (ideal 0.5).",
        f"- Full diffusion: semua {BITS**2} pasangan ketemu dan "
        f"|mean avalanche - 50| <= {AVALANCHE_TOL} poin persen.",
        "- Cipher dipanggil lewat `TKCipher(key, rounds=r)` dari package `tk_cipher`.",
        "",
        "## Hasil",
        "",
        "| Ronde | Avalanche mean | min | max | std | Dependency | SAC min | SAC max |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['rounds']} | {row['avalanche_mean']:.2f}% "
            f"| {row['avalanche_min']:.2f}% | {row['avalanche_max']:.2f}% "
            f"| {row['avalanche_std']:.2f} "
            f"| {row['dependency_pairs']} ({row['dependency_pct']:.2f}%) "
            f"| {row['sac_min']:.3f} | {row['sac_max']:.3f} |"
        )
    lines += ["", "## Kesimpulan", ""]
    if full is None:
        lines.append(
            f"Full diffusion **tidak tercapai** sampai {ROUNDS} ronde. Jumlah ronde "
            "perlu didiskusikan di issue #15 sebelum `ROUNDS` diubah."
        )
    else:
        margin = ROUNDS / full
        lines.append(
            f"Full diffusion pertama kali tercapai di **ronde {full}**. Dengan "
            f"{ROUNDS} ronde, margin keamanannya {ROUNDS - full} ronde tambahan "
            f"({margin:.1f}x ronde full diffusion)."
        )
        lines.append("")
        lines.append(
            f"Di ronde {full - 1} dependency sudah "
            f"{rows[full - 2]['dependency_pct']:.2f}% dan avalanche "
            f"{rows[full - 2]['avalanche_mean']:.2f}%, jadi ronde {full} adalah batas "
            "konservatif. Sesudahnya avalanche stabil di sekitar 50% sampai ronde "
            f"{ROUNDS}."
        )
        lines.append("")
        verdict = (
            f"Margin {margin:.1f}x sebanding dengan AES-128 (full diffusion 2 ronde, "
            f"10 ronde, 5x), jadi {ROUNDS} ronde dianggap cukup dan `ROUNDS` tetap."
            if margin >= 4
            else f"Margin {margin:.1f}x jauh di bawah AES-128 (5x), jadi jumlah ronde "
            "perlu didiskusikan di issue #15 sebelum `ROUNDS` diubah."
        )
        lines.append(verdict)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=SEED)
    seed = parser.parse_args().seed

    rng = random.Random(seed)
    keys = [rng.randbytes(16) for _ in range(N_KEYS)]
    plaintexts = [[rng.randbytes(BLOCK_SIZE) for _ in range(PT_PER_KEY)] for _ in keys]

    rows = []
    for r in range(1, ROUNDS + 1):
        row = measure(r, keys, plaintexts)
        rows.append(row)
        print(
            f"ronde {r:2d}: avalanche {row['avalanche_mean']:6.2f}%  "
            f"dependency {row['dependency_pairs']:5d}/{BITS**2}"
        )
    full = next((row["rounds"] for row in rows if row["full_diffusion"]), None)

    RESULTS.mkdir(parents=True, exist_ok=True)
    with open(RESULTS / "round_diffusion.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["seed", *rows[0]])
        writer.writeheader()
        writer.writerows({"seed": seed, **row} for row in rows)
    plot(rows, full, seed, RESULTS / "round_diffusion.png")
    write_summary(rows, full, seed, RESULTS / "round_diffusion.md")
    print(f"full diffusion: ronde {full}")


if __name__ == "__main__":
    main()
