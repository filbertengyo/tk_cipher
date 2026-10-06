"""A-05: histogram byte plaintext vs ciphertext per file dan mode, plus visual ECB vs CBC"""

import argparse
import pathlib
import random
import struct
from multiprocessing import Pool

import matplotlib.pyplot as plt
import numpy as np

from tk_cipher.cipher import BLOCK_SIZE, TKCipher
from tk_cipher.modes import Mode, encrypt
from tk_cipher.padding import pad

SEED = 20261006
ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
RESULTS = ROOT / "tests" / "results"
FILES = ["text_small.txt", "repetitive.bin", "image.bmp", "binary.png", "medium.bin"]

BLUE = "#2a78d6"
INK = "#0b0b0b"
MUTED = "#52514e"
GRID = "#e4e3df"


def key_and_iv(seed: int) -> tuple[bytes, bytes]:
    """Key 128-bit dan IV tetap dari seed biar hasil bisa diulang"""
    rng = random.Random(seed)
    return rng.randbytes(16), rng.randbytes(BLOCK_SIZE)


def encrypt_data(data: bytes, mode: Mode, key: bytes, iv: bytes) -> bytes:
    """Enkripsi data ber-padding pakai modes.encrypt langsung, tanpa header dan tag"""
    return encrypt(TKCipher(key), mode, pad(data), None if mode == Mode.ECB else iv)


def style(ax) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.grid(axis="y", color=GRID, lw=0.8)
    ax.set_axisbelow(True)


def plot_histogram(task: tuple) -> str:
    name, mode, key, iv, seed = task
    plain = (DATA / name).read_bytes()
    cipher = encrypt_data(plain, mode, key, iv)
    plt.rcParams.update({"text.color": INK, "axes.labelcolor": MUTED})
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.8))
    for ax, data, label in (
        (axes[0], plain, "Plaintext"),
        (axes[1], cipher, "Ciphertext"),
    ):
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        ax.bar(np.arange(256), counts, width=1.0, color=BLUE, lw=0)
        ax.set_xlim(-1, 256)
        ax.set_xticks([0, 64, 128, 192, 255])
        ax.set_xlabel("Nilai byte")
        ax.set_ylabel("Frekuensi")
        ax.set_title(
            f"{label}  ·  {len(data):,} byte", loc="left", fontsize=11, color=INK
        )
        style(ax)
    fig.suptitle(
        f"Histogram byte {name}  ·  mode {mode.name}  ·  seed {seed}",
        x=0.01,
        ha="left",
        fontsize=12,
        color=INK,
    )
    fig.tight_layout()
    out = RESULTS / f"histogram_{pathlib.Path(name).stem}_{mode.name.lower()}.png"
    fig.savefig(out, dpi=120, facecolor="white")
    plt.close(fig)
    return out.name


def split_bmp(data: bytes) -> tuple[bytes, bytes, int, int]:
    """Pisahkan header dan piksel BMP 24-bit, return header, piksel, lebar, tinggi"""
    offset = struct.unpack_from("<I", data, 10)[0]
    width, height = struct.unpack_from("<ii", data, 18)
    return data[:offset], data[offset:], width, height


def bmp_to_rgb(pixels: bytes, width: int, height: int) -> np.ndarray:
    row = (width * 3 + 3) // 4 * 4
    arr = np.frombuffer(pixels[: row * abs(height)], dtype=np.uint8).reshape(
        abs(height), row
    )
    rgb = arr[:, : width * 3].reshape(abs(height), width, 3)[:, :, ::-1]
    return rgb[::-1] if height > 0 else rgb


def ecb_vs_cbc(key: bytes, iv: bytes, seed: int) -> list[str]:
    header, pixels, width, height = split_bmp((DATA / "image.bmp").read_bytes())
    images = [("Asli", pixels)]
    written = []
    for mode in (Mode.ECB, Mode.CBC):
        enc = encrypt_data(pixels, mode, key, iv)[: len(pixels)]
        out = RESULTS / f"image_{mode.name.lower()}.bmp"
        out.write_bytes(header + enc)
        written.append(out.name)
        images.append((mode.name, enc))

    fig, axes = plt.subplots(1, 3, figsize=(11, 4.2))
    for ax, (label, px) in zip(axes, images):
        ax.imshow(bmp_to_rgb(px, width, height), interpolation="nearest")
        ax.set_title(label, loc="left", fontsize=11, color=INK)
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_color(GRID)
    fig.suptitle(
        f"image.bmp: piksel dienkripsi, header BMP utuh  ·  seed {seed}",
        x=0.01,
        ha="left",
        fontsize=12,
        color=INK,
    )
    fig.tight_layout()
    fig.savefig(RESULTS / "ecb_vs_cbc.png", dpi=120, facecolor="white")
    plt.close(fig)
    return [*written, "ecb_vs_cbc.png"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--workers", type=int, default=None)
    args = parser.parse_args()

    key, iv = key_and_iv(args.seed)
    RESULTS.mkdir(parents=True, exist_ok=True)
    tasks = [(name, mode, key, iv, args.seed) for name in FILES for mode in Mode]
    with Pool(args.workers) as pool:
        written = pool.map(plot_histogram, tasks, chunksize=1)
    written += ecb_vs_cbc(key, iv, args.seed)
    print(f"seed {args.seed}, key {key.hex()}, iv {iv.hex()}, {len(written)} files")


if __name__ == "__main__":
    main()
