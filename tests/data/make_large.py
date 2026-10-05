"""Bikin file uji biner deterministik dari counter, default large.bin 5 MiB"""

import argparse
from pathlib import Path

DEFAULT_SIZE = 5 * 1024 * 1024
DEFAULT_SEED = 2
MULT = 1664525
INC = 1013904223


def generate(size: int, seed: int) -> bytes:
    """Hasilkan size byte dari LCG 32-bit, hasilnya sama persis tiap dipanggil"""
    state = seed & 0xFFFFFFFF
    out = bytearray()
    while len(out) < size:
        state = (state * MULT + INC) & 0xFFFFFFFF
        out += state.to_bytes(4, "big")
    return bytes(out[:size])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="large.bin")
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    path = Path(__file__).resolve().parent / args.name
    path.write_bytes(generate(args.size, args.seed))
    print(f"{path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
