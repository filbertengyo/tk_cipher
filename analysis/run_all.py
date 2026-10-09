import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = [
    "sbox_stats.py",
    "round_diffusion.py",
    "avalanche.py",
    "entropy.py",
    "histogram.py",
    "benchmark.py",
]


def run(cmd: list[str]) -> bool:
    start = time.perf_counter()
    result = subprocess.run(cmd, cwd=ROOT, check=False)
    print(
        f"{'OK  ' if result.returncode == 0 else 'GAGAL'} {' '.join(cmd[1:])} ({time.perf_counter() - start:.0f} s)"
    )
    return result.returncode == 0


def main() -> int:
    ok = True
    if not (ROOT / "tests" / "data" / "large.bin").exists():
        ok &= run([sys.executable, "tests/data/make_large.py"])
    for name in SCRIPTS:
        ok &= run([sys.executable, f"analysis/{name}"])
    print("semua analisis selesai" if ok else "ada analisis yang gagal")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
