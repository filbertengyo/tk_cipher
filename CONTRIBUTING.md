# Contributing

## Setup

Project ini pakai [uv](https://docs.astral.sh/uv/). Dari root repo:

```bash
uv sync --all-groups
```

## Alur kerja

1. Ambil satu issue yang belum Blocked.
2. Bikin branch dari `main`, satu branch per issue.
3. Tulis kode dan test-nya.
4. Jalankan test (lihat bawah), lalu buka PR ke `main` dengan `Closes #<nomor issue>`.

Commit pakai conventional commits, contohnya `feat(cipher): add key schedule`.

## Lint dan test

CI jalanin lint (ruff) dan test di Linux dan Windows setiap ada push dan PR. Jalankan dulu di lokal biar nggak merah:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

`uv run ruff format .` buat merapikan format otomatis.

Test yang lama ditandai `slow` dan nggak dijalankan di CI. Buat jalan cepat: `uv run pytest -m "not slow"`. Kalau perubahan kamu nyentuh cipher atau format file, jalankan yang lengkap di lokal.

Merge PR kalau CI hijau.

## Aturan kode

- Di `src/` cuma boleh stdlib. Library crypto apa pun dilarang, termasuk `hashlib`, `hmac`, `random`, dan `secrets`.
- `numpy` dan `matplotlib` cuma buat `analysis/`.
- Harus jalan di Linux dan Windows.
- Fungsi dan kelas publik pakai type hints dan docstring.
