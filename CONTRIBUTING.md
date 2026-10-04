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

## Test

Nggak ada CI, jadi test dijalankan manual sebelum PR:

```bash
uv run pytest
```

Test yang lama ditandai `slow`. Buat jalan cepat: `uv run pytest -m "not slow"`.

Tulis hasilnya di deskripsi PR: OS, versi Python, dan jumlah test yang lulus.

## Aturan kode

- Di `src/` cuma boleh stdlib. Library crypto apa pun dilarang, termasuk `hashlib`, `hmac`, `random`, dan `secrets`.
- `numpy` dan `matplotlib` cuma buat `analysis/`.
- Harus jalan di Linux dan Windows.
- Fungsi dan kelas publik pakai type hints dan docstring.
