# Contributing

## Setup

Project ini pakai [uv](https://docs.astral.sh/uv/). Install uv dulu, lalu dari root repo:

```bash
uv sync --all-groups
```

Perintah itu bikin `.venv`, install package `tk_cipher` (editable), dan semua dependency group (`dev` dan `analysis`). Cipher-nya sendiri nggak punya dependency runtime.

## Alur kerja

1. Ambil satu issue yang belum Blocked dan di-assign ke kamu.
2. Bikin branch dari `main`, satu branch per issue.
3. Kerjain, tulis test bareng kodenya.
4. Jalankan test manual (lihat bagian bawah).
5. Buka PR ke `main` dan tulis `Closes #<nomor issue>`. Review diminta otomatis ke anggota tim lewat CODEOWNERS.

Commit pakai format conventional commits, contohnya `feat(cipher): add key schedule`.

## Test manual

Repo ini nggak punya CI, jadi test dijalankan sendiri sebelum buka PR:

```bash
uv run pytest
```

Test yang lama dikasih marker `slow`. Buat jalan cepat saat develop:

```bash
uv run pytest -m "not slow"
```

Sebelum PR, jalankan test lengkap (termasuk `slow`) dan tulis hasilnya di deskripsi PR: OS, versi Python, dan jumlah test yang lulus. Kalau perubahan kamu bisa beda perilakunya antar OS, jalankan di Linux dan Windows.

## Aturan kode

- Di `src/` cuma boleh stdlib. Library crypto apa pun dilarang, termasuk `hashlib`, `hmac`, `random`, dan `secrets`.
- `numpy` dan `matplotlib` cuma buat `analysis/`.
- Kode harus jalan di Linux dan Windows.
- Semua fungsi dan kelas publik pakai type hints dan docstring (deskripsi, parameter, return, raises, contoh). Docstring ini nanti jadi API docs.
