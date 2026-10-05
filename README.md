# tk_cipher

## API docs

Dokumentasi API dibuat dari docstring dan type hints di `src/tk_cipher/` pakai [pdoc](https://pdoc.dev). Isinya deskripsi tiap modul, kelas, dan fungsi publik, parameter beserta tipe data, return, exception, contoh pemakaian, dan catatan.

Link: <https://filbertengyo.github.io/tk_cipher/api/>

### Tools

- **pdoc**: generate HTML statis dari docstring format Google (`Args`, `Returns`, `Raises`, `Example`, `Note`). Ada di dependency group `dev`.
- **GitHub Pages**: repo menyajikan folder `docs/` di branch `main`, jadi HTML hasil pdoc disimpan di `docs/api/` dan langsung terbit setelah merge, tanpa server backend.
- **Doctest**: semua contoh di docstring ikut dijalankan `uv run pytest` (`--doctest-modules`), jadi contoh di docs selalu sesuai kode.

### Build ulang

Dari root repo:

```bash
uv sync --all-groups
uv run pdoc --docformat google -o docs/api tk_cipher
```

Buka `docs/api/index.html` di browser buat lihat hasilnya. Setiap kali docstring berubah, build ulang lalu commit `docs/api/` supaya halaman online ikut ter-update.
