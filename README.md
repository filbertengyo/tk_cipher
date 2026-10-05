# tk_cipher

## API docs

Dokumentasi API dibuat dari docstring dan type hints di `src/tk_cipher/` pakai [pdoc](https://pdoc.dev). Isinya deskripsi tiap modul, kelas, dan fungsi publik, parameter beserta tipe data, return, exception, contoh pemakaian, dan catatan.

Link: <https://filbertengyo.github.io/tk_cipher/> (di-host dari branch `gh-pages` lewat GitHub Pages).

### Tools

- **pdoc**: generate HTML statis dari docstring format Google (`Args`, `Returns`, `Raises`, `Example`, `Note`). Ada di dependency group `dev`.
- **Hosting**: hasil HTML disimpan di branch `gh-pages` dan disajikan sebagai halaman statis, tanpa server backend.
- **Doctest**: semua contoh di docstring ikut dijalankan `uv run pytest` (`--doctest-modules`), jadi contoh di docs selalu sesuai kode.

### Build ulang

Dari root repo:

```bash
uv sync --all-groups
uv run pdoc --docformat google -o build/api tk_cipher
```

Buka `build/api/index.html` di browser buat lihat hasilnya. Folder `build/` tidak di-commit ke `main`.

### Publish ke branch gh-pages

```bash
git worktree add ../tk_cipher_pages gh-pages
rm -rf ../tk_cipher_pages/*
cp -r build/api/. ../tk_cipher_pages/
cd ../tk_cipher_pages
git add -A
git commit -m "docs: update API docs"
git push origin gh-pages
```

Kalau branch `gh-pages` belum ada, bikin dulu sebagai branch orphan: `git worktree add --orphan -b gh-pages ../tk_cipher_pages`.
