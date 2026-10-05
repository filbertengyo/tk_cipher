# Sample data

File uji bersama untuk integration test, entropi, histogram, dan benchmark. Semua dibangkitkan deterministik, tanpa modul `random`.

| File             | Ukuran    | Asal                                                                                            |
| ---------------- | --------- | ----------------------------------------------------------------------------------------------- |
| `text_small.txt` | ~20 KB    | Teks Indonesia dan Inggris karangan sendiri, paragrafnya disusun dari kalimat yang bervariasi   |
| `repetitive.bin` | 64 KB     | Pola 16 byte `10 11 ... 1f` diulang 4096 kali                                                   |
| `image.bmp`      | ~192 KB   | BMP 24-bit tanpa kompresi, 256x256, tiga bentuk berwarna solid di latar abu-abu                  |
| `binary.png`     | ~95 KB    | PNG 180x180 hasil gradasi warna ditambah noise dari LCG, jadi file biner nyata yang sulit dikompres |
| `medium.bin`     | 1 MiB     | Hasil `make_large.py --name medium.bin --size 1048576 --seed 1`                                 |
| `large.bin`      | 5 MiB     | Hasil `make_large.py`, tidak di-commit (ada di `.gitignore`)                                    |

Kategori ukuran: kecil = file di bawah 100 KB, sedang = `medium.bin`, besar = `large.bin`.

## Bikin large.bin

Dari root repo:

```bash
uv run python tests/data/make_large.py
```

Skrip memakai LCG 32-bit dari seed tetap, jadi isinya sama persis tiap dijalankan di Linux dan Windows.

File edge case (0, 1, 15, 16, 17, 31, 32, 33 byte) tidak disimpan, dibikin langsung di test.
