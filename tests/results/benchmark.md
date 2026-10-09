# Benchmark

Seed: `20261006`. Dibuat oleh `analysis/benchmark.py`.

## Mesin

- OS: Linux 6.18.44-1-lts (x86_64)
- CPU: AMD Ryzen 7 7730U with Radeon Graphics, 16 logical core
- Python: CPython 3.14.7

## Throughput file

Waktu `encrypt_file` dan `decrypt_file` (termasuk KDF, MAC, dan I/O), median dari beberapa ulangan.

| Kategori | File | Ukuran | Mode | Ulangan | Enc (s) | Dec (s) | Enc KiB/s | Dec KiB/s | Round trip |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| kecil | binary.png | 97,473 | ECB | 5 | 2.2753 | 2.2361 | 41.84 | 42.57 | OK |
| kecil | binary.png | 97,473 | CBC | 5 | 2.3019 | 2.3035 | 41.35 | 41.32 | OK |
| kecil | binary.png | 97,473 | CFB | 5 | 1.0763 | 1.0678 | 88.44 | 89.14 | OK |
| kecil | binary.png | 97,473 | OFB | 5 | 2.3211 | 2.3178 | 41.01 | 41.07 | OK |
| kecil | binary.png | 97,473 | CTR | 5 | 1.0687 | 1.0723 | 89.07 | 88.77 | OK |
| kecil | repetitive.bin | 65,536 | ECB | 5 | 1.5968 | 1.6073 | 40.08 | 39.82 | OK |
| kecil | repetitive.bin | 65,536 | CBC | 5 | 1.6084 | 1.5998 | 39.79 | 40.01 | OK |
| kecil | repetitive.bin | 65,536 | CFB | 5 | 1.61 | 1.4018 | 39.75 | 45.65 | OK |
| kecil | repetitive.bin | 65,536 | OFB | 5 | 0.7424 | 0.7501 | 86.21 | 85.33 | OK |
| kecil | repetitive.bin | 65,536 | CTR | 5 | 1.6073 | 1.6012 | 39.82 | 39.97 | OK |
| kecil | text_small.txt | 20,383 | ECB | 5 | 0.2881 | 0.2874 | 69.1 | 69.26 | OK |
| kecil | text_small.txt | 20,383 | CBC | 5 | 0.2924 | 0.2902 | 68.07 | 68.59 | OK |
| kecil | text_small.txt | 20,383 | CFB | 5 | 0.293 | 0.2915 | 67.93 | 68.27 | OK |
| kecil | text_small.txt | 20,383 | OFB | 5 | 0.6284 | 0.6323 | 31.67 | 31.48 | OK |
| kecil | text_small.txt | 20,383 | CTR | 5 | 0.6299 | 0.6301 | 31.6 | 31.59 | OK |
| sedang | medium.bin | 1,048,576 | ECB | 3 | 17.9928 | 15.6642 | 56.91 | 65.37 | OK |
| sedang | medium.bin | 1,048,576 | CBC | 3 | 18.8495 | 21.3302 | 54.33 | 48.01 | OK |
| sedang | medium.bin | 1,048,576 | CFB | 3 | 22.5297 | 25.2819 | 45.45 | 40.5 | OK |
| sedang | medium.bin | 1,048,576 | OFB | 3 | 18.3646 | 18.2487 | 55.76 | 56.11 | OK |
| sedang | medium.bin | 1,048,576 | CTR | 3 | 18.9447 | 20.5581 | 54.05 | 49.81 | OK |
| besar | large.bin | 5,242,880 | ECB | 1 | 306.2986 | 125.6544 | 16.72 | 40.75 | OK |
| besar | large.bin | 5,242,880 | CBC | 1 | 131.1949 | 120.118 | 39.03 | 42.62 | OK |
| besar | large.bin | 5,242,880 | CFB | 1 | 130.7386 | 139.547 | 39.16 | 36.69 | OK |
| besar | large.bin | 5,242,880 | OFB | 1 | 138.4371 | 112.1419 | 36.98 | 45.66 | OK |
| besar | large.bin | 5,242,880 | CTR | 1 | 124.2353 | 113.5798 | 41.21 | 45.08 | OK |

## Key setup

Waktu `TKCipher(key)`, yaitu bikin S-box dinamis plus 17 round key.

| Key | Sampel | Median (ms) | Min (ms) | Max (ms) |
| --- | --- | --- | --- | --- |
| 128-bit | 20 | 27.93 | 27.57 | 59.75 |
| 192-bit | 20 | 28.47 | 28.07 | 61.15 |
| 256-bit | 20 | 28.87 | 28.03 | 57.26 |
