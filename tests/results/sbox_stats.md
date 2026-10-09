# Statistik S-box Dinamis

Skrip: `analysis/sbox_stats.py`, seed `20261006`. Data: `sbox_stats.csv` (per key) dan `sbox_candidates.csv` (kandidat sebelum filter).

## Metode

- 100 key acak per ukuran (128, 192, 256-bit), total 300 key, masing-masing lewat `generate_sbox`.
- Dicatat DU, NL, `attempts`, dan waktu generate (ms) per key. DU, NL, dan attempts deterministik per seed; waktu tergantung mesin.
- Untuk review threshold, 2 kandidat pertama per key (total 600) diukur **sebelum** filter, memakai shuffle dan fix-up yang sama dengan `generate_sbox`.

## S-box yang dihasilkan (sesudah filter)

| Statistik | min | max | mean | median |
| :--- | ---: | ---: | ---: | ---: |
| DU | 10 | 12 | 11.11 | 12 |
| NL | 90 | 98 | 93.14 | 94 |
| attempts | 1 | 3 | 1.18 | 1 |
| waktu (ms) | 26.75 | 127.35 | 34.23 | 28.17 |

| DU | Jumlah | % | |
| ---: | ---: | ---: | :--- |
| 10 | 133 | 44.3% | `######################` |
| 12 | 167 | 55.7% | `############################` |

| NL | Jumlah | % | |
| ---: | ---: | ---: | :--- |
| 90 | 33 | 11.0% | `######` |
| 92 | 104 | 34.7% | `#################` |
| 94 | 124 | 41.3% | `#####################` |
| 96 | 37 | 12.3% | `######` |
| 98 | 2 | 0.7% | `#` |

| attempts | Jumlah | % | |
| ---: | ---: | ---: | :--- |
| 1 | 253 | 84.3% | `##########################################` |
| 2 | 40 | 13.3% | `#######` |
| 3 | 7 | 2.3% | `#` |

## Kandidat sebelum filter

| DU | Jumlah | % | |
| ---: | ---: | ---: | :--- |
| 10 | 242 | 40.3% | `####################` |
| 12 | 311 | 51.8% | `##########################` |
| 14 | 45 | 7.5% | `####` |
| 16 | 2 | 0.3% | `#` |

| NL | Jumlah | % | |
| ---: | ---: | ---: | :--- |
| 80 | 1 | 0.2% | `#` |
| 86 | 7 | 1.2% | `#` |
| 88 | 24 | 4.0% | `##` |
| 90 | 66 | 11.0% | `######` |
| 92 | 201 | 33.5% | `#################` |
| 94 | 233 | 38.8% | `###################` |
| 96 | 66 | 11.0% | `######` |
| 98 | 2 | 0.3% | `#` |

## Perbandingan threshold

| Threshold | Lolos | Ekspektasi attempts | Estimasi waktu generate |
| :--- | ---: | ---: | ---: |
| DU <= 12, NL >= 90 (sekarang) | 87.2% | 1.15 | ~54 ms |
| DU <= 14, NL >= 88 | 98.3% | 1.02 | ~47 ms |
| DU <= 12, NL >= 92 | 77.0% | 1.30 | ~61 ms |
| DU <= 10, NL >= 90 | 38.7% | 2.59 | ~121 ms |
| DU <= 10, NL >= 92 | 35.7% | 2.80 | ~131 ms |

## Keputusan

**Threshold dipertahankan: DU <= 12, NL >= 90.**

- Threshold ini membuang ekor terlemah kandidat: 7.8% kandidat punya DU > 12 dan 5.3% punya NL < 90.
- Biayanya kecil: rata-rata 1.18 attempts per key (ekspektasi 1.15).
- Memperketat ke DU <= 10 butuh ~2.6 attempts (2.3x lebih lama) untuk satu tingkat DU, padahal S-box acak 8-bit memang umumnya di DU 10 sampai 12, jauh dari S-box aljabar seperti AES (DU 4, NL 112). Keamanan TK-Cipher bertumpu pada 16 ronde (margin 4x di atas full diffusion, `round_diffusion.md`), bukan pada S-box yang optimal.
- NL >= 92 memang murah (~1.30 attempts), tapi hanya menurunkan bias linear maksimum dari 38/256 ke 36/256. Selisih sekecil itu tidak sebanding dengan mengganti semua test vector.
- Karena threshold tidak berubah, test vector di `tests/vectors.json` tetap berlaku.
