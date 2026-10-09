# Avalanche plaintext dan key

Seed: `20261006`. Semua nilai dalam persen bit ciphertext yang berubah, ideal sekitar 50%.
Dibuat oleh `analysis/avalanche.py`, data mentah di `avalanche_plaintext.csv` dan `avalanche_key.csv`.

## Flip 1 bit plaintext

1000 sampel per mode, key 128-bit acak, plaintext 4 blok, IV sama untuk dua run.

### Statistik per blok ciphertext

| Mode | Blok | Mean | Min | Max | Std |
| --- | --- | --- | --- | --- | --- |
| ECB | 0 | 12.60 | 0.00 | 61.72 | 21.74 |
| ECB | 1 | 13.66 | 0.00 | 66.41 | 22.58 |
| ECB | 2 | 12.07 | 0.00 | 64.84 | 21.41 |
| ECB | 3 | 11.68 | 0.00 | 64.06 | 21.27 |
| ECB | total | 12.50 | 8.98 | 16.60 | 1.12 |
| CBC | 0 | 12.11 | 0.00 | 64.84 | 21.54 |
| CBC | 1 | 24.77 | 0.00 | 62.50 | 25.07 |
| CBC | 2 | 36.76 | 0.00 | 65.62 | 22.29 |
| CBC | 3 | 50.07 | 34.38 | 64.06 | 4.54 |
| CBC | total | 30.93 | 8.59 | 57.03 | 14.13 |
| CFB | 0 | 0.19 | 0.00 | 0.78 | 0.34 |
| CFB | 1 | 12.49 | 0.00 | 62.50 | 21.51 |
| CFB | 2 | 25.57 | 0.00 | 61.72 | 25.04 |
| CFB | 3 | 37.58 | 0.78 | 64.06 | 21.77 |
| CFB | total | 18.96 | 0.20 | 44.92 | 14.08 |
| OFB | 0 | 0.20 | 0.00 | 0.78 | 0.34 |
| OFB | 1 | 0.19 | 0.00 | 0.78 | 0.34 |
| OFB | 2 | 0.20 | 0.00 | 0.78 | 0.34 |
| OFB | 3 | 0.19 | 0.00 | 0.78 | 0.33 |
| OFB | total | 0.20 | 0.20 | 0.20 | 0.00 |
| CTR | 0 | 0.20 | 0.00 | 0.78 | 0.34 |
| CTR | 1 | 0.20 | 0.00 | 0.78 | 0.34 |
| CTR | 2 | 0.19 | 0.00 | 0.78 | 0.34 |
| CTR | 3 | 0.20 | 0.00 | 0.78 | 0.34 |
| CTR | total | 0.20 | 0.20 | 0.20 | 0.00 |

### Blok ciphertext relatif terhadap blok plaintext yang di-flip

| Mode | Posisi | Mean | Min | Max | Std |
| --- | --- | --- | --- | --- | --- |
| ECB | sebelum | 0.00 | 0.00 | 0.00 | 0.00 |
| ECB | sama | 50.01 | 35.94 | 66.41 | 4.46 |
| ECB | sesudah | 0.00 | 0.00 | 0.00 | 0.00 |
| CBC | sebelum | 0.00 | 0.00 | 0.00 | 0.00 |
| CBC | sama | 49.80 | 34.38 | 64.84 | 4.38 |
| CBC | sesudah | 50.04 | 36.72 | 65.62 | 4.52 |
| CFB | sebelum | 0.00 | 0.00 | 0.00 | 0.00 |
| CFB | sama | 0.78 | 0.78 | 0.78 | 0.00 |
| CFB | sesudah | 50.04 | 35.94 | 64.06 | 4.48 |
| OFB | sebelum | 0.00 | 0.00 | 0.00 | 0.00 |
| OFB | sama | 0.78 | 0.78 | 0.78 | 0.00 |
| OFB | sesudah | 0.00 | 0.00 | 0.00 | 0.00 |
| CTR | sebelum | 0.00 | 0.00 | 0.00 | 0.00 |
| CTR | sama | 0.78 | 0.78 | 0.78 | 0.00 |
| CTR | sesudah | 0.00 | 0.00 | 0.00 | 0.00 |

Satu bit dari 128 bit adalah 0.78%.

## Flip 1 bit key

Plaintext dan IV sama, master key beda 1 bit. Ukuran key bergantian 128, 192, 256-bit.
Jalur `cipher` adalah `TKCipher` plus mode (300 sampel per mode), jalur `full` adalah
`encrypt_bytes` lengkap dengan KDF dan MAC, hanya bagian ciphertext yang dibandingkan (50 sampel per mode).

| Jalur | Mode | Mean | Min | Max | Std |
| --- | --- | --- | --- | --- | --- |
| cipher | ECB | 49.98 | 43.95 | 56.25 | 2.18 |
| cipher | CBC | 50.36 | 43.36 | 56.45 | 2.38 |
| cipher | CFB | 49.91 | 43.55 | 55.86 | 2.27 |
| cipher | OFB | 49.87 | 41.41 | 55.86 | 2.35 |
| cipher | CTR | 49.85 | 43.55 | 54.88 | 2.11 |
| full | ECB | 50.44 | 46.41 | 55.16 | 1.80 |
| full | CBC | 49.63 | 44.84 | 53.75 | 2.05 |
| full | CFB | 49.67 | 45.47 | 52.03 | 1.56 |
| full | OFB | 50.18 | 46.88 | 53.91 | 1.68 |
| full | CTR | 50.30 | 46.09 | 55.78 | 1.92 |

## Kesesuaian dengan ekspektasi

Semua hasil sesuai tabel ekspektasi: ECB hanya mengubah blok yang di-flip, CBC mengubah blok itu dan
semua blok sesudahnya, CFB mengubah tepat 1 bit di blok itu lalu sekitar 50% di blok sesudahnya,
OFB dan CTR hanya mengubah tepat 1 bit, dan flip 1 bit key mengubah sekitar 50% ciphertext di semua mode.
