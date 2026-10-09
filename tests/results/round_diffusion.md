# Round Diffusion

Skrip: `analysis/round_diffusion.py`, seed `20261005`. Data: `round_diffusion.csv`, grafik: `round_diffusion.png`.

## Metode

- 8 key 128-bit acak x 8 plaintext acak per key. Tiap plaintext di-flip di **semua** 128 bit satu per satu, jadi 8192 sampel per ronde dan 64 sampel per bit input.
- Avalanche: persen bit ciphertext yang berubah per sampel.
- Dependency: pasangan (bit input i, bit output j) yang pernah berubah, dari maksimum 16384.
- SAC min/max: peluang terkecil/terbesar bit output j berubah saat bit i di-flip (ideal 0.5).
- Full diffusion: semua 16384 pasangan ketemu dan |mean avalanche - 50| <= 1.0 poin persen.
- Cipher dipanggil lewat `TKCipher(key, rounds=r)` dari package `tk_cipher`.

## Hasil

| Ronde | Avalanche mean | min | max | std | Dependency | SAC min | SAC max |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 11.44% | 1.56% | 29.69% | 4.83 | 4919 (30.02%) | 0.000 | 0.750 |
| 2 | 38.12% | 4.69% | 67.19% | 12.10 | 13685 (83.53%) | 0.000 | 0.781 |
| 3 | 47.04% | 11.72% | 65.62% | 7.43 | 16200 (98.88%) | 0.000 | 0.750 |
| 4 | 49.83% | 26.56% | 65.62% | 4.52 | 16384 (100.00%) | 0.250 | 0.719 |
| 5 | 49.99% | 32.81% | 65.62% | 4.36 | 16384 (100.00%) | 0.266 | 0.750 |
| 6 | 49.98% | 32.03% | 67.19% | 4.44 | 16384 (100.00%) | 0.234 | 0.750 |
| 7 | 49.99% | 34.38% | 70.31% | 4.40 | 16384 (100.00%) | 0.266 | 0.719 |
| 8 | 49.98% | 31.25% | 65.62% | 4.46 | 16384 (100.00%) | 0.250 | 0.750 |
| 9 | 50.03% | 32.03% | 65.62% | 4.41 | 16384 (100.00%) | 0.266 | 0.719 |
| 10 | 49.96% | 35.16% | 67.97% | 4.41 | 16384 (100.00%) | 0.281 | 0.750 |
| 11 | 49.98% | 33.59% | 67.97% | 4.44 | 16384 (100.00%) | 0.266 | 0.734 |
| 12 | 49.95% | 32.81% | 66.41% | 4.45 | 16384 (100.00%) | 0.250 | 0.750 |
| 13 | 50.03% | 32.81% | 67.19% | 4.43 | 16384 (100.00%) | 0.250 | 0.734 |
| 14 | 49.96% | 33.59% | 66.41% | 4.45 | 16384 (100.00%) | 0.234 | 0.734 |
| 15 | 50.02% | 34.38% | 66.41% | 4.43 | 16384 (100.00%) | 0.234 | 0.750 |
| 16 | 49.97% | 32.81% | 66.41% | 4.41 | 16384 (100.00%) | 0.250 | 0.734 |

## Kesimpulan

Full diffusion pertama kali tercapai di **ronde 4**. Dengan 16 ronde, margin keamanannya 12 ronde tambahan (4.0x ronde full diffusion).

Di ronde 3 dependency sudah 98.88% dan avalanche 47.04%, jadi ronde 4 adalah batas konservatif. Sesudahnya avalanche stabil di sekitar 50% sampai ronde 16.

Margin 4.0x sebanding dengan AES-128 (full diffusion 2 ronde, 10 ronde, 5x), jadi 16 ronde dianggap cukup dan `ROUNDS` tetap.
