# Entropi dan Chi-square (A-04, A-06)

Skrip: `analysis/entropy.py`, seed `20261006` (key `5c47ab7e4c73d1147e1a8dac21b05d49`, IV `1087cbea3edfe749d9dd83827edb7732`). Data: `entropy.csv` dan `chi_square.csv`.

## Metode

- Tiap file di `tests/data/` dienkripsi dengan `encrypt_bytes` di 5 mode, key dan IV tetap (ECB tanpa IV). Yang diukur hanya bagian ciphertext, tanpa header 32 byte dan tag 16 byte.
- Entropi Shannon: `H = -sum(p_i * log2(p_i))` atas 256 nilai byte, maks 8.
- Chi-square: `sum((O_i - E)^2 / E)`, `E = jumlah_byte / 256`, df 255. Lolos kalau `chi2 <= 293.248` (alpha 0.05).

## Hasil

| File | Mode | H plaintext | H ciphertext | chi2 | Lolos | Blok berulang |
| :--- | :--- | ---: | ---: | ---: | :---: | ---: |
| binary.png | ECB | 7.9974 | 7.9981 | 260.3 | ya | 0 |
| binary.png | CBC | 7.9974 | 7.9981 | 256.3 | ya | 0 |
| binary.png | CFB | 7.9974 | 7.9983 | 233.7 | ya | 0 |
| binary.png | OFB | 7.9974 | 7.9982 | 248.4 | ya | 0 |
| binary.png | CTR | 7.9974 | 7.9982 | 238.4 | ya | 0 |
| image.bmp | ECB | 1.9640 | 6.1764 | 1058193.2 | tidak | 12240 |
| image.bmp | CBC | 1.9640 | 7.9990 | 268.8 | ya | 0 |
| image.bmp | CFB | 1.9640 | 7.9989 | 305.4 | tidak | 0 |
| image.bmp | OFB | 1.9640 | 7.9990 | 263.0 | ya | 0 |
| image.bmp | CTR | 1.9640 | 7.9991 | 256.2 | ya | 0 |
| medium.bin | ECB | 7.9999 | 7.9998 | 225.3 | ya | 0 |
| medium.bin | CBC | 7.9999 | 7.9998 | 238.3 | ya | 0 |
| medium.bin | CFB | 7.9999 | 7.9998 | 249.7 | ya | 0 |
| medium.bin | OFB | 7.9999 | 7.9998 | 251.6 | ya | 0 |
| medium.bin | CTR | 7.9999 | 7.9998 | 229.9 | ya | 0 |
| repetitive.bin | ECB | 4.0000 | 3.8781 | 1113840.1 | tidak | 4095 |
| repetitive.bin | CBC | 4.0000 | 7.9972 | 254.0 | ya | 0 |
| repetitive.bin | CFB | 4.0000 | 7.9971 | 266.2 | ya | 0 |
| repetitive.bin | OFB | 4.0000 | 7.9977 | 213.9 | ya | 0 |
| repetitive.bin | CTR | 4.0000 | 7.9975 | 224.8 | ya | 0 |
| text_small.txt | ECB | 4.3551 | 7.9849 | 421.0 | tidak | 385 |
| text_small.txt | CBC | 4.3551 | 7.9891 | 304.7 | tidak | 0 |
| text_small.txt | CFB | 4.3551 | 7.9916 | 238.2 | ya | 0 |
| text_small.txt | OFB | 4.3551 | 7.9913 | 245.6 | ya | 0 |
| text_small.txt | CTR | 4.3551 | 7.9917 | 234.1 | ya | 0 |

## Kesimpulan

**ECB pada `repetitive.bin` gagal total:** entropi ciphertext cuma 3.8781 bit/byte (plaintext 4.0000) dan chi2 1113840, jauh di atas 293.248. File ini pola 16 byte yang sama diulang, dan ECB mengenkripsi tiap blok sendiri-sendiri, jadi blok plaintext yang identik selalu jadi blok ciphertext yang identik: 4095 dari 4097 blok ciphertext adalah duplikat. Polanya bocor utuh.

Mode lain pada file yang sama (CBC, CFB, OFB, CTR) mencapai entropi 7.9971 sampai 7.9977, lolos chi-square, dan tidak punya blok berulang, karena tiap blok dicampur dengan IV, ciphertext sebelumnya, atau counter.

Kebocoran yang sama terlihat di ECB pada `image.bmp` (12240 blok berulang, H 6.1764, chi2 1058193.2) dan `text_small.txt` (385 blok berulang, H 7.9849, chi2 421.0): plaintext-nya punya blok 16 byte yang kembar (area warna solid di gambar, potongan kalimat yang terulang di teks). ECB pada `binary.png` dan `medium.bin` lolos karena plaintext-nya tidak punya blok kembar, bukan karena ECB aman.

Mode CBC, CFB, OFB, dan CTR punya entropi ciphertext >= 7.9891 bit/byte di semua file, termasuk teks dan gambar yang entropi plaintext-nya jauh di bawah 8. 18 dari 20 lolos chi-square; yang tidak: image.bmp CFB (chi2 305.4), text_small.txt CBC (chi2 304.7), tanpa blok berulang. Dengan alpha 0.05, data yang benar-benar acak pun diharapkan gagal sekitar 5% (~1 dari 20), jadi ini fluktuasi statistik, bukan pola.
