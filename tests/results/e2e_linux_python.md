# E2E Linux python

- OS: Linux 6.18.44-1-lts (x86_64)
- Python runner: 3.14.7
- Target: `python`
- Hasil: 67 dari 67 skenario lulus

| Skenario | Hasil | Detail |
| --- | --- | --- |
| keygen --bits 128 | lulus | 32 karakter hex |
| keygen --bits 192 | lulus | 48 karakter hex |
| keygen --bits 256 | lulus | 64 karakter hex |
| round trip binary.png ecb | lulus | 97473 byte identik |
| round trip binary.png cbc | lulus | 97473 byte identik |
| round trip binary.png cbc --iv | lulus | 97473 byte identik |
| round trip binary.png cfb | lulus | 97473 byte identik |
| round trip binary.png ofb | lulus | 97473 byte identik |
| round trip binary.png ctr | lulus | 97473 byte identik |
| round trip binary.png ctr --iv | lulus | 97473 byte identik |
| round trip image.bmp ecb | lulus | 196662 byte identik |
| round trip image.bmp cbc | lulus | 196662 byte identik |
| round trip image.bmp cbc --iv | lulus | 196662 byte identik |
| round trip image.bmp cfb | lulus | 196662 byte identik |
| round trip image.bmp ofb | lulus | 196662 byte identik |
| round trip image.bmp ctr | lulus | 196662 byte identik |
| round trip image.bmp ctr --iv | lulus | 196662 byte identik |
| round trip large.bin ecb | lulus | 5242880 byte identik |
| round trip large.bin cbc | lulus | 5242880 byte identik |
| round trip large.bin cbc --iv | lulus | 5242880 byte identik |
| round trip large.bin cfb | lulus | 5242880 byte identik |
| round trip large.bin ofb | lulus | 5242880 byte identik |
| round trip large.bin ctr | lulus | 5242880 byte identik |
| round trip large.bin ctr --iv | lulus | 5242880 byte identik |
| round trip medium.bin ecb | lulus | 1048576 byte identik |
| round trip medium.bin cbc | lulus | 1048576 byte identik |
| round trip medium.bin cbc --iv | lulus | 1048576 byte identik |
| round trip medium.bin cfb | lulus | 1048576 byte identik |
| round trip medium.bin ofb | lulus | 1048576 byte identik |
| round trip medium.bin ctr | lulus | 1048576 byte identik |
| round trip medium.bin ctr --iv | lulus | 1048576 byte identik |
| round trip repetitive.bin ecb | lulus | 65536 byte identik |
| round trip repetitive.bin cbc | lulus | 65536 byte identik |
| round trip repetitive.bin cbc --iv | lulus | 65536 byte identik |
| round trip repetitive.bin cfb | lulus | 65536 byte identik |
| round trip repetitive.bin ofb | lulus | 65536 byte identik |
| round trip repetitive.bin ctr | lulus | 65536 byte identik |
| round trip repetitive.bin ctr --iv | lulus | 65536 byte identik |
| round trip text_small.txt ecb | lulus | 20383 byte identik |
| round trip text_small.txt cbc | lulus | 20383 byte identik |
| round trip text_small.txt cbc --iv | lulus | 20383 byte identik |
| round trip text_small.txt cfb | lulus | 20383 byte identik |
| round trip text_small.txt ofb | lulus | 20383 byte identik |
| round trip text_small.txt ctr | lulus | 20383 byte identik |
| round trip text_small.txt ctr --iv | lulus | 20383 byte identik |
| round trip 1_empty.bin ecb | lulus | 0 byte identik |
| round trip 1_empty.bin cbc | lulus | 0 byte identik |
| round trip 1_empty.bin cbc --iv | lulus | 0 byte identik |
| round trip 1_empty.bin cfb | lulus | 0 byte identik |
| round trip 1_empty.bin ofb | lulus | 0 byte identik |
| round trip 1_empty.bin ctr | lulus | 0 byte identik |
| round trip 1_empty.bin ctr --iv | lulus | 0 byte identik |
| round trip 2_17.bin ecb | lulus | 17 byte identik |
| round trip 2_17.bin cbc | lulus | 17 byte identik |
| round trip 2_17.bin cbc --iv | lulus | 17 byte identik |
| round trip 2_17.bin cfb | lulus | 17 byte identik |
| round trip 2_17.bin ofb | lulus | 17 byte identik |
| round trip 2_17.bin ctr | lulus | 17 byte identik |
| round trip 2_17.bin ctr --iv | lulus | 17 byte identik |
| key lewat --key-file | lulus | exit enc 0, dec 0 |
| tamper 1 byte ciphertext | lulus | exit 3 (harus 3) |
| dec pakai key lain | lulus | exit 3 (harus 3) |
| file terpotong 40 byte | lulus | exit 2 (harus 2) |
| --iv di ECB | lulus | exit 1 (harus 1) |
| key 31 karakter hex | lulus | exit 1 (harus 1) |
| file input tidak ada | lulus | exit 1 (harus 1) |
| -o sama dengan -i | lulus | exit 1 (harus 1) |
