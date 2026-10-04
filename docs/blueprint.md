# BLUEPRINT IMPLEMENTASI: TK-CIPHER (Custom SPN Block Cipher)

**Nama Algoritma:** TK-Cipher (nama final dipakai konsisten di kode, README, laporan)
**Arsitektur Dasar:** Substitution-Permutation Network (SPN), byte-level, state matriks 4x4
**Bahasa:** Python 3 (stdlib only di jalur cipher)

> **Status: rancangan awal, belum ada implementasi.** Rancangan ini memenuhi semua ketentuan spesifikasi tugas
> di level rancangan. Klaim keamanan (confusion, diffusion, cukupnya 16 ronde) masih **hipotesis** dan baru
> dibuktikan lewat analisis setelah implementasi berjalan (Bagian 7). Parameter bisa direvisi kalau hasil analisis menuntut.

---

## 0. Pemenuhan Spesifikasi

| Spec requirement                                          | Dipenuhi di                          | Status   |
| --------------------------------------------------------- | ------------------------------------ | ------ |
| Block >= 64-bit                                           | 128-bit (Bagian 2)                   | Tercakup |
| Master key >= block size                                  | 128/192/256-bit (Bagian 3)           | Tercakup |
| Iterated cipher, n rounds + justifikasi                   | 16 ronde (Bagian 2.3, Bagian 7)      | Hipotesis |
| Round key unik per ronde dari master key                  | Key schedule (Bagian 3.2)            | Tercakup |
| Substitusi (S-box, invertible untuk SPN)                  | DynamicSub (Bagian 2.2)              | Tercakup |
| Transposisi                                               | DiagonalTranspose                    | Tercakup |
| Operasi tambahan (min 1)                                  | RowRotator + ColumnCascade           | Tercakup |
| Confusion + diffusion (1 bit => seluruh blok)             | Bagian 2, dibuktikan di Bagian 7     | Hipotesis |
| S-box bukan S-box AES, cara generate didokumentasi        | Bagian 3.1                           | Tercakup |
| Tidak copy AES/DES/dll                                    | Bagian 1                             | Tercakup |
| 5 mode (ECB, CBC, CFB, OFB, CTR) from scratch             | Bagian 4                             | Tercakup |
| IV untuk CBC/CFB/OFB, counter awal untuk CTR              | Bagian 4, Bagian 6                   | Tercakup |
| IV random otomatis bila tidak diberikan                   | Bagian 4 (`os.urandom`)              | Tercakup |
| Padding + justifikasi + mekanisme + edge case             | Bagian 5.1                           | Tercakup |
| Integritas: Encrypt-then-MAC, MAC from scratch            | CMAC-TK (Bagian 5.3)                 | Tercakup |
| Key enc & key MAC terpisah via KDF sendiri                | Bagian 5.2                           | Tercakup |
| Verifikasi MAC **sebelum** dekripsi, error jelas          | Bagian 5.4                           | Tercakup |
| Constant-time tag compare                                 | Bagian 5.3                           | Tercakup |
| Format file self-describing                               | Bagian 5.4                           | Tercakup |
| Program: input file + key + mode + IV => output           | CLI (Bagian 6)                       | Tercakup |
| Jalan di Linux/Windows                                    | Pure Python, `pathlib`               | Tercakup |
| Zero third-party crypto                                   | Bagian 8                             | Tercakup |
| Analisis avalanche (PT + key), entropi, histogram, 5 mode | Bagian 7, Bagian 9                   | Tercakup |
| Struktur repo + README 5 poin                             | Bagian 8, Bagian 8.1                 | Tercakup |

Tercakup = sudah ada di rancangan (belum diimplementasi dan diuji). Hipotesis = butuh bukti dari analisis setelah implementasi.

---

## 1. Referensi & Perbedaan dengan AES

TK-Cipher hanya meminjam bentuk state matriks 4x4 dari AES. Komponen, urutan, dan matematikanya beda total:

| Aspek         | AES                                                | TK-Cipher                                                                                                             |
| ------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Urutan ronde  | SubBytes => ShiftRows => MixColumns => AddRoundKey | AddRoundKey => DiagonalTranspose => DynamicSub => RowRotator => ColumnCascade                                         |
| S-box         | Statis (inverse GF(2^8) + affine)                  | **Dinamis per key**, Fisher-Yates + PRNG ARX sendiri + filter kualitas                                                |
| Transposisi   | ShiftRows (geser byte per baris)                   | Transpose matriks `(r,c) => (c,r)`                                                                                    |
| Linear mixing | MixColumns (perkalian GF(2^8))                     | **RowRotator** (rotasi _bit_ 32-bit per baris) + **ColumnCascade** (penjumlahan mod 256 berantai), tanpa Galois Field |
| Key schedule  | RotWord/SubWord/Rcon                               | Sponge-like absorb lane key, pakai S-box dinamis + konstanta golden-ratio                                             |
| Jumlah ronde  | 10 (128-bit)                                       | 16 (semua ukuran key)                                                                                                 |

**Pelajaran dari rancangan awal:** rancangan awal tidak merotasi baris 0, dan transpose memetakan `(0,0) => (0,0)`. Akibatnya byte 0 terisolasi total (`C[0] = f(P[0], K)`), tidak pernah menerima atau menyebarkan difusi, berapa pun jumlah rondenya. Selain itu, linear layer rancangan awal hanya permutasi bit tanpa pencampuran antar-byte, sehingga difusinya lambat. rancangan sekarang memperbaiki keduanya: semua baris dirotasi, dan ditambah ColumnCascade sebagai pencampur antar-byte.

---

## 2. Cipher Core

### 2.1 Representasi state

16 byte `b[0..15]` disusun row-major: `state[r][c] = b[4r + c]`. Round key juga 16 byte dengan layout yang sama.

### 2.2 Satu ronde `R_i` (i = 0..15)

```
state => AddRoundKey(RK_i) => DiagonalTranspose => DynamicSub => RowRotator => ColumnCascade => state'
```

1. **AddRoundKey**: `state ^= RK_i` (XOR byte-wise).
2. **DiagonalTranspose** (transposisi): `state[r][c] => state[c][r]`. Involution (inverse = dirinya sendiri).
3. **DynamicSub** (substitusi): `b = S[b]` untuk tiap byte. `S` adalah S-box dinamis dari Bagian 3.1. Inverse: `S_inv`.
4. **RowRotator** (operasi tambahan #1): tiap baris dibaca sebagai word 32-bit big-endian, lalu **rotasi bit** ke kiri sebanyak `ROT = [1, 3, 5, 7]` untuk baris 0..3. Semua baris dirotasi (baris 0 juga) dengan jumlah ganjil berbeda, sehingga bit melintasi batas byte. Inverse: rotasi kanan.
5. **ColumnCascade** (operasi tambahan #2): per kolom `(a, b, d, e)` = baris 0..3, semua mod 256:
   ```
   b = b + a ; d = d + b ; e = e + d ; a = a + e
   ```
   Inverse (urutan dibalik): `a = a - e ; e = e - d ; d = d - b ; b = b - a`.
   Efeknya: perubahan di satu byte kolom menjalar ke byte lain di kolom itu, plus carry penjumlahan menambah non-linearitas terhadap XOR.

### 2.3 Enkripsi / Dekripsi

```
Enc(P):  s = P
         for i in 0..15:  s = R_i(s)
         C = s ^ RK_16                      # whitening akhir (wajib, 17 round key total)

Dec(C):  s = C ^ RK_16
         for i in 15..0:
             s = InvColumnCascade(s)
             s = RowRotator_inv(s)            # rotasi kanan [1,3,5,7]
             s = S_inv[s]
             s = DiagonalTranspose(s)
             s = s ^ RK_i
         P = s
```

**Hipotesis 16 ronde:** 16 ronde diperkirakan beberapa kali lipat dari jumlah ronde yang dibutuhkan untuk full diffusion (setiap bit input memengaruhi setiap bit output), sehingga ada margin keamanan. Ini nilai awal. Justifikasi resminya baru ditulis setelah jumlah ronde full diffusion diukur (Bagian 7), dan jumlah ronde bisa direvisi kalau hasilnya tidak mendukung. Whitening `RK_16` mencegah ronde terakhir dikupas tanpa key.

---

## 3. Key Setup

Master key: **16, 24, atau 32 byte** (128/192/256-bit), diberikan user sebagai hex. Key setup terdiri dari S-box dinamis dan round keys.

### 3.1 Dynamic S-box (bukan S-box AES)

1. **PRNG `TKRand`** (desain sendiri, ARX 4x32-bit):
   - Init state: `[G, rotl(G,8), rotl(G,16), rotl(G,24)]`, `G = 0x9E3779B9` (golden ratio).
   - Absorb `b"TKC-SBOX" + key + len(key)` per byte: `s[i%4] += byte`, lalu `mix`. Setelah itu 32x `mix` warm-up.
   - `mix(a,b,c,d)`: `a+=b; d=rotl(d^a,13); c+=d; b=rotl(b^c,9); a+=b; d=rotl(d^a,5); c+=d; b=rotl(b^c,11)`.
   - Output `next32 = s0 ^ s2` setelah `mix`. Bilangan `[0,n)` diambil via rejection sampling (tanpa modulo bias).
   - **Tidak memakai** modul `random` Python.
2. **Fisher-Yates shuffle** array `[0..255]` dengan `TKRand`.
3. **Fix-up fixed point:** selama ada `x` dengan `S[x] == x` atau `S[x] == x ^ 0xFF`, swap `S[x]` dengan posisi acak lain.
4. **Filter kualitas:** terima hanya kalau **differential uniformity <= 12** dan **nonlinearity >= 90** (threshold awal, ditinjau ulang dari statistik S-box di analisis). Kalau gagal, shuffle ulang (PRNG lanjut, tetap deterministik per key).
5. `S_inv[S[x]] = x`.

Dokumen desain mencatat statistik S-box (DU, NL, jumlah percobaan) untuk test vector key.

### 3.2 Round keys (17 x 128-bit)

```
k0 = key[0:16]
k1 = key[16:] zero-padded ke 16 byte          (key 192/256-bit)
   = S[rot_bytes(k0, 5)]                       (key 128-bit)
t  = 0^16
for i in 0..16:
    t ^= (k0 if i even else k1)                # absorb lane key
    t  = S[t]                                  # non-linear (S-box dinamis)
    t ^= RC_i                                  # RC_i = rotl32(G, 5i mod 32) ^ (i*0x01010101), diulang 4x
    t  = ColumnCascade(RowRotator(DiagonalTranspose(t)))
    RK_i = t
```

Tujuan desain: non-linear (lewat S-box), berbeda per ronde (RC_i untuk mencegah slide attack), dan semua bit key ikut memengaruhi setiap RK. Penyebaran perubahan key ke round key diukur di analisis (Bagian 7).

---

## 4. Mode Operasi (semua from scratch, full-block 128-bit)

`E` = TK-Cipher dengan `K_enc` (Bagian 5.2). Data sudah di-pad (Bagian 5.1), jadi panjangnya kelipatan 16.

| Mode | Enkripsi                                               | Dekripsi                   | IV/Counter                         |
| ---- | ------------------------------------------------------ | -------------------------- | ---------------------------------- |
| ECB  | `C_i = E(P_i)`                                         | `P_i = D(C_i)`             | tidak ada (field IV di header = 0) |
| CBC  | `C_i = E(P_i XOR C_{i-1})`, `C_{-1} = IV`              | `P_i = D(C_i) XOR C_{i-1}` | IV 16 B                            |
| CFB  | `C_i = P_i XOR E(C_{i-1})`, `C_{-1} = IV`              | `P_i = C_i XOR E(C_{i-1})` | IV 16 B                            |
| OFB  | `O_i = E(O_{i-1})`, `O_{-1} = IV`, `C_i = P_i XOR O_i` | sama                       | IV 16 B                            |
| CTR  | `C_i = P_i XOR E((CTR_0 + i) mod 2^128)`               | sama                       | counter awal 16 B (big-endian)     |

- CFB/OFB/CTR hanya memakai arah `E` (tidak butuh `D`).
- IV/counter awal: dari user (`--iv <32 hex>`) atau `os.urandom(16)` otomatis.
- Peringatan untuk user (README): jangan reuse IV/counter dengan key yang sama di OFB/CTR.

---

## 5. Padding, KDF, MAC, Format File

### 5.1 Padding: PKCS#7 di **semua** mode

- Pad `p = 16 - (len mod 16)` byte bernilai `p` (1..16). Kalau sudah pas kelipatan 16, tambah 1 blok penuh `0x10`.
- **Justifikasi:** satu code path untuk 5 mode (konsisten, sesuai catatan spec). Unpad selalu tidak ambigu, termasuk file yang berakhiran byte mirip padding. Edge case bisa diuji seragam. CFB/OFB/CTR secara teknis tidak butuh padding (stream-like). Ini dijelaskan di `docs/DESIGN.md` Bagian 7, tapi tetap dipad demi konsistensi.
- Edge case yang diuji: 0 byte (=> 1 blok `0x10`), 1 byte, 15, 16, 17, 31, 32, 33 byte.
- Unpad memvalidasi `1 <= p <= 16` dan semua `p` byte terakhir bernilai `p`. Ini hanya dijalankan **setelah** MAC valid, jadi tidak ada padding oracle.

### 5.2 KDF (sendiri): key enc & key MAC terpisah

Dibangun dari TK-Cipher sebagai PRF (counter-mode KDF), dengan `E_M` = TK-Cipher berkunci master key:

```
block(label, j) = E_M( "TKC--KDF" (8 B) || label (1 B) || 6 byte 0x00 || j (1 B) )
K_enc = block(0x01, 0) || block(0x01, 1) ...   dipotong ke len(master key)
K_mac = block(0x02, 0) || block(0x02, 1) ...   dipotong ke len(master key)
```

`K_enc` dan `K_mac` pseudo-random independen satu sama lain dan panjangnya sama dengan master key (kekuatan tidak turun untuk key 192/256-bit).

### 5.3 MAC: CMAC-TK (Encrypt-then-MAC)

- Konstruksi CMAC (OMAC1) di-implement from scratch dengan `E = TK-Cipher(K_mac)`:
  - `L = E(0^128)`; `K1 = dbl(L)`, `K2 = dbl(K1)`. `dbl` = shift kiri 1 bit, XOR `0x87` ke byte terakhir kalau MSB = 1.
  - Pesan dibagi blok 16 B. Blok terakhir lengkap => XOR `K1`. Tidak lengkap => pad `0x80 00..` lalu XOR `K2`. CBC-MAC dengan IV 0, output 16 B.
- **Input MAC = header || ciphertext** (lihat Bagian 5.4), jadi mode, IV, dan panjang asli ikut terlindungi.
- **Constant-time compare** sendiri (tanpa `hmac.compare_digest`):
  ```python
  diff = len(a) ^ len(b)
  for x, y in zip(a, b): diff |= x ^ y
  return diff == 0
  ```
- Kenapa bukan "hash XOR/rotasi" seperti rancangan awal: checksum tanpa key bisa dihitung ulang penyerang setelah mengubah ciphertext. CMAC berkunci tidak bisa.

### 5.4 Format file ciphertext (self-describing, little overhead)

| Offset | Size | Field           | Isi                                        |
| ------ | ---- | --------------- | ------------------------------------------ |
| 0      | 4    | magic           | `b"TKC1"`                                  |
| 4      | 1    | version         | `0x01`                                     |
| 5      | 1    | mode            | `0=ECB 1=CBC 2=CFB 3=OFB 4=CTR`            |
| 6      | 2    | reserved        | `0x0000` (harus nol)                       |
| 8      | 16   | IV / counter    | ECB: nol semua                             |
| 24     | 8    | original length | uint64 big-endian (panjang plaintext asli) |
| 32     | N    | ciphertext      | N kelipatan 16, N >= 16                    |
| 32+N   | 16   | tag             | `CMAC(K_mac, bytes[0 : 32+N])`             |

**Urutan dekripsi** (hanya butuh file + key):

1. Cek ukuran >= 64 B, `(size - 48) % 16 == 0`, magic, version, mode valid, reserved = 0. Kalau gagal => `InvalidFormatError`.
2. Derive `K_enc`, `K_mac`. Hitung tag dan bandingkan constant-time. Kalau gagal => `AuthenticationError: "MAC verification failed: wrong key or file has been modified"`, **tanpa menulis output apa pun**.
3. Dekripsi sesuai mode, unpad, lalu cek panjang == original length.
4. Tulis output (ke file temp lalu rename, supaya tidak ada file setengah jadi).

Wrong key otomatis ditolak di langkah 2, karena `K_mac` berbeda.

---

## 6. Program (CLI)

```
tk-cipher enc -i <in> -o <out> -k <hex key> -m {ecb,cbc,cfb,ofb,ctr} [--iv <32 hex>]
tk-cipher dec -i <in> -o <out> -k <hex key>
tk-cipher keygen [--bits 128|192|256]       # cetak key random (os.urandom) dalam hex
```

- `-k` menerima 32/48/64 karakter hex. Opsi `--key-file <path>` (isi hex) dipakai supaya key tidak masuk shell history.
- Validasi input sejak awal: panjang key, hex valid, `--iv` ditolak untuk ECB, ukuran IV 16 B.
- `--iv` di mode CTR = nilai counter awal.
- Exit code: `0` OK, `1` argumen invalid, `2` format invalid, `3` autentikasi gagal.
- Pure Python + `argparse` + `pathlib` => jalan di Linux & Windows. Entry point `python -m tk_cipher` + script `tk-cipher`. Executable Linux dan Windows wajib, dibangun dengan PyInstaller (bukan crypto lib) ke `dist/` dan GitHub Release.

---

## 7. Rencana Validasi Desain

Diukur setelah implementasi, skrip di `analysis/`, hasil di `tests/results/`:

- Avalanche plaintext dan dependency bit (input ke output) per jumlah ronde, 1 sampai 16 ronde (`analysis/round_diffusion.py`). Hasilnya menentukan ronde full diffusion untuk justifikasi 16 ronde.
- Avalanche plaintext dan key untuk cipher penuh.
- Penyebaran perubahan 1 bit key ke round key.
- Statistik S-box (DU, NL, jumlah percobaan) untuk banyak key.
- Round-trip enc=>dec untuk key 128/192/256-bit (unit test).
- Throughput enc/dec (benchmark).

---

## 8. Struktur Kode & Dependensi

```
src/tk_cipher/
├── prng.py          # TKRand
├── sbox.py          # generate S-box + filter DU/NL + inverse
├── key_schedule.py  # 17 round keys
├── cipher.py        # class TKCipher: encrypt_block / decrypt_block
├── modes.py         # ECB, CBC, CFB, OFB, CTR
├── padding.py       # PKCS#7 pad/unpad
├── kdf.py           # derive K_enc, K_mac
├── mac.py           # CMAC-TK + constant_time_eq
├── fileformat.py    # header pack/parse, encrypt_file / decrypt_file
├── errors.py        # InvalidFormatError, AuthenticationError
├── cli.py
└── __main__.py
tests/               # unittest/pytest + data/ + results/
analysis/            # avalanche.py, entropy.py, histogram.py, round_diffusion.py
docs/                # DESIGN.md, diagrams/, draft laporan
dist/                # executable Linux + Windows
```

- `src/`: **stdlib saja** (`os`, `struct`, `argparse`, `pathlib`). Tidak ada `hashlib`, `hmac`, `random`, `secrets`, `cryptography`, dll.
- `analysis/`: `numpy`, `matplotlib` (dipisah di `requirements-analysis.txt`).
- `tests/`: `pytest` (dev only).
- CI/cek manual: grep import terlarang di `src/` sebagai salah satu test.

### 8.1 README

Wajib berisi: (1) nama TK-Cipher + deskripsi singkat, (2) tech stack, (3) dependensi (cipher: stdlib saja; analisis: numpy, matplotlib; test: pytest), (4) cara run beserta contoh enc/dec untuk kelima mode, (5) link API docs. Ditambah peringatan reuse IV/counter dan cara menjalankan test + analisis.

---

## 9. Pengujian & Analisis (5 mode semuanya)

**Unit tests:**

- Test vector internal: key, plaintext, dan ciphertext tetap untuk 128/192/256-bit. Nilainya dihasilkan implementasi, disimpan sebagai fixture test, dan dicatat di `tests/results/`.
- Komponen invertible: `InvX(X(s)) == s` untuk transpose, rotator, cascade, S-box.
- Round-trip byte-identical teks + biner x 5 mode x key 128/192/256.
- Padding edge cases (Bagian 5.1).
- Tamper 1 byte di setiap region (header, IV, length, ciphertext, tag) => `AuthenticationError`.
- Wrong key => ditolak. File terpotong atau magic salah => `InvalidFormatError`.
- CMAC: tag berbeda untuk pesan yang beda 1 bit dan untuk panjang berbeda.
- Tidak ada import terlarang di `src/`.

**Analisis keamanan** (`analysis/` => `tests/results/`, ratusan sampai ribuan sampel, mean/min/max/std):

1. **Avalanche plaintext & key** per mode. **IV dibuat sama** untuk kedua run (kalau IV random, hasilnya otomatis ~50% dan menyesatkan). Laporkan per blok:
   - Block cipher murni & ECB: ~50% di blok yang diubah.
   - CBC: blok yang diubah dan seluruh blok setelahnya ~50%.
   - CFB: blok ke-i hanya 1 bit, blok i+1 dst. ~50%.
   - OFB/CTR: hanya 1 bit (stream mode, sesuai teori). Dijelaskan di laporan sebagai sifat mode, bukan kelemahan cipher.
   - Key avalanche: ~50% di semua mode.
2. **Entropi Shannon** per byte: plaintext vs ciphertext, per mode, untuk teks, gambar, dan file berulang.
3. **Histogram** PNG plaintext vs ciphertext per mode. File berulang dan gambar BMP memperlihatkan kebocoran pola ECB.
4. **Tambahan (wajib, dari item opsional spec):** chi-square uniformity, benchmark throughput file kecil/sedang/besar, statistik S-box (DU/NL) untuk banyak key.

---

## 10. Urutan Implementasi

Kerjakan bertahap. Setiap langkah punya unit test sebelum lanjut:
`prng => sbox => key_schedule => cipher (+ test vector) => padding => modes => kdf => mac => fileformat => cli => analysis => docs`.

Fokus pada clean code: type hints, docstring singkat, nama fungsi sesuai istilah di blueprint ini (`diagonal_transpose`, `row_rotator`, `column_cascade`, `dynamic_sub`). Source code akan di-review asisten dosen. Semua bonus spec dikerjakan dan wajib: API docs (pdoc => GitHub Pages) yang mendokumentasikan fungsi publik beserta tipe datanya, executable Linux + Windows, dan video demo (manual). Lihat `docs/trd.md` Bagian 1.1 dan 13.
