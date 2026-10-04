# Desain TK-Cipher

Gambaran umum desain TK-Cipher: alur enkripsi dan dekripsi, struktur ronde, key schedule, S-box, mode operasi, padding, dan integritas. Dokumen ini menjelaskan **ide dan alasan** setiap komponen. Isinya menjadi bahan Bab 5 (Perancangan) laporan.

- Konstanta dan detail implementasi: `docs/blueprint.md`.
- Requirement teknis dan test: `docs/trd.md`.
- Angka hasil pengukuran (avalanche, entropi, histogram, dll.): dihasilkan skrip di `analysis/`, disimpan di `tests/results/`, dibahas di Bab 7 laporan.

Diagram ada di `docs/diagrams/`:

| Diagram                                                | Isi                                         |
| ------------------------------------------------------ | ------------------------------------------- |
| [01-overview](diagrams/01-overview.md)                 | Alur besar enkripsi dan dekripsi file       |
| [02-cipher](diagrams/02-cipher.md)                     | Alur ronde enkripsi dan dekripsi            |
| [03-state-operations](diagrams/03-state-operations.md) | Layout state dan operasi di dalam ronde     |
| [04-key-setup](diagrams/04-key-setup.md)               | Pembangkitan S-box dan round key            |
| [05-modes](diagrams/05-modes.md)                       | ECB, CBC, CFB, OFB, CTR                     |
| [06-kdf-mac](diagrams/06-kdf-mac.md)                   | Penurunan key dan MAC                       |
| [07-file-format](diagrams/07-file-format.md)           | Isi file ciphertext dan validasinya         |
| [08-cli-and-modules](diagrams/08-cli-and-modules.md)   | Alur program dan pembagian modul            |

---

## 1. Gambaran Umum

TK-Cipher adalah block cipher berstruktur **Substitution-Permutation Network (SPN)** yang bekerja di level byte, dengan state berupa matriks 4x4 byte.

| Parameter    | Pilihan                                       | Ketentuan spec                    |
| ------------ | --------------------------------------------- | --------------------------------- |
| Ukuran blok  | 128 bit                                       | minimal 64 bit                    |
| Ukuran key   | 128 bit (boleh 192 atau 256 bit)              | minimal sama dengan ukuran blok   |
| Struktur     | SPN, iterated, 16 ronde + whitening akhir     | n ronde, ditentukan + justifikasi |
| Round key    | Unik per ronde, diturunkan dari master key    | wajib                             |

Komponen wajib spec dan pemenuhannya:

| Komponen wajib     | Di TK-Cipher                                                     |
| ------------------ | ---------------------------------------------------------------- |
| Substitusi         | **DynamicSub**: S-box yang dibangkitkan dari key                 |
| Transposisi        | **DiagonalTranspose**: transpose matriks state                   |
| Operasi tambahan   | **RowRotator** (rotasi bit) dan **ColumnCascade** (penjumlahan modular) |
| Round key          | **AddRoundKey** dengan round key berbeda tiap ronde              |

Di atas cipher dibangun program enkripsi file lengkap: 5 mode operasi, padding, penurunan key, dan MAC untuk integritas. Lihat [diagram 01](diagrams/01-overview.md).

---

## 2. State

Blok 16 byte disusun menjadi matriks 4 baris x 4 kolom (baris demi baris). Semua operasi ronde bekerja pada matriks ini: sebagian per byte, sebagian per baris, sebagian per kolom. Round key memakai layout yang sama. Lihat [diagram 03](diagrams/03-state-operations.md).

---

## 3. Struktur Satu Ronde

Setiap ronde menjalankan lima operasi berurutan ([diagram 02](diagrams/02-cipher.md)):

```
AddRoundKey => DiagonalTranspose => DynamicSub => RowRotator => ColumnCascade
```

| Operasi           | Apa yang dilakukan                                           | Perannya                                           | Inverse                     |
| ----------------- | ------------------------------------------------------------ | -------------------------------------------------- | --------------------------- |
| AddRoundKey       | XOR state dengan round key ronde itu                         | Memasukkan key ke setiap ronde                     | XOR lagi dengan key sama    |
| DiagonalTranspose | Baris menjadi kolom, kolom menjadi baris                     | Transposisi: memindahkan byte antar baris/kolom    | Dirinya sendiri             |
| DynamicSub        | Setiap byte diganti lewat S-box                              | Substitusi: sumber utama confusion (non-linear)    | S-box inverse               |
| RowRotator        | Setiap baris dirotasi per **bit**, jumlah rotasi beda tiap baris | Menyebarkan bit melewati batas byte dalam baris | Rotasi ke arah sebaliknya   |
| ColumnCascade     | Byte dalam satu kolom dijumlahkan berantai (modular)         | Mencampur byte antar baris dalam kolom             | Pengurangan dengan urutan dibalik |

**Kenapa kombinasi ini menghasilkan diffusion:**
1. DynamicSub membuat perubahan 1 bit memengaruhi seluruh bit di byte itu.
2. RowRotator membawa perubahan itu ke byte tetangga di baris yang sama.
3. ColumnCascade membawanya ke byte lain di kolom yang sama.
4. DiagonalTranspose di ronde berikutnya menukar baris dan kolom, sehingga penyebaran berlanjut ke arah yang lain.

Setelah beberapa ronde, perubahan 1 bit diharapkan menyebar ke seluruh blok. Seberapa cepat ini terjadi diukur di analisis (Bagian 11).

**Kenapa ada dua operasi tambahan:** RowRotator saja hanya memindahkan posisi bit tanpa mencampur nilai antar-byte. ColumnCascade menambahkan pencampuran nyata antar-byte, dan carry dari penjumlahan modular menambah sifat non-linear terhadap XOR. Komponen ini mengisi peran MixColumns di AES tanpa memakai aritmetika Galois Field.

---

## 4. Enkripsi dan Dekripsi Blok

- **Enkripsi:** jalankan 16 ronde berurutan, lalu XOR dengan satu round key terakhir (**whitening**).
- **Dekripsi:** kebalikannya. Buang whitening, lalu jalankan inverse setiap ronde dari ronde terakhir ke pertama, dengan urutan operasi dibalik.

Whitening akhir diperlukan supaya operasi di ronde terakhir tidak bisa dibalik begitu saja oleh pihak yang tidak tahu key.

---

## 5. Key Setup

Dilakukan sekali untuk setiap key. Lihat [diagram 04](diagrams/04-key-setup.md).

### 5.1 S-box Dinamis

Berbeda dengan AES yang memakai satu S-box tetap, TK-Cipher **membangkitkan S-box dari key**:

1. Key dipakai sebagai seed untuk PRNG buatan sendiri (berbasis operasi add, rotate, XOR). Library `random` tidak dipakai.
2. PRNG mengacak urutan 0 sampai 255 (Fisher-Yates shuffle), sehingga hasilnya pasti permutasi dan bisa di-inverse.
3. Byte yang tidak berubah oleh S-box (fixed point) dihilangkan.
4. S-box diuji dengan dua ukuran kualitas kriptografi. Kalau tidak lolos, diacak ulang:
   - **Differential uniformity:** seberapa mudah pola perbedaan input menebak pola perbedaan output. Makin kecil makin baik.
   - **Nonlinearity:** seberapa jauh S-box dari fungsi linear. Makin besar makin baik.
5. S-box inverse dihitung untuk dekripsi.

Hasilnya, setiap key punya S-box sendiri yang tetap memenuhi standar kualitas minimum. Prosesnya deterministik: key yang sama selalu menghasilkan S-box yang sama.

### 5.2 Key Schedule

Round key dibangkitkan secara iteratif dari master key:
- Bagian-bagian key diserap bergantian di setiap ronde.
- Setiap langkah melewati S-box dinamis, sehingga hubungan round key dengan master key **tidak linear**.
- Setiap ronde mendapat konstanta ronde yang berbeda, sehingga tidak ada dua round key yang dibangun dengan cara identik.
- Operasi transpose, rotator, dan cascade dari ronde cipher dipakai ulang, dengan harapan perubahan 1 bit key cepat menyebar ke seluruh round key.

---

## 6. Mode Operasi

Kelima mode wajib di-implement sendiri. Lihat [diagram 05](diagrams/05-modes.md). `E` = enkripsi blok, `D` = dekripsi blok.

| Mode | Ide                                                                 | Butuh IV / counter  |
| ---- | ------------------------------------------------------------------- | ------------------- |
| ECB  | Setiap blok dienkripsi sendiri-sendiri                              | Tidak               |
| CBC  | Plaintext di-XOR dengan ciphertext sebelumnya, lalu dienkripsi      | IV                  |
| CFB  | Ciphertext sebelumnya dienkripsi, lalu di-XOR dengan plaintext      | IV                  |
| OFB  | Output enkripsi sebelumnya dienkripsi lagi jadi keystream           | IV                  |
| CTR  | Counter yang terus bertambah dienkripsi jadi keystream              | Counter awal        |

- IV atau counter awal bisa diberikan user. Kalau tidak, dibangkitkan acak.
- CFB, OFB, dan CTR hanya memakai arah enkripsi blok.
- Sifat tiap mode (kebocoran pola di ECB, error propagation, paralelisme) dibahas di laporan dan terlihat di analisis histogram.

---

## 7. Padding

Dipakai **PKCS#7** di kelima mode: data selalu ditambah 1 sampai 16 byte, dan setiap byte tambahan berisi jumlah byte yang ditambahkan.

**Alasan pemilihan:**
- Tidak ambigu: padding selalu ada, jadi data yang kebetulan berakhir dengan byte mirip padding tetap bisa dibedakan.
- Satu cara yang sama untuk semua mode. CFB, OFB, dan CTR sebenarnya tidak butuh padding, tapi tetap di-pad supaya format file dan pengujian seragam.
- Aturan unpad sederhana dan mudah diverifikasi.
- Unpad hanya dilakukan setelah MAC lolos, sehingga tidak bisa dipakai penyerang sebagai padding oracle.

Edge case yang harus ditangani (sesuai spec): file kosong, 1 byte, tepat kelipatan blok (ditambah 1 blok penuh), serta kelipatan blok plus atau minus 1.

---

## 8. Integritas

Lihat [diagram 06](diagrams/06-kdf-mac.md).

- **Encrypt-then-MAC:** data dienkripsi dulu, lalu MAC dihitung atas ciphertext beserta header file.
- **Key terpisah:** dari master key diturunkan dua key berbeda, satu untuk enkripsi dan satu untuk MAC. Penurunannya (KDF) memakai TK-Cipher sendiri.
- **MAC buatan sendiri:** konstruksi CMAC yang dijalankan dengan TK-Cipher, bukan library.
- **Verifikasi dulu, baru dekripsi:** kalau tag tidak cocok, proses langsung berhenti dengan error jelas dan tidak ada plaintext yang ditulis.
- **Constant-time compare:** perbandingan tag tidak berhenti di byte pertama yang berbeda, supaya waktu eksekusi tidak membocorkan informasi.
- **Key salah otomatis ditolak**, karena key MAC yang diturunkan dari key salah akan berbeda.

---

## 9. Format File

File ciphertext bersifat **self-describing**, sehingga dekripsi cukup butuh file dan key. Isinya berurutan ([diagram 07](diagrams/07-file-format.md)):

1. **Header:** penanda format (magic), versi, mode, field cadangan (reserved), IV atau counter awal, panjang plaintext asli.
2. **Ciphertext.**
3. **Tag MAC.**

Header ikut dilindungi MAC, jadi mengubah mode, IV, atau panjang juga terdeteksi. Ukuran dan posisi tiap field ada di `docs/blueprint.md`.

---

## 10. Program

Program berupa CLI dengan tiga perintah: enkripsi, dekripsi, dan pembangkitan key acak. User memberikan file input, file output, key, mode, dan (opsional) IV. Program berjalan di Linux dan Windows dan hanya memakai standard library Python di jalur kriptografi. Lihat [diagram 08](diagrams/08-cli-and-modules.md).

---

## 11. Yang Akan Diukur

Klaim desain di dokumen ini dibuktikan lewat analisis setelah implementasi (`docs/trd.md` Bagian 8):

| Klaim desain                                | Dibuktikan oleh                                         |
| ------------------------------------------- | ------------------------------------------------------- |
| Confusion dan diffusion                     | Avalanche plaintext dan key di 5 mode                   |
| 16 ronde cukup                              | Avalanche dan penyebaran bit per jumlah ronde           |
| Ciphertext terlihat acak                    | Entropi dan histogram, plaintext vs ciphertext          |
| ECB membocorkan pola, mode lain tidak       | Histogram dan visual gambar terenkripsi                 |
| S-box dinamis berkualitas                   | Statistik S-box untuk banyak key                        |
| Integritas berjalan                         | Test tamper dan key salah                               |

---

## 12. Perbedaan dengan AES

| Aspek         | AES                                           | TK-Cipher                                                          |
| ------------- | --------------------------------------------- | ------------------------------------------------------------------ |
| Urutan ronde  | SubBytes, ShiftRows, MixColumns, AddRoundKey  | AddRoundKey, DiagonalTranspose, DynamicSub, RowRotator, ColumnCascade |
| S-box         | Satu S-box tetap                              | S-box berbeda untuk setiap key                                     |
| Transposisi   | Geser byte per baris                          | Transpose matriks penuh                                            |
| Pencampuran   | Perkalian di Galois Field                     | Rotasi bit per baris + penjumlahan modular per kolom               |
| Key schedule  | Berbasis word dengan konstanta Rcon           | Penyerapan key bergantian lewat S-box dinamis dan operasi ronde    |

Kesamaan dengan AES hanya pada bentuk state 4x4 dan ukuran blok.

---

## 13. Pelajaran dari Rancangan Awal

Rancangan pertama tidak merotasi baris pertama, sementara transpose tidak memindahkan byte di pojok kiri atas. Akibatnya byte pertama setiap blok tidak pernah tercampur dengan byte lain, berapa pun jumlah rondenya. Rancangan awal juga tidak punya operasi yang benar-benar mencampur nilai antar-byte.

Desain sekarang memperbaikinya dengan merotasi semua baris dan menambahkan ColumnCascade.

---

## 14. Batasan

- Dibuat untuk tugas kuliah dan belum melalui kriptanalisis formal.
- Implementasi Python tidak menjamin waktu eksekusi konstan selain pada perbandingan tag.
- Kualitas S-box bisa bervariasi antar key, tetapi selalu di atas batas minimum.
- IV atau counter tidak boleh dipakai ulang dengan key yang sama di mode OFB dan CTR.
- Key dimasukkan dalam bentuk hex, bukan passphrase.
