# TRD: TK-Cipher

**Dokumen:** Technical Requirements Document
**Proyek:** IF4020 Tugas 2, Custom Block Cipher
**Acuan:** spesifikasi tugas IF4020 Tugas 2 (sumber kebenaran), `docs/blueprint.md` (rancangan)
**Deadline:** Sabtu, 10 Oktober 2026, 23.59 WIB (release GitHub)
**Status:** Rancangan awal, belum ada implementasi. Menjadi dasar backlog issue (Bagian 13).

---

## 1. Tujuan & Scope

Membangun **TK-Cipher**, block cipher SPN 128-bit buatan sendiri, beserta:

1. Library Python (`src/tk_cipher/`) untuk cipher, 5 mode operasi, padding, KDF, MAC, dan format file.
2. Program CLI `tk-cipher` untuk enkripsi dan dekripsi file teks atau biner.
3. Suite unit test (`tests/`) dan suite analisis keamanan (`analysis/`) yang hasilnya tersimpan di `tests/results/`.
4. Dokumentasi: `README.md`, `docs/DESIGN.md` + `docs/diagrams/`, draft laporan, dan API docs ter-host.
5. Executable untuk Linux dan Windows di `dist/` dan di GitHub Release.
6. Video demo (dikerjakan manual oleh anggota).

**Di luar scope:** GUI, mode AEAD lain (GCM dsb.), passphrase/password hashing, streaming file yang lebih besar dari RAM. Cover, foto, dan tanda tangan laporan dikerjakan manual.

### 1.1 Kebijakan Bonus dan Item Opsional

**Semua item bonus dan opsional di spec diperlakukan WAJIB.** Tidak ada label "opsional" di TRD ini. Item bonus yang bergantung pada main spec dikerjakan sebagai issue tersendiri setelah dependensinya selesai (Bagian 13).

| Item bonus/opsional di spec                    | Sumber spec    | Di TRD           | Issue       |
| ---------------------------------------------- | -------------- | ---------------- | ----------- |
| API documentation ter-host (+5)                | Bagian 6       | Bagian 9, FR-D1  | #20         |
| Video demo                                     | Bagian 6, 5.10 | Bagian 9         | #24         |
| Executable                                     | Bagian 4       | NFR-8            | #21         |
| File kecil / sedang / besar (performa + hasil) | Bagian 3.4     | T-14, A-08       | #12, #19    |
| Round-trip test                                | Bagian 3.4     | T-03, T-08, T-14 | #5, #7, #13 |
| Tamper test                                    | Bagian 3.4     | T-15             | #13         |
| Wrong key test                                 | Bagian 3.4     | T-16             | #13         |
| Edge case padding                              | Bagian 3.4     | T-06, T-07       | #6          |
| Chi-square / uji uniformitas                   | Bagian 3.4     | A-06             | #16         |
| Test vector                                    | Bagian 3.4     | T-04             | #5          |
| Benchmark throughput                           | Bagian 3.4     | A-08             | #19         |

---

## 2. Istilah

| Istilah    | Arti                                                                |
| ---------- | ------------------------------------------------------------------- |
| Block      | 16 byte (128-bit)                                                   |
| Master key | Key dari user, 16/24/32 byte                                        |
| K_enc      | Key enkripsi hasil KDF                                              |
| K_mac      | Key MAC hasil KDF                                                   |
| RK_i       | Round key ke-i, i = 0..16 (17 buah)                                 |
| IV         | Initialization vector 16 byte (CBC/CFB/OFB) atau counter awal (CTR) |
| Tag        | Output CMAC 16 byte                                                 |
| PT / CT    | Plaintext / ciphertext                                              |

---

## 3. Functional Requirements

### 3.1 Cipher core (FR-C)

| ID    | Requirement                                                                                                     |
| ----- | --------------------------------------------------------------------------------------------------------------- |
| FR-C1 | Block size 16 byte. Input selain 16 byte ke `encrypt_block`/`decrypt_block` => `ValueError`.                    |
| FR-C2 | Master key 16, 24, atau 32 byte. Panjang lain => `InvalidKeyError`.                                             |
| FR-C3 | 16 ronde. Tiap ronde: AddRoundKey => DiagonalTranspose => DynamicSub => RowRotator => ColumnCascade.            |
| FR-C4 | Whitening akhir dengan RK_16. Total 17 round key.                                                               |
| FR-C5 | DiagonalTranspose: `state[r][c] => state[c][r]`, state row-major `b[4r + c]`.                                   |
| FR-C6 | RowRotator: baris r sebagai uint32 big-endian, rotasi kiri `ROT = [1, 3, 5, 7]` bit. Inverse: rotasi kanan.     |
| FR-C7 | ColumnCascade per kolom (mod 256): `b += a; d += b; e += d; a += e`. Inverse: `a -= e; e -= d; d -= b; b -= a`. |
| FR-C8 | `decrypt_block(encrypt_block(x)) == x` untuk semua x dan semua key valid.                                       |
| FR-C9 | Semua operasi deterministik: key + PT yang sama selalu menghasilkan CT yang sama (test vector stabil).          |

### 3.2 Key setup (FR-K)

| ID    | Requirement                                                                                                                                                 |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-K1 | PRNG `TKRand` sesuai blueprint Bagian 3.1 (ARX 4 x 32-bit, seed `b"TKC-SBOX" + key + bytes([len(key)])`, 32 warm-up, output `s0 ^ s2`, rejection sampling). |
| FR-K2 | S-box: Fisher-Yates dengan `TKRand`, lalu fix-up sampai tidak ada `S[x] == x` dan `S[x] == x ^ 0xFF`.                                                       |
| FR-K3 | S-box diterima hanya jika differential uniformity <= 12 dan nonlinearity >= 90. Kalau tidak, ulangi dari FR-K2 (PRNG lanjut).                               |
| FR-K4 | `S_inv` dihitung dari `S`. Statistik (DU, NL, jumlah percobaan) bisa diambil lewat API untuk dokumentasi.                                                   |
| FR-K5 | Round key sesuai blueprint Bagian 3.2 (lane k0/k1, S-box, RC_i, transpose + rotator + cascade).                                                             |
| FR-K6 | Waktu key setup per key dicatat di benchmark (A-08).                                                                                                        |

### 3.3 Mode operasi (FR-M)

| ID    | Requirement                                                                                                     |
| ----- | --------------------------------------------------------------------------------------------------------------- |
| FR-M1 | Mode ECB, CBC, CFB (full-block 128), OFB, CTR, semua di-implement sendiri.                                      |
| FR-M2 | Input ke layer mode selalu kelipatan 16 byte (sudah di-pad). Selain itu => `ValueError`.                        |
| FR-M3 | CBC/CFB/OFB memakai IV 16 byte. CTR memakai counter awal 16 byte, increment `(CTR_0 + i) mod 2^128` big-endian. |
| FR-M4 | ECB tidak menerima IV. IV yang diberikan untuk ECB => error argumen.                                            |
| FR-M5 | IV/counter tidak diberikan => dibangkitkan dengan `os.urandom(16)`.                                             |
| FR-M6 | CFB, OFB, CTR hanya memakai `encrypt_block`.                                                                    |

### 3.4 Padding (FR-P)

| ID    | Requirement                                                                                                     |
| ----- | --------------------------------------------------------------------------------------------------------------- |
| FR-P1 | PKCS#7 di kelima mode. Pad p = 16 - (len mod 16), nilai p, p dalam 1..16.                                       |
| FR-P2 | Input kosong => 1 blok penuh `0x10`. Input kelipatan 16 => tambah 1 blok penuh `0x10`.                          |
| FR-P3 | Unpad memvalidasi panjang kelipatan 16, `1 <= p <= 16`, dan semua p byte terakhir = p. Gagal => `PaddingError`. |
| FR-P4 | Unpad hanya dipanggil setelah MAC lolos.                                                                        |

### 3.5 KDF & MAC (FR-I)

| ID    | Requirement                                                                                                                        |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------- |
| FR-I1 | KDF: `block(label, j) = E_master(b"TKC--KDF" + bytes([label]) + bytes(6) + bytes([j]))`. K_enc pakai label 0x01, K_mac label 0x02. |
| FR-I2 | Panjang K_enc dan K_mac = panjang master key (gabung blok j = 0, 1, lalu dipotong).                                                |
| FR-I3 | MAC: CMAC (OMAC1) dengan TK-Cipher(K_mac), subkey `dbl` dengan konstanta 0x87, tag 16 byte.                                        |
| FR-I4 | Input MAC = header (32 byte) + ciphertext. Encrypt-then-MAC.                                                                       |
| FR-I5 | `constant_time_eq(a, b)` sendiri: loop penuh tanpa early return, membandingkan juga panjangnya.                                    |
| FR-I6 | Dilarang `hashlib`, `hmac`, `secrets`, `random`, dan library crypto apa pun di `src/`.                                             |

### 3.6 Format file (FR-F)

| ID    | Requirement                                                                                                                                                                        |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-F1 | Layout: magic `"TKC1"` (4), version `0x01` (1), mode (1), reserved `0x0000` (2), IV (16), original length uint64 BE (8), ciphertext (N), tag (16). Detail di blueprint Bagian 5.4. |
| FR-F2 | Kode mode: 0 = ECB, 1 = CBC, 2 = CFB, 3 = OFB, 4 = CTR. ECB menulis IV 16 byte nol.                                                                                                |
| FR-F3 | Dekripsi urut: (1) validasi struktur, (2) verifikasi tag constant-time, (3) dekripsi, (4) unpad, (5) cek panjang == original length.                                               |
| FR-F4 | Validasi struktur: ukuran >= 64, `(size - 48) % 16 == 0`, magic, version, mode 0..4, reserved = 0. Gagal => `InvalidFormatError`.                                                  |
| FR-F5 | Tag tidak cocok => `AuthenticationError("MAC verification failed: wrong key or file has been modified")`. Tidak ada plaintext yang ditulis, sebagian pun tidak.                    |
| FR-F6 | Output ditulis ke file sementara di folder tujuan, lalu `os.replace` ke nama akhir.                                                                                                |
| FR-F7 | File cukup didekripsi dengan file + key (mode dan IV dibaca dari header).                                                                                                          |

### 3.7 CLI (FR-U)

```
tk-cipher enc -i <in> -o <out> (-k <hex> | --key-file <path>) -m {ecb,cbc,cfb,ofb,ctr} [--iv <32 hex>]
tk-cipher dec -i <in> -o <out> (-k <hex> | --key-file <path>)
tk-cipher keygen [--bits {128,192,256}]
```

| ID    | Requirement                                                                                                                                                |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-U1 | Key berupa hex 32/48/64 karakter (spasi dan huruf besar/kecil diterima). `--key-file` berisi hex yang sama.                                                |
| FR-U2 | `-k` dan `--key-file` saling eksklusif, salah satu wajib.                                                                                                  |
| FR-U3 | `--iv` harus 32 karakter hex. Di mode CTR artinya counter awal.                                                                                            |
| FR-U4 | Saat enc, CLI mencetak mode dan IV yang dipakai (hex) ke stderr, supaya IV auto-generate bisa dicatat.                                                     |
| FR-U5 | `-o` sama dengan `-i` ditolak.                                                                                                                             |
| FR-U6 | Exit code: 0 sukses, 1 argumen/key invalid atau file input tidak ada, 2 format file invalid, 3 autentikasi gagal. Pesan error satu baris, tanpa traceback. |
| FR-U7 | Jalan via `python -m tk_cipher ...` dan via script `tk-cipher` (entry point di `pyproject.toml`).                                                          |

### 3.8 Deliverable Bonus (FR-D)

| ID    | Requirement                                                                                                                                   |
| ----- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-D1 | API docs dibangkitkan dari docstring (pdoc), di-deploy otomatis ke GitHub Pages lewat GitHub Actions, link di README dan di "About" repo.     |
| FR-D2 | API docs memuat untuk setiap fungsi/kelas publik: deskripsi, parameter + tipe data, return + tipe data, exception, contoh pemakaian, catatan. |
| FR-D3 | README dan laporan menjelaskan tools yang dipakai untuk API docs (pdoc + GitHub Pages) dan cara membangunnya ulang.                           |
| FR-D4 | Executable single-file untuk Linux dan Windows dibangun dengan PyInstaller, berjalan tanpa Python terpasang, perilaku sama dengan CLI.        |
| FR-D5 | Video demo memperlihatkan enc/dec 5 mode (teks + biner), padding, tamper test, wrong key, dan hasil analisis. Dikerjakan manual oleh anggota. |

---

## 4. Public API (Python)

API ini juga jadi isi API docs (FR-D1). Semua fungsi publik wajib punya type hints dan docstring (deskripsi, parameter, return, raises, contoh).

```python
# tk_cipher/errors.py
class TKCipherError(Exception): ...
class InvalidKeyError(TKCipherError): ...
class InvalidFormatError(TKCipherError): ...
class AuthenticationError(TKCipherError): ...
class PaddingError(TKCipherError): ...

# tk_cipher/prng.py
class TKRand:
    def __init__(self, seed: bytes) -> None: ...
    def next32(self) -> int: ...
    def below(self, n: int) -> int: ...                     # uniform di [0, n)

# tk_cipher/sbox.py
@dataclass(frozen=True)
class SBox:
    forward: tuple[int, ...]                                 # 256 entri
    inverse: tuple[int, ...]
    differential_uniformity: int
    nonlinearity: int
    attempts: int
def generate_sbox(key: bytes) -> SBox: ...

# tk_cipher/key_schedule.py
def expand_key(key: bytes, sbox: SBox, rounds: int = 16) -> list[bytes]: ...   # rounds + 1 round key

# tk_cipher/cipher.py
BLOCK_SIZE: int = 16
ROUNDS: int = 16
class TKCipher:
    def __init__(self, key: bytes) -> None: ...
    def encrypt_block(self, block: bytes) -> bytes: ...
    def decrypt_block(self, block: bytes) -> bytes: ...

# tk_cipher/padding.py
def pad(data: bytes, block_size: int = 16) -> bytes: ...
def unpad(data: bytes, block_size: int = 16) -> bytes: ...

# tk_cipher/modes.py
class Mode(IntEnum): ECB = 0; CBC = 1; CFB = 2; OFB = 3; CTR = 4
def encrypt(cipher: TKCipher, mode: Mode, data: bytes, iv: bytes | None) -> bytes: ...
def decrypt(cipher: TKCipher, mode: Mode, data: bytes, iv: bytes | None) -> bytes: ...

# tk_cipher/kdf.py
def derive_keys(master_key: bytes) -> tuple[bytes, bytes]: ...   # (k_enc, k_mac)

# tk_cipher/mac.py
def cmac(key: bytes, message: bytes) -> bytes: ...
def constant_time_eq(a: bytes, b: bytes) -> bool: ...

# tk_cipher/fileformat.py
@dataclass(frozen=True)
class Header:
    mode: Mode
    iv: bytes
    original_length: int
    version: int = 1
    def pack(self) -> bytes: ...
    @classmethod
    def unpack(cls, data: bytes) -> "Header": ...
def encrypt_bytes(plaintext: bytes, master_key: bytes, mode: Mode, iv: bytes | None = None) -> bytes: ...
def decrypt_bytes(blob: bytes, master_key: bytes) -> bytes: ...
def encrypt_file(src: Path, dst: Path, master_key: bytes, mode: Mode, iv: bytes | None = None) -> Header: ...
def decrypt_file(src: Path, dst: Path, master_key: bytes) -> Header: ...
```

Catatan desain:

- `TKCipher` menyimpan S-box dan round key, sehingga satu instance dipakai ulang untuk semua blok.
- Layer mode menerima instance `TKCipher`, bukan key, supaya analisis bisa mengukur cipher + mode tanpa KDF/MAC.
- File diproses di memori (cukup untuk file uji sampai beberapa MB).

---

## 5. Non-Functional Requirements

| ID    | Requirement                                                                                                                                     |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| NFR-1 | Python >= 3.10. Jalur cipher hanya memakai stdlib (`os`, `struct`, `argparse`, `pathlib`, `dataclasses`, `enum`, `tempfile`).                   |
| NFR-2 | Jalan di Linux dan Windows: path via `pathlib`, file dibuka mode biner, tidak ada perintah shell atau path hardcoded.                           |
| NFR-3 | Performa diukur di benchmark (A-08). Optimasi yang boleh: tabel precomputed, operasi int, selama hasil identik dengan test vector.              |
| NFR-4 | Clean code: type hints, docstring, nama fungsi sesuai istilah blueprint (`diagonal_transpose`, `row_rotator`, `column_cascade`, `dynamic_sub`). |
| NFR-5 | Tidak ada salinan kode AES/DES/Blowfish atau S-box AES. Inspirasi dicantumkan di `docs/DESIGN.md` dan laporan.                                  |
| NFR-6 | Dependensi analisis (numpy, matplotlib) dan test (pytest) dipisah dari cipher dan tidak di-import oleh `src/`.                                  |
| NFR-7 | Pesan error jelas, tidak membocorkan perbedaan antara wrong key dan file rusak.                                                                 |
| NFR-8 | Executable Linux dan Windows dibangun di CI (PyInstaller) dan dilampirkan ke GitHub Release, salinannya di `dist/`.                             |
| NFR-9 | CI GitHub Actions menjalankan seluruh test di matrix `ubuntu-latest` dan `windows-latest` di setiap push dan pull request.                      |

---

## 6. Struktur Repo & Build

```
.
├── README.md
├── pyproject.toml              # package tk_cipher, script tk-cipher, tanpa dependency runtime
├── requirements-analysis.txt   # numpy, matplotlib
├── requirements-dev.txt        # pytest, pdoc (atau mkdocs)
├── src/tk_cipher/              # lihat blueprint Bagian 8
├── tests/
│   ├── data/                   # sample input
│   ├── results/                # output analisis + log
│   └── test_*.py
├── analysis/
│   ├── avalanche.py
│   ├── entropy.py
│   ├── histogram.py
│   ├── round_diffusion.py
│   ├── sbox_stats.py
│   └── benchmark.py
├── docs/                       # DESIGN.md, blueprint.md, trd.md, diagrams/, draft laporan
└── dist/                       # executable PyInstaller (Linux + Windows)
```

Sample input di `tests/data/`:

| File                | Isi                                              | Tujuan                          |
| ------------------- | ------------------------------------------------ | ------------------------------- |
| `text_small.txt`    | Teks Indonesia/Inggris ~20 KB                    | Round-trip teks, entropi teks   |
| `repetitive.bin`    | Pola 16 byte diulang, ~64 KB                     | Histogram, kebocoran ECB        |
| `image.bmp`         | Gambar BMP tidak terkompresi, ~100 sampai 300 KB | Visual ECB vs mode lain         |
| `binary.pdf`/`.png` | File biner nyata ~100 KB                         | Round-trip biner                |
| `medium.bin`        | ~1 MB                                            | Round-trip + benchmark (sedang) |
| `large.bin`         | ~5 MB, dibangkitkan skrip, tidak di-commit       | Round-trip + benchmark (besar)  |

Kategori ukuran: kecil = file di bawah 100 KB, sedang = `medium.bin`, besar = `large.bin`. File edge case (0, 1, 15, 16, 17, 31, 32, 33 byte) dibangkitkan langsung di test, tidak disimpan.

---

## 7. Test Requirements

Semua test dijalankan dengan `pytest` dari root. Test yang lambat (key avalanche, file 1 MB) diberi marker `slow`.

| ID   | Test                                                                                                                        | Kriteria lulus                                                          |
| ---- | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| T-01 | Inverse komponen: transpose, rotator, cascade, S-box untuk 1000 state acak                                                  | `inv(f(x)) == x`                                                        |
| T-02 | S-box: permutasi, tanpa fixed/opposite fixed point, DU <= 12, NL >= 90, untuk 20 key acak                                   | Semua terpenuhi                                                         |
| T-03 | Round-trip blok: 1000 blok acak x key 128/192/256                                                                           | Identik                                                                 |
| T-04 | Test vector: 3 vektor tetap (128/192/256) disimpan di fixture test + `tests/results/`                                       | CT persis sama                                                          |
| T-05 | Determinisme: key sama => S-box dan round key sama                                                                          | Identik                                                                 |
| T-06 | Padding: panjang 0, 1, 15, 16, 17, 31, 32, 33 => pad lalu unpad                                                             | Identik, panjang pad benar                                              |
| T-07 | Unpad input rusak (p = 0, p > 16, byte pad tidak seragam, panjang bukan kelipatan 16)                                       | `PaddingError`                                                          |
| T-08 | Mode round-trip: 5 mode x edge case panjang x key 128/192/256                                                               | Identik                                                                 |
| T-09 | Mode vs definisi: CBC/CFB/OFB/CTR dihitung manual blok per blok dari `encrypt_block` untuk 3 blok                           | Sama dengan output layer mode                                           |
| T-10 | CTR wrap: counter awal `ff..ff`                                                                                             | Blok berikutnya pakai `00..00`, round-trip OK                           |
| T-11 | KDF: K_enc != K_mac, panjang = panjang master key, deterministik                                                            | Terpenuhi                                                               |
| T-12 | CMAC: pesan beda 1 bit => tag beda; pesan beda panjang => tag beda; key beda => tag beda                                    | Terpenuhi                                                               |
| T-13 | `constant_time_eq`: sama, beda 1 byte di awal/akhir, beda panjang                                                           | Hasil benar                                                             |
| T-14 | File round-trip: semua file `tests/data/` x 5 mode                                                                          | Byte-identical                                                          |
| T-15 | Tamper: flip 1 bit di magic/version/mode/reserved/IV/length/ciphertext/tag                                                  | `InvalidFormatError` atau `AuthenticationError`, output tidak terbentuk |
| T-16 | Wrong key: dekripsi dengan key lain (beda 1 bit, dan acak)                                                                  | `AuthenticationError`, output tidak terbentuk                           |
| T-17 | File terpotong (< 64 byte, panjang tidak pas)                                                                               | `InvalidFormatError`                                                    |
| T-18 | CLI: enc/dec semua mode, IV auto vs manual, `--iv` di ECB ditolak, key invalid, exit code 0/1/2/3                           | Sesuai FR-U                                                             |
| T-19 | Larangan import: scan AST semua file `src/` untuk `hashlib`, `hmac`, `secrets`, `random`, `Crypto`, `cryptography`, `numpy` | Tidak ditemukan                                                         |

---

## 8. Analysis Requirements

Semua skrip di `analysis/` bisa dijalankan ulang dan menulis hasil ke `tests/results/` (CSV/JSON + PNG + ringkasan Markdown). Seed analisis dicatat supaya hasil bisa direproduksi.

| ID   | Analisis            | Metode                                                                                                                                                                                   | Output                                          |
| ---- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| A-01 | Avalanche plaintext | 1000 sampel per mode, input 4 blok, flip 1 bit acak, **IV sama** untuk kedua run, bandingkan ciphertext tanpa tag. Laporkan per blok dan total: mean/min/max/std.                        | `avalanche_plaintext.csv`, ringkasan            |
| A-02 | Avalanche key       | 300 sampel per mode (minimal), flip 1 bit master key, PT dan IV sama. Diukur di level `TKCipher` + mode (tanpa KDF/MAC) dan 50 sampel lewat jalur file lengkap. Boleh `multiprocessing`. | `avalanche_key.csv`, ringkasan                  |
| A-03 | Round diffusion     | Avalanche dan dependency bit per jumlah ronde 1..16 (justifikasi 16 ronde)                                                                                                               | `round_diffusion.csv`, PNG                      |
| A-04 | Entropi Shannon     | Per file `tests/data/` x 5 mode, PT vs CT (bit/byte)                                                                                                                                     | `entropy.csv`                                   |
| A-05 | Histogram           | Frekuensi byte PT vs CT per file x mode, plus visual BMP terenkripsi ECB vs CBC                                                                                                          | `histogram_<file>_<mode>.png`, `ecb_vs_cbc.png` |
| A-06 | Chi-square          | Uji uniformitas byte CT, df = 255                                                                                                                                                        | `chi_square.csv`                                |
| A-07 | Statistik S-box     | DU, NL, attempts untuk 100 key                                                                                                                                                           | `sbox_stats.csv`                                |
| A-08 | Benchmark           | Throughput enc/dec file kecil/sedang/besar per mode                                                                                                                                      | `benchmark.csv`                                 |

Ekspektasi yang harus dijelaskan di laporan (bukan bug):

- OFB dan CTR: flip 1 bit PT => tepat 1 bit CT berubah (stream mode).
- CFB: blok yang diubah 1 bit, blok sesudahnya ~50%.
- CBC: blok yang diubah dan semua blok sesudahnya ~50%. ECB: hanya blok yang diubah ~50%.
- Key avalanche: ~50% di semua mode.

---

## 9. Dokumentasi

| Dokumen          | Isi wajib                                                                                                                                                                                                                                                                              |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `README.md`      | Nama + deskripsi, tech stack, dependensi, cara install/run, contoh enc/dec untuk 5 mode, cara run test & analisis, link API docs.                                                                                                                                                      |
| `docs/DESIGN.md` | Gambaran umum desain: ide dan alasan tiap komponen (ronde, key setup, mode, padding, integritas, format file), perbedaan dengan AES, dan klaim yang dibuktikan analisis. Tanpa konstanta (ada di blueprint) dan tanpa angka hasil ukur (ada di `tests/results/`). Bahan Bab 5 laporan. |
| `docs/diagrams/` | 8 file diagram Mermaid (alur file, cipher, operasi state, key setup, mode, KDF/MAC, format file, CLI/modul), dirujuk dari DESIGN.md.                                                                                                                                                   |
| Draft laporan    | Bab 3 sampai 9 sesuai sistematika spec, mengambil isi dari DESIGN.md dan `tests/results/`. Cover, pernyataan keaslian, foto, tanda tangan, video diisi manual.                                                                                                                         |
| API docs         | Dibangkitkan dari docstring (pdoc), di-deploy ke GitHub Pages. Isi: deskripsi, parameter + tipe data, return, raises, contoh, catatan. Tools dijelaskan di README.                                                                                                                     |

---

## 10. Rencana Kerja (4 sampai 10 Oktober 2026)

| Tanggal    | Target                                                                                     | Selesai jika                        |
| ---------- | ------------------------------------------------------------------------------------------ | ----------------------------------- |
| Min 4 Okt  | TRD final, scaffold repo (`pyproject.toml`, folder, CI test lokal), DESIGN.md + diagrams   | `pytest` jalan (kosong)             |
| Sen 5 Okt  | `prng`, `sbox`, `key_schedule`, `cipher` + test vector                                     | T-01 sampai T-05 lulus              |
| Sel 6 Okt  | `padding`, `modes`, `kdf`, `mac`, `fileformat`                                             | T-06 sampai T-17 lulus              |
| Rab 7 Okt  | `cli`, sample data, uji di Windows                                                         | T-18, T-19 lulus, demo 5 mode jalan |
| Kam 8 Okt  | Semua skrip analisis + hasil di `tests/results/`                                           | A-01 sampai A-08 lengkap            |
| Jum 9 Okt  | Draft laporan + diagram desain, README, API docs ter-host                                  | Semua dokumen Bagian 9 ada          |
| Sab 10 Okt | Executable Linux + Windows, video demo, review akhir, **release GitHub sebelum 20.00 WIB** | Release + link di Google Form       |

Pembagian peran (sesuaikan dengan anggota):

- **A:** cipher core + key setup + test vector.
- **B:** modes, padding, KDF, MAC, file format.
- **C:** CLI, sample data, uji Windows, README, release.
- **D (atau dibagi):** analisis, draft laporan, API docs. DESIGN.md di-update siapa pun yang mengubah desain.

---

## 11. Traceability (Spec => TRD => Test)

| Spec                                                                                  | Requirement                      | Bukti                          |
| ------------------------------------------------------------------------------------- | -------------------------------- | ------------------------------ |
| Block >= 64-bit, key >= block                                                         | FR-C1, FR-C2                     | T-03                           |
| Iterated cipher, round key per ronde                                                  | FR-C3, FR-C4, FR-K5              | T-04, A-03                     |
| Substitusi, transposisi, operasi tambahan                                             | FR-C5 sampai FR-C7, FR-K2, FR-K3 | T-01, T-02                     |
| Confusion + diffusion                                                                 | FR-C3, FR-K3                     | A-01, A-02, A-03               |
| S-box sendiri + dokumentasi                                                           | FR-K1 sampai FR-K4               | T-02, A-07, DESIGN.md Bagian 5 |
| 5 mode from scratch, IV/counter                                                       | FR-M1 sampai FR-M6               | T-08 sampai T-10               |
| Padding + edge case + justifikasi                                                     | FR-P1 sampai FR-P4               | T-06, T-07, DESIGN.md Bagian 7 |
| Integritas, MAC from scratch, verify dulu                                             | FR-I1 sampai FR-I5, FR-F3, FR-F5 | T-11 sampai T-16               |
| Format file self-describing                                                           | FR-F1 sampai FR-F7               | T-14, T-15, T-17               |
| No third-party crypto                                                                 | FR-I6, NFR-1, NFR-6              | T-19                           |
| Program input/output, Linux/Windows                                                   | FR-U1 sampai FR-U7, NFR-2        | T-18, uji Windows              |
| Avalanche, entropi, histogram di 5 mode                                               | Bagian 8                         | A-01 sampai A-05               |
| README, laporan                                                                       | Bagian 9                         | Review akhir                   |
| Bonus: API docs, video, executable                                                    | FR-D1 sampai FR-D5, NFR-8        | #20, #21, #24                  |
| Item opsional spec (wajib bagi kita): chi-square, benchmark, ukuran file, test vector | Bagian 1.1, 7, 8                 | A-06, A-08, T-04, T-14         |

---

## 12. Definition of Done

- [ ] Semua FR terimplementasi, T-01 sampai T-19 lulus di Linux dan Windows (CI).
- [ ] A-01 sampai A-08 untuk 5 mode tersimpan di `tests/results/`.
- [ ] T-19 lulus (zero third-party crypto) dan `pyproject.toml` tanpa dependency runtime.
- [ ] README, DESIGN.md + diagrams, test vector di `tests/results/`, dan draft laporan (Bab 3 sampai 9) lengkap.
- [ ] API docs ter-host dan link ada di README.
- [ ] Executable Linux dan Windows ada di `dist/` dan di GitHub Release.
- [ ] Video demo selesai dan link ada di laporan.
- [ ] Semua issue di Bagian 13 closed.
- [ ] Release GitHub dibuat sebelum 10 Oktober 2026 23.59 WIB.

---

## 13. Backlog GitHub Issues

Daftar issue yang akan dibuat di GitHub (belum dibuat). Semua issue **wajib**, termasuk yang berasal dari bonus. Label: `core`, `test`, `analysis`, `docs`, `bonus`, `infra`, `manual`. Satu issue = satu PR, dan test di dalam issue harus lulus sebelum PR di-merge.

| #   | Judul                                        | Label           | Depends on           | Cakupan                                                                                                                                                                                        | Selesai jika                                          |
| --- | -------------------------------------------- | --------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| 1   | Scaffold repo + CI Linux/Windows             | infra           |                      | `pyproject.toml` (tanpa dependency runtime, script `tk-cipher`), `requirements-analysis.txt`, `requirements-dev.txt`, `.gitignore`, konfigurasi pytest, GitHub Actions matrix ubuntu + windows | NFR-9, CI hijau dengan test kosong                    |
| 2   | PRNG TKRand                                  | core            | 1                    | `prng.py`                                                                                                                                                                                      | FR-K1, unit test determinisme dan `below`             |
| 3   | S-box dinamis + DU/NL                        | core            | 2                    | `sbox.py`, dataclass `SBox`, filter kualitas, inverse                                                                                                                                          | FR-K2 sampai FR-K4, T-02                              |
| 4   | Key schedule                                 | core            | 3                    | `key_schedule.py`, round constants, 17 round key                                                                                                                                               | FR-K5, T-05                                           |
| 5   | Cipher core + test vector                    | core            | 4                    | `cipher.py`, 5 operasi ronde + inverse, `TKCipher`, `errors.py`, 3 test vector                                                                                                                 | FR-C1 sampai FR-C9, T-01, T-03, T-04                  |
| 6   | Padding PKCS#7                               | core            | 1                    | `padding.py`                                                                                                                                                                                   | FR-P1 sampai FR-P3, T-06, T-07                        |
| 7   | Mode operasi ECB/CBC/CFB/OFB/CTR             | core            | 5                    | `modes.py`, `Mode` enum                                                                                                                                                                        | FR-M1 sampai FR-M6, T-08 sampai T-10                  |
| 8   | KDF                                          | core            | 5                    | `kdf.py`                                                                                                                                                                                       | FR-I1, FR-I2, T-11                                    |
| 9   | CMAC-TK + constant-time compare              | core            | 5                    | `mac.py`                                                                                                                                                                                       | FR-I3, FR-I5, T-12, T-13                              |
| 10  | Format file + encrypt/decrypt file           | core            | 6, 7, 8, 9           | `fileformat.py`, header, alur verify-then-decrypt, tulis atomik                                                                                                                                | FR-F1 sampai FR-F7, FR-I4, FR-P4                      |
| 11  | CLI                                          | core            | 10                   | `cli.py`, `__main__.py`, `keygen`, exit code                                                                                                                                                   | FR-U1 sampai FR-U7, T-18                              |
| 12  | Sample data kecil/sedang/besar               | test            | 1                    | Isi `tests/data/` (Bagian 6) + skrip pembangkit `large.bin`                                                                                                                                    | Semua file Bagian 6 tersedia                          |
| 13  | Integration test suite                       | test            | 11, 12               | Round-trip semua file x 5 mode x 3 ukuran key, tamper, wrong key, file rusak, scan import terlarang                                                                                            | T-14 sampai T-17, T-19, CI hijau di Linux dan Windows |
| 14  | Analisis avalanche plaintext + key           | analysis        | 7, 10                | `analysis/avalanche.py`                                                                                                                                                                        | A-01, A-02 untuk 5 mode di `tests/results/`           |
| 15  | Analisis round diffusion + justifikasi ronde | analysis        | 5                    | `analysis/round_diffusion.py`, finalisasi justifikasi 16 ronde di blueprint dan DESIGN.md                                                                                                      | A-03, hipotesis 16 ronde dikonfirmasi atau direvisi   |
| 16  | Analisis entropi + chi-square                | analysis, bonus | 10, 12               | `analysis/entropy.py`                                                                                                                                                                          | A-04, A-06                                            |
| 17  | Analisis histogram + visual ECB              | analysis        | 10, 12               | `analysis/histogram.py`                                                                                                                                                                        | A-05                                                  |
| 18  | Statistik S-box                              | analysis, bonus | 3                    | `analysis/sbox_stats.py`, tinjau ulang threshold DU/NL                                                                                                                                         | A-07                                                  |
| 19  | Benchmark kecil/sedang/besar                 | analysis, bonus | 11, 12               | `analysis/benchmark.py`, termasuk waktu key setup                                                                                                                                              | A-08, FR-K6, NFR-3                                    |
| 20  | API docs + GitHub Pages                      | docs, bonus     | 11                   | Docstring lengkap semua API publik, pdoc, workflow deploy Pages, link di README                                                                                                                | FR-D1 sampai FR-D3                                    |
| 21  | Executable Linux + Windows                   | infra, bonus    | 11                   | Spec PyInstaller, workflow build, artefak ke `dist/` dan Release                                                                                                                               | FR-D4, NFR-8, executable lolos smoke test enc/dec     |
| 22  | README                                       | docs            | 11, 20, 21           | 5 poin wajib spec + contoh 5 mode + cara test/analisis/build + link API docs + download executable                                                                                             | Bagian 9                                              |
| 23  | Draft laporan Bab 3 sampai 9                 | docs            | 13 sampai 19         | Isi dari DESIGN.md, diagram (export PNG), `tests/results/`                                                                                                                                     | Bagian 9, sistematika spec Bagian 5                   |
| 24  | Video demo                                   | manual, bonus   | 11, 13, 14 sampai 19 | Rekam demo sesuai FR-D5, upload, link di laporan                                                                                                                                               | FR-D5                                                 |
| 25  | Release GitHub + submit                      | infra           | 13 sampai 24         | Tag versi, lampirkan executable, cek DoD, link release ke Google Form                                                                                                                          | Bagian 12 terpenuhi                                   |

Urutan kritis: 1 => 2 => 3 => 4 => 5 => 7/8/9 => 10 => 11 => 13 => 23 => 25. Issue 6, 12, 15, dan 18 bisa dikerjakan paralel begitu dependensinya selesai.
