# TRD: TK-Cipher

**Dokumen:** Technical Requirements Document
**Proyek:** IF4020 Tugas 2, Custom Block Cipher
**Acuan:** spesifikasi tugas IF4020 Tugas 2 (sumber kebenaran), `docs/blueprint.md` (rancangan)
**Deadline:** Sabtu, 10 Oktober 2026, 23.59 WIB (release GitHub)
**Status:** Development selesai. Semua requirement terimplementasi dan diuji, laporan disusun di luar repo, video dibatalkan (#24), dan release GitHub (#25) dibuat satu kali setelah laporan final. Tim memakai Linux, jadi E2E lewat CLI dijalankan di Linux dan Windows dicakup lewat CI (pytest di `windows-latest`).

---

## 1. Tujuan & Scope

Membangun **TK-Cipher**, block cipher SPN 128-bit buatan sendiri, beserta:

1. Library Python (`src/tk_cipher/`) untuk cipher, 5 mode operasi, padding, KDF, MAC, dan format file.
2. Program CLI `tk-cipher` untuk enkripsi dan dekripsi file teks atau biner.
3. Suite unit test (`tests/`) dan suite analisis keamanan (`analysis/`) yang hasilnya tersimpan di `tests/results/`.
4. Dokumentasi: `README.md`, `docs/DESIGN.md` + `docs/diagrams/`, draft laporan, dan API docs ter-host.
5. Executable untuk Linux dan Windows di `dist/` dan di GitHub Release.
6. Video demo dibatalkan, tidak dikerjakan.

**Di luar scope:** GUI, mode AEAD lain (GCM dsb.), passphrase/password hashing, streaming file yang lebih besar dari RAM. Cover, foto, dan tanda tangan laporan dikerjakan manual.

### 1.1 Kebijakan Bonus dan Item Opsional

**Semua item bonus dan opsional di spec diperlakukan WAJIB.** Tidak ada label "opsional" di TRD ini. Item bonus yang bergantung pada main spec dikerjakan sebagai issue tersendiri setelah dependensinya selesai (Bagian 13).

| Item bonus/opsional di spec                    | Sumber spec    | Di TRD           | Issue       |
| ---------------------------------------------- | -------------- | ---------------- | ----------- |
| API documentation ter-host (+5)                | Bagian 6       | Bagian 9, FR-D1  | #20         |
| Video demo (dibatalkan)                        | Bagian 6, 5.10 | Bagian 9         | #24         |
| Executable                                     | Bagian 4       | NFR-8            | #21         |
| File kecil / sedang / besar (performa + hasil) | Bagian 3.4     | T-14, A-08       | #12, #19    |
| Round-trip test                                | Bagian 3.4     | T-03, T-08, T-14 | #6, #8, #13 |
| Tamper test                                    | Bagian 3.4     | T-15, T-20       | #13, #26    |
| Wrong key test                                 | Bagian 3.4     | T-16, T-20       | #13, #26    |
| Edge case padding                              | Bagian 3.4     | T-06, T-07       | #7          |
| Chi-square / uji uniformitas                   | Bagian 3.4     | A-06             | #16         |
| Test vector                                    | Bagian 3.4     | T-04             | #6          |
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
| FR-D1 | API docs dibangkitkan dari docstring (pdoc), di-build ke `docs/api/` dan disajikan GitHub Pages dari folder `docs/` di `main`. Link di README. |
| FR-D2 | API docs memuat untuk setiap fungsi/kelas publik: deskripsi, parameter + tipe data, return + tipe data, exception, contoh pemakaian, catatan. |
| FR-D3 | README dan laporan menjelaskan tools yang dipakai untuk API docs (pdoc + GitHub Pages) dan cara membangunnya ulang.                           |
| FR-D4 | Executable single-file untuk Linux dan Windows dibangun dengan PyInstaller, berjalan tanpa Python terpasang, perilaku sama dengan CLI.        |
| FR-D5 | Dibatalkan. Video demo tidak dikerjakan dan tidak ada link video di laporan. |

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
def differential_uniformity(s: Sequence[int]) -> int: ...
def nonlinearity(s: Sequence[int]) -> int: ...

# tk_cipher/rounds.py (dipisah dari cipher.py biar nggak circular import dengan key_schedule)
ROT = (1, 3, 5, 7)
TRANSPOSE_IDX: tuple[int, ...]
def add_round_key(state: list[int], rk: bytes) -> list[int]: ...
def diagonal_transpose(state: list[int]) -> list[int]: ...
def dynamic_sub(state: list[int], table: Sequence[int]) -> list[int]: ...
def row_rotator(state: list[int]) -> list[int]: ...
def inv_row_rotator(state: list[int]) -> list[int]: ...
def column_cascade(state: list[int]) -> list[int]: ...
def inv_column_cascade(state: list[int]) -> list[int]: ...

# tk_cipher/key_schedule.py
def expand_key(key: bytes, sbox: SBox, rounds: int = 16) -> list[bytes]: ...   # rounds + 1 round key

# tk_cipher/cipher.py
BLOCK_SIZE: int = 16
ROUNDS: int = 16
class TKCipher:
    def __init__(self, key: bytes, rounds: int = ROUNDS) -> None: ...   # rounds selain 16 cuma buat analisis
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
| NFR-8 | Executable Linux dan Windows dibangun manual pakai PyInstaller di masing-masing OS, dilampirkan ke GitHub Release, salinannya di `dist/`.                             |
| NFR-9 | CI (GitHub Actions) menjalankan ruff dan `pytest -m "not slow"` di Linux dan Windows setiap push dan PR. Full suite termasuk `slow` dijalankan lokal sebelum merge. |

---

## 6. Struktur Repo & Build

```
.
├── README.md
├── CONTRIBUTING.md             # setup uv, alur branch dan PR, test manual 2 OS
├── pyproject.toml              # package tk_cipher, script tk-cipher, tanpa dependency runtime, dependency group dev + analysis
├── uv.lock                     # dikelola uv, di-commit
├── .python-version
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
| T-20  | E2E: `tests/e2e/run_e2e.py` menjalankan keygen, enc/dec semua sample x 5 mode, tamper, wrong key, argumen salah lewat `python -m tk_cipher` dan executable | Semua skenario lulus di Linux, Windows dicakup CI (pytest) |

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
| Draft laporan    | Bab 3 sampai 9 sesuai sistematika spec, mengambil isi dari DESIGN.md dan `tests/results/`. Cover, pernyataan keaslian, foto, tanda tangan diisi manual.                                                                                                                         |
| API docs         | Dibangkitkan dari docstring (pdoc), di-deploy ke GitHub Pages. Isi: deskripsi, parameter + tipe data, return, raises, contoh, catatan. Tools dijelaskan di README.                                                                                                                     |

---

## 10. Rencana Kerja (4 sampai 10 Oktober 2026)

| Tanggal    | Target                                                                                     | Selesai jika                        |
| ---------- | ------------------------------------------------------------------------------------------ | ----------------------------------- |
| Min 4 Okt  | TRD final, scaffold repo (`pyproject.toml` + uv, folder), DESIGN.md + diagrams             | `uv run pytest` jalan (kosong)      |
| Sen 5 Okt  | `prng`, `sbox`, `key_schedule`, `cipher` + test vector                                     | T-01 sampai T-05 lulus              |
| Sel 6 Okt  | `padding`, `modes`, `kdf`, `mac`, `fileformat`                                             | T-06 sampai T-17 lulus              |
| Rab 7 Okt  | `cli`, sample data, uji di Windows                                                         | T-18, T-19 lulus, demo 5 mode jalan |
| Kam 8 Okt  | Semua skrip analisis + hasil di `tests/results/`                                           | A-01 sampai A-08 lengkap            |
| Jum 9 Okt  | E2E test, API docs ter-host, README, verifikasi final, mulai draft laporan                 | Development selesai (#27 closed)    |
| Sab 10 Okt | Executable Linux + Windows, review akhir, **release GitHub sebelum 20.00 WIB** | Release + link di Google Form       |

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
| Program input/output, Linux/Windows                                                   | FR-U1 sampai FR-U7, NFR-2        | T-18, T-20, CI 2 OS            |
| Avalanche, entropi, histogram di 5 mode                                               | Bagian 8                         | A-01 sampai A-05               |
| README, laporan                                                                       | Bagian 9                         | Review akhir                   |
| Bonus: API docs, executable                                                           | FR-D1 sampai FR-D4, NFR-8        | #20, #21                       |
| Item opsional spec (wajib bagi kita): chi-square, benchmark, ukuran file, test vector | Bagian 1.1, 7, 8                 | A-06, A-08, T-04, T-14         |

---

## 12. Definition of Done

- [x] Semua FR terimplementasi, T-01 sampai T-20 lulus (CI Linux dan Windows untuk test non `slow`, full suite dan E2E dijalankan lokal di Linux).
- [x] A-01 sampai A-08 untuk 5 mode tersimpan di `tests/results/` dan bisa dibuat ulang dengan `uv run python analysis/run_all.py`.
- [x] T-19 lulus (zero third-party crypto) dan `pyproject.toml` tanpa dependency runtime.
- [x] README, DESIGN.md + diagrams, dan test vector di `tests/results/` lengkap.
- [ ] Draft laporan (Bab 3 sampai 9) lengkap.
- [x] API docs ter-host dan link ada di README.
- [x] Executable Linux dan Windows ada di `dist/`.
- [ ] Executable dilampirkan di GitHub Release.
- [x] Video demo dibatalkan, tidak ada link video di laporan.
- [ ] Semua issue di Bagian 13 closed.
- [ ] Release GitHub dibuat sebelum 10 Oktober 2026 23.59 WIB.

---

## 13. Backlog GitHub Issues

Semua issue udah dibuat di GitHub dan semuanya **wajib**, termasuk yang asalnya bonus. Tiap issue self-contained: developer cukup baca issue-nya. Dependensi dipasang sebagai relasi "blocked by" bawaan GitHub, jadi issue yang belum bisa dikerjain kelihatan Blocked. Satu issue = satu PR, test di issue harus lulus sebelum merge.

Label tahapan: `setup`, `cipher`, `modes`, `integrity`, `program`, `testing`, `analysis`, `docs`, `release`, ditambah `bonus` (asalnya bonus atau opsional spec) dan `manual` (dikerjakan manual).

| #   | Judul | Label | Blocked by | Cakupan | Selesai jika | Status |
| --- | --- | --- | --- | --- | --- | --- |
| [#2](https://github.com/filbertengyo/tk_cipher/issues/2) | Scaffold project Python dan pytest | setup |  | `pyproject.toml` (uv, dependency group dev + analysis), `uv.lock`, `errors.py`, pytest, `CONTRIBUTING.md` | NFR-1, `uv run pytest` hijau | Selesai |
| [#3](https://github.com/filbertengyo/tk_cipher/issues/3) | PRNG TKRand dan S-box dinamis | cipher | #2 | `prng.py`, `sbox.py`, filter DU/NL, inverse | FR-K1 sampai FR-K4, T-02 | Selesai |
| [#4](https://github.com/filbertengyo/tk_cipher/issues/4) | Operasi ronde dan inverse-nya | cipher | #2 | `rounds.py`: 5 operasi ronde + inverse | T-01 | Selesai |
| [#5](https://github.com/filbertengyo/tk_cipher/issues/5) | Key schedule 17 round key | cipher | #3, #4 | `key_schedule.py`, round constants, 17 round key | FR-K5, T-05 | Selesai |
| [#6](https://github.com/filbertengyo/tk_cipher/issues/6) | TKCipher encrypt dan decrypt satu blok + test vector | cipher | #5 | `cipher.py`, `TKCipher(key, rounds)`, 3 test vector | FR-C1 sampai FR-C9, T-03, T-04 | Selesai |
| [#7](https://github.com/filbertengyo/tk_cipher/issues/7) | Padding PKCS#7 | modes | #2 | `padding.py` | FR-P1 sampai FR-P3, T-06, T-07 | Selesai |
| [#8](https://github.com/filbertengyo/tk_cipher/issues/8) | Mode operasi ECB, CBC, CFB, OFB, CTR | modes | #6 | `modes.py`, `Mode` enum | FR-M1 sampai FR-M6, T-08 sampai T-10 | Selesai |
| [#9](https://github.com/filbertengyo/tk_cipher/issues/9) | KDF dan CMAC-TK + constant-time compare | integrity | #6 | `kdf.py`, `mac.py` | FR-I1 sampai FR-I5, T-11 sampai T-13 | Selesai |
| [#10](https://github.com/filbertengyo/tk_cipher/issues/10) | Format file ciphertext dengan verify-then-decrypt | program | #7, #8, #9 | `fileformat.py`, header, verify-then-decrypt, tulis atomik | FR-F1 sampai FR-F7 | Selesai |
| [#11](https://github.com/filbertengyo/tk_cipher/issues/11) | CLI enc, dec, keygen | program | #10 | `cli.py`, `__main__.py`, entry point, exit code | FR-U1 sampai FR-U7, T-18 | Selesai |
| [#12](https://github.com/filbertengyo/tk_cipher/issues/12) | Sample data kecil, sedang, besar | testing, bonus | #2 | isi `tests/data/` + `make_large.py` | Bagian 6 | Selesai |
| [#13](https://github.com/filbertengyo/tk_cipher/issues/13) | Integration test dan run manual di Linux dan Windows | testing, bonus | #11, #12 | integration test, CI Linux dan Windows | T-14 sampai T-17, T-19, NFR-9 | Selesai |
| [#14](https://github.com/filbertengyo/tk_cipher/issues/14) | Analisis avalanche plaintext dan key | analysis | #8, #10 | `analysis/avalanche.py` | A-01, A-02 | Selesai |
| [#15](https://github.com/filbertengyo/tk_cipher/issues/15) | Round diffusion dan konfirmasi 16 ronde | analysis | #6 | `analysis/round_diffusion.py`, justifikasi 16 ronde di docs | A-03 | Selesai |
| [#16](https://github.com/filbertengyo/tk_cipher/issues/16) | Analisis entropi dan chi-square | analysis, bonus | #10, #12 | `analysis/entropy.py` | A-04, A-06 | Selesai |
| [#17](https://github.com/filbertengyo/tk_cipher/issues/17) | Histogram dan visual ECB | analysis | #10, #12 | `analysis/histogram.py` | A-05 | Selesai |
| [#18](https://github.com/filbertengyo/tk_cipher/issues/18) | Statistik S-box dan review threshold | analysis, bonus | #3 | `analysis/sbox_stats.py`, review threshold | A-07 | Selesai |
| [#19](https://github.com/filbertengyo/tk_cipher/issues/19) | Benchmark file kecil, sedang, besar | analysis, bonus | #11, #12 | `analysis/benchmark.py` | A-08, FR-K6, NFR-3 | Selesai |
| [#20](https://github.com/filbertengyo/tk_cipher/issues/20) | API docs pakai pdoc di GitHub Pages | docs, bonus | #11 | docstring, pdoc, `docs/api/` di GitHub Pages | FR-D1 sampai FR-D3 | Selesai |
| [#21](https://github.com/filbertengyo/tk_cipher/issues/21) | Executable Linux dan Windows | release, bonus | #11 | PyInstaller, Windows dibangun lewat workflow `build-exe` | FR-D4, NFR-8 | Selesai |
| [#22](https://github.com/filbertengyo/tk_cipher/issues/22) | README | docs | #11, #20, #21 | `README.md` | Bagian 9 | Selesai |
| [#23](https://github.com/filbertengyo/tk_cipher/issues/23) | Draft laporan Bab 3 sampai 9 | docs | #13, #14, #15, #16, #17, #18, #19, #27 | `docs/draft_laporan.md`, export diagram PNG | Bagian 9 | Open |
| [#24](https://github.com/filbertengyo/tk_cipher/issues/24) | Video demo | release, bonus, manual | #13, #14, #15, #16, #17, #18, #19, #27 | rekam demo, link di laporan | FR-D5 | Closed (dibatalkan) |
| [#25](https://github.com/filbertengyo/tk_cipher/issues/25) | Release GitHub dan submit Google Form | release | #13, #14, #15, #16, #17, #18, #19, #20, #21, #22, #23, #24, #26, #27 | tag, release, executable, Google Form | Bagian 12 | Open |
| [#26](https://github.com/filbertengyo/tk_cipher/issues/26) | End-to-end test lewat CLI dan executable | testing | #11, #12, #21 | `tests/e2e/run_e2e.py` untuk python dan executable | T-20 | Selesai |
| [#27](https://github.com/filbertengyo/tk_cipher/issues/27) | Verifikasi final dan sinkron docs sebelum laporan | testing, docs | #13, #14, #15, #16, #17, #18, #19, #20, #21, #22, #26 | fresh run 2 OS, `analysis/run_all.py`, sinkron docs, cek DoD | Bagian 12 kecuali laporan dan video | Selesai |

Urutan kritis: #2 => #3/#4 => #5 => #6 => #8/#9 => #10 => #11 => #21 => #26 => #27 => #23 => #25. Begitu #27 selesai, development udah tutup dan yang tersisa cuma laporan (#23) dan release (#25). Video (#24) dibatalkan.
