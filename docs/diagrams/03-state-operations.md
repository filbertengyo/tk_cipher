# Diagram 03: State dan Operasi di Dalam Ronde

Penjelasan: `docs/DESIGN.md` Bagian 2 dan 3.

## Layout state

Blok disusun baris demi baris menjadi matriks 4x4.

| baris \ kolom | 0   | 1   | 2   | 3   |
| ------------- | --- | --- | --- | --- |
| 0             | b0  | b1  | b2  | b3  |
| 1             | b4  | b5  | b6  | b7  |
| 2             | b8  | b9  | b10 | b11 |
| 3             | b12 | b13 | b14 | b15 |

## Arah kerja setiap operasi

```mermaid
flowchart LR
    ARK["AddRoundKey<br/>per byte"]
    DT["DiagonalTranspose<br/>seluruh matriks"]
    SUB["DynamicSub<br/>per byte"]
    ROT["RowRotator<br/>per baris"]
    CC["ColumnCascade<br/>per kolom"]
    ARK --> DT --> SUB --> ROT --> CC
```

## DiagonalTranspose

Byte di diagonal tetap di tempatnya. Byte lain bertukar dengan pasangannya di seberang diagonal.

```mermaid
flowchart LR
    b1["b1"] <--> b4["b4"]
    b2["b2"] <--> b8["b8"]
    b3["b3"] <--> b12["b12"]
    b6["b6"] <--> b9["b9"]
    b7["b7"] <--> b13["b13"]
    b11["b11"] <--> b14["b14"]
```

## RowRotator

Setiap baris diperlakukan sebagai satu deretan bit dan dirotasi. Jumlah rotasi berbeda untuk setiap baris, sehingga bit berpindah melewati batas byte.

```mermaid
flowchart LR
    R0["Baris 0"] --> O0["rotasi bit"]
    R1["Baris 1"] --> O1["rotasi bit, jumlah berbeda"]
    R2["Baris 2"] --> O2["rotasi bit, jumlah berbeda"]
    R3["Baris 3"] --> O3["rotasi bit, jumlah berbeda"]
```

## ColumnCascade (satu kolom)

Byte dalam satu kolom dijumlahkan berantai dari atas ke bawah, lalu byte paling bawah ditambahkan kembali ke byte paling atas. Inverse-nya pengurangan dengan urutan dibalik.

```mermaid
flowchart LR
    A["baris 0"] --> B["baris 1<br/>ditambah baris 0"]
    B --> C["baris 2<br/>ditambah baris 1"]
    C --> D["baris 3<br/>ditambah baris 2"]
    D --> A2["baris 0<br/>ditambah baris 3"]
```
