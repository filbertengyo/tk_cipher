# Diagram 05: Mode Operasi

Penjelasan: `docs/DESIGN.md` Bagian 6. Rumus tiap mode ada di catatan di bawah diagramnya. `E` = enkripsi blok TK-Cipher berkunci key enkripsi, `D` = dekripsi blok. Indeks blok mulai dari 0.

## ECB

```mermaid
flowchart TD
    P0["P0"] --> E0["E"] --> C0["C0"]
    P1["P1"] --> E1["E"] --> C1["C1"]
    P2["P2"] --> E2["E"] --> C2["C2"]
```

## CBC (enkripsi)

```mermaid
flowchart TD
    IV["IV"] --> X0(("XOR"))
    P0["P0"] --> X0 --> E0["E"] --> C0["C0"]
    C0 --> X1(("XOR"))
    P1["P1"] --> X1 --> E1["E"] --> C1["C1"]
    C1 --> X2(("XOR"))
    P2["P2"] --> X2 --> E2["E"] --> C2["C2"]
```

Dekripsi: `P_i = D(C_i) XOR C_(i-1)`, dengan `C_(-1) = IV`.

## CFB

```mermaid
flowchart TD
    IV["IV"] --> E0["E"] --> X0(("XOR"))
    P0["P0"] --> X0 --> C0["C0"]
    C0 --> E1["E"] --> X1(("XOR"))
    P1["P1"] --> X1 --> C1["C1"]
    C1 --> E2["E"] --> X2(("XOR"))
    P2["P2"] --> X2 --> C2["C2"]
```

Dekripsi: `P_i = C_i XOR E(C_(i-1))`. Hanya memakai `E`.

## OFB

```mermaid
flowchart TD
    IV["IV"] --> E0["E"] --> O0["O0"]
    O0 --> X0(("XOR"))
    P0["P0"] --> X0 --> C0["C0"]
    O0 --> E1["E"] --> O1["O1"]
    O1 --> X1(("XOR"))
    P1["P1"] --> X1 --> C1["C1"]
    O1 --> E2["E"] --> O2["O2"]
    O2 --> X2(("XOR"))
    P2["P2"] --> X2 --> C2["C2"]
```

Dekripsi sama persis, karena keystream tidak bergantung pada plaintext.

## CTR

```mermaid
flowchart TD
    CT0["CTR_0 (counter awal)"] --> E0["E"] --> X0(("XOR"))
    P0["P0"] --> X0 --> C0["C0"]
    CT1["CTR_0 + 1"] --> E1["E"] --> X1(("XOR"))
    P1["P1"] --> X1 --> C1["C1"]
    CT2["CTR_0 + 2"] --> E2["E"] --> X2(("XOR"))
    P2["P2"] --> X2 --> C2["C2"]
```

Dekripsi sama persis. Counter adalah integer 128-bit, bertambah mod 2^128.
