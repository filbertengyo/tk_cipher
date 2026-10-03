# Diagram 06: KDF dan MAC

Penjelasan: `docs/DESIGN.md` Bagian 8.

## KDF

Master key dipakai sebagai key TK-Cipher untuk mengenkripsi blok input yang berbeda (diberi label berbeda). Hasilnya menjadi dua key yang berbeda dan tidak saling berkaitan.

```mermaid
flowchart TD
    MK["Master key"] --> EM["TK-Cipher berkunci master key"]
    L1["Input berlabel 'enkripsi'"] --> EM
    L2["Input berlabel 'MAC'"] --> EM
    EM --> KENC["Key enkripsi"]
    EM --> KMAC["Key MAC"]
```

## MAC (CMAC dengan TK-Cipher)

```mermaid
flowchart TD
    KMAC["Key MAC"] --> SUB["Turunkan subkey CMAC"]
    MSG["Header + ciphertext"] --> SPLIT["Pecah per blok"]
    SPLIT --> LAST["Blok terakhir dicampur subkey"]
    SUB --> LAST
    LAST --> CHAIN["Enkripsi berantai seperti CBC<br/>memakai TK-Cipher berkunci key MAC"]
    CHAIN --> TAG["Tag"]
```

## Verifikasi saat dekripsi

```mermaid
flowchart TD
    FILE["Tag di file"] --> CMP{"Sama?<br/>constant-time compare"}
    CALC["Tag hasil hitung ulang"] --> CMP
    CMP -- ya --> GO["Lanjut dekripsi"]
    CMP -- tidak --> STOP["Berhenti, error autentikasi"]
```
