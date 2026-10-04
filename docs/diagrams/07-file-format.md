# Diagram 07: Format File Ciphertext

Penjelasan: `docs/DESIGN.md` Bagian 9. Ukuran dan posisi tiap field ada di `docs/blueprint.md`.

## Isi file

```mermaid
flowchart LR
    subgraph HEADER["Header"]
        MAGIC["magic"] --> VER["versi"] --> MODE["mode"] --> RES["reserved"] --> IV["IV / counter"] --> LEN["panjang asli"]
    end
    HEADER --> CT["Ciphertext"] --> TAG["Tag MAC"]
```

## Cakupan MAC

```mermaid
flowchart LR
    H["Header"] --> M["Input MAC"]
    C["Ciphertext"] --> M
    M --> T["Tag, disimpan di akhir file"]
```

Semua isi header ikut di-MAC, jadi perubahan mode, IV, atau panjang juga terdeteksi.

## Validasi saat dekripsi

```mermaid
flowchart TD
    A{"Ukuran file masuk akal?"} -- tidak --> F["Error: format tidak valid"]
    A -- ya --> B{"Magic dan versi dikenali?"}
    B -- tidak --> F
    B -- ya --> C{"Mode valid?"}
    C -- tidak --> F
    C -- ya --> R{"Reserved bernilai nol?"}
    R -- tidak --> F
    R -- ya --> D["Lanjut ke verifikasi MAC"]
```
