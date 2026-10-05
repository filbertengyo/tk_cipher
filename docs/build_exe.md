# Build executable

Executable single file dibangun pakai PyInstaller dari `tk-cipher.spec`. PyInstaller tidak bisa cross compile, jadi tiap OS harus dibangun di OS itu sendiri.

| OS      | Hasil                           |
| ------- | ------------------------------- |
| Linux   | `dist/tk-cipher-linux`          |
| Windows | `dist/tk-cipher-windows.exe`    |

## Build

Dari root repo:

```bash
uv sync --all-groups
uv run pyinstaller --noconfirm --clean tk-cipher.spec
```

Nama file otomatis dipilih dari OS yang dipakai. File kerja PyInstaller ada di `build/` dan tidak di-commit.

## Smoke test

Linux:

```bash
cd dist
./tk-cipher-linux keygen > key.txt
./tk-cipher-linux enc -i ../README.md -o cbc.enc --key-file key.txt -m cbc
./tk-cipher-linux dec -i cbc.enc -o cbc.out --key-file key.txt
cmp ../README.md cbc.out
./tk-cipher-linux enc -i ../README.md -o ctr.enc --key-file key.txt -m ctr
./tk-cipher-linux dec -i ctr.enc -o ctr.out --key-file key.txt
cmp ../README.md ctr.out
```

Windows (PowerShell):

```powershell
cd dist
.\tk-cipher-windows.exe keygen > key.txt
.\tk-cipher-windows.exe enc -i ..\README.md -o cbc.enc --key-file key.txt -m cbc
.\tk-cipher-windows.exe dec -i cbc.enc -o cbc.out --key-file key.txt
fc.exe /b ..\README.md cbc.out
.\tk-cipher-windows.exe enc -i ..\README.md -o ctr.enc --key-file key.txt -m ctr
.\tk-cipher-windows.exe dec -i ctr.enc -o ctr.out --key-file key.txt
fc.exe /b ..\README.md ctr.out
```

`cmp` dan `fc.exe /b` tidak mencetak perbedaan kalau file identik. Hapus file hasil smoke test sebelum commit, yang di-commit cuma executable.

## Catatan

Executable Linux memakai glibc dari mesin yang membangunnya, jadi bisa gagal di distro yang glibc-nya lebih tua. Kalau perlu jangkauan lebih luas, bangun di distro yang lebih lama.
