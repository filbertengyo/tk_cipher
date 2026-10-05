# Spec PyInstaller buat executable tk-cipher single file, jalankan: uv run pyinstaller tk-cipher.spec
import sys

name = "tk-cipher-windows" if sys.platform == "win32" else "tk-cipher-linux"

a = Analysis(
    ["src/tk_cipher/__main__.py"],
    pathex=["src"],
    excludes=["numpy", "matplotlib", "pytest"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name=name,
    console=True,
    upx=False,
)
