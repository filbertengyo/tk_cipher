"""Build API docs pakai pdoc ke docs/api lalu buang comment bawaan pdoc di HTML dan search.js"""

import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "api"
STYLE = re.compile(r"(<style[^>]*>)(.*?)(</style>)", re.DOTALL)
CSS_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
JS_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def strip_comments(html: str) -> str:
    """Hapus comment CSS di dalam style dan comment HTML biasa"""
    html = STYLE.sub(
        lambda m: m.group(1) + CSS_COMMENT.sub("", m.group(2)) + m.group(3), html
    )
    return HTML_COMMENT.sub("", html)


def main() -> int:
    shutil.rmtree(OUT, ignore_errors=True)
    cmd = [
        sys.executable,
        "-m",
        "pdoc",
        "--docformat",
        "google",
        "--footer-text",
        "TK-Cipher 0.1.0",
        "-o",
        str(OUT),
        "tk_cipher",
    ]
    if subprocess.run(cmd, cwd=ROOT, check=False).returncode != 0:
        return 1
    for page in OUT.rglob("*.html"):
        page.write_text(
            strip_comments(page.read_text(encoding="utf-8")), encoding="utf-8"
        )
    search = OUT / "search.js"
    search.write_text(
        JS_COMMENT.sub("", search.read_text(encoding="utf-8")), encoding="utf-8"
    )
    print(f"API docs di {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
