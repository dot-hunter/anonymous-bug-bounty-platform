#!/usr/bin/env python3
"""search_payloads.py — CLI search over the RAG/knowledge index.

Usage:
    python3 tools/rag-builder/search_payloads.py --class xss --query dompurify
    python3 tools/rag-builder/search_payloads.py --class ssrf --top 5
    python3 tools/rag-builder/search_payloads.py --query "laravel idor"
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent.parent / "rag-index.db"


def search(db_path: Path, vuln_class: str | None, query: str, top: int) -> list[tuple]:
    if not db_path.exists():
        print(f"[!] index not found: {db_path} — run tools/rag-builder/build.py first")
        sys.exit(1)

    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row

    params: list = []
    where = ""
    if vuln_class:
        where = " WHERE d.vuln_class = ?"

    # Term frequency overlap scoring
    terms = {t for t in query.lower().split() if len(t) > 2}
    if terms:
        join = ""
        score_expr = "0"
        for i, t in enumerate(terms):
            alias = f"k{i}"
            join += f" JOIN keywords {alias} ON {alias}.doc_id = d.id AND {alias}.term = ?"
            params.append(t)
            score_expr = f"({score_expr} + 1)"
        # WHERE placeholder comes after JOIN placeholders in SQL text → append class param last
        if vuln_class:
            params.append(vuln_class.lower())
        sql = (
            f"SELECT d.title, d.url, d.vuln_class, {score_expr} AS hits "
            f"FROM documents d {join} {where} "
            f"ORDER BY hits DESC LIMIT ?"
        )
    else:
        if vuln_class:
            params.append(vuln_class.lower())
        sql = (
            f"SELECT d.title, d.url, d.vuln_class, 1 AS hits "
            f"FROM documents d {where} "
            f"ORDER BY d.id LIMIT ?"
        )
    params.append(top)
    return db.execute(sql, params).fetchall()


def main() -> None:
    ap = argparse.ArgumentParser(description="Search payload/writeup index")
    ap.add_argument("--class", dest="vuln_class", help="filter by vuln class (xss, ssrf, idor, ...)")
    ap.add_argument("--query", default="", help="keyword query")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    args = ap.parse_args()

    rows = search(args.db, args.vuln_class, args.query, args.top)
    if not rows:
        print("[!] no matches")
        return
    for title, url, cls, hits in rows:
        print(f"[{cls}] ({hits} hits) {title}\n      {url}")


if __name__ == "__main__":
    main()