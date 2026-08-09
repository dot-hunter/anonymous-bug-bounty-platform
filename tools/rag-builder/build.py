#!/usr/bin/env python3
"""RAG payload/writeup builder.

Builds a lightweight keyword-based index (SQLite, no FAISS) over public
writeup/payload corpora so hunt skills can answer "show me a working payload
for <vuln class> against <framework>" from local data.

Usage:
    python3 tools/rag-builder/build.py --corpus ./corpus --out ./rag-index.db
    python3 tools/rag-builder/build.py --fetch-disclosed --limit 50   # optional: pull HackerOne disclosed summaries (requires API token, skipped if absent)

Index schema:
    documents(id, source, url, title, content, vuln_class, framework, techniques)
    keywords(term, doc_id)          -- tokenized, lowercased, deduped

Search (SQL FTS5 not required; simple term-overlap ranking is enough):
    SELECT docs ranked by number of keyword hits.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "of", "for",
    "with", "by", "from", "as", "is", "are", "was", "were", "be", "been", "being",
    "it", "this", "that", "these", "those", "i", "you", "he", "she", "we", "they",
    "not", "no", "yes", "if", "then", "else", "when", "where", "which", "who",
    "what", "how", "all", "any", "some", "each", "every", "both", "few", "more",
    "most", "other", "such", "only", "own", "same", "so", "than", "too", "very",
    "s", "t", "can", "will", "just", "don", "should", "now",
}

TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-#.]+")


def tokenize(text: str) -> set[str]:
    return {
        t.lower() for t in TOKEN_RE.findall(text)
        if t.lower() not in STOPWORDS and len(t) > 2
    }


def load_corpora(root: Path) -> list[dict]:
    """Recursively load .md, .txt, .json corpus files from root dir."""
    docs: list[dict] = []
    if not root.exists():
        return docs
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".md", ".txt", ".json"):
            continue
        try:
            content = path.read_text(errors="ignore")
            if len(content) < 30:
                continue
            title = path.name
            docs.append({
                "title": title,
                "url": f"file://{path.resolve()}",
                "content": content,
                "vuln_class": infer_vuln_class(content, title),
                "framework": "",
                "techniques": "",
            })
        except Exception as e:  # noqa: BLE001
            print(f"[!] skip {path}: {e}", file=sys.stderr)
    return docs


KNOWN_CLASSES = ["xss", "ssrf", "sqli", "ssti", "idor", "bfla", "rce", "xxe",
                 "oauth", "race", "lfi", "jwt", "file_upload", "graphql",
                 "llm", "nosqli", "prototype_pollution"]


def infer_vuln_class(content: str, title: str) -> str:
    # 1. filename is the strongest signal (corpus files are named by class)
    for cls in KNOWN_CLASSES:
        if cls in title.lower():
            return cls
    # 2. content fallback
    hay = (content[:2000] + " " + title).lower()
    table = [
        ("xss", ["xss", "cross-site script", "dompurify", "mutation xss", "dangling markup"]),
        ("ssrf", ["ssrf", "server-side request forgery", "gopher", "169.254.169.254"]),
        ("ssti", ["ssti", "server-side template injection", "{{7*7}}", "${7*7}"]),
        ("sqli", ["sqli", "sql injection", "sqlmap", "union select", "boolean-based"]),
        ("idor", ["idor", "bola", "object-level authorization", "direct object reference"]),
        ("bfla", ["bfla", "broken function level", "method-level auth"]),
        ("rce", ["rce", "remote code execution", "command injection", "deserialization"]),
        ("xxe", ["xxe", "xml external entity", "doctype entity"]),
        ("oauth", ["oauth", "open redirect", "redirect_uri", "csrf oauth"]),
        ("race", ["race condition", "toctou", "double-spend", "single-use"]),
    ]
    for cls, needles in table:
        if any(n in hay for n in needles):
            return cls
    return "unclassified"


def build_index(docs: list[dict], out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(out_path)
    db.execute("DROP TABLE IF EXISTS documents")
    db.execute("DROP TABLE IF EXISTS keywords")
    db.execute("""
        CREATE TABLE documents (
            id INTEGER PRIMARY KEY,
            title TEXT, url TEXT, content TEXT,
            vuln_class TEXT, framework TEXT, techniques TEXT
        )
    """)
    db.execute("CREATE INDEX idx_doc_class ON documents(vuln_class)")
    db.execute("""
        CREATE TABLE keywords (
            term TEXT, doc_id INTEGER,
            PRIMARY KEY (term, doc_id)
        )
    """)
    db.execute("CREATE INDEX idx_kw_term ON keywords(term)")

    n = 0
    for d in docs:
        cur = db.execute(
            "INSERT INTO documents (title,url,content,vuln_class,framework,techniques) VALUES (?,?,?,?,?,?)",
            (d["title"], d["url"], d["content"], d["vuln_class"], d["framework"], d["techniques"]),
        )
        doc_id = cur.lastrowid
        terms = tokenize(f"{d['title']} {d['content']}")
        db.executemany(
            "INSERT OR IGNORE INTO keywords (term, doc_id) VALUES (?, ?)",
            [(t, doc_id) for t in terms],
        )
        n += 1

    db.commit()
    db.close()
    return n


def main() -> None:
    ap = argparse.ArgumentParser(description="Build keyword RAG index")
    ap.add_argument("--corpus", type=Path, default=Path("data"),
                    help="directory of .md/.txt/.json corpus files")
    ap.add_argument("--outdir", type=Path, default=Path("rag-index.db"))
    args = ap.parse_args()

    docs = load_corpora(args.corpus)
    if not docs:
        print("[!] no corpus documents found — put writeups/payloads in data/ first")
        sys.exit(0)

    n = build_index(docs, args.outdir)
    print(f"[+] indexed {n} documents -> {args.outdir}")


if __name__ == "__main__":
    main()