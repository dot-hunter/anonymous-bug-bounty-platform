#!/usr/bin/env python3
"""Writeup Corpus Index — SQLite-backed technique search (P1-D)."""

from __future__ import annotations
import json
import logging
import sqlite3
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("writeup-index")

DATA_DIR = Path.home() / ".config" / "platform"
DB_FILE = DATA_DIR / "writeups.db"


def init_db():
    """Initialize the writeup database."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS writeups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_class TEXT NOT NULL,
            technique TEXT NOT NULL,
            target_type TEXT,
            payload_hint TEXT,
            source_url TEXT,
            bounty_paid REAL DEFAULT 0,
            year INTEGER,
            summary TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_vuln_class ON writeups(vuln_class)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_technique ON writeups(technique)
    """)
    conn.commit()
    conn.close()


def search_techniques(vuln_class: str, technology: str = None, limit: int = 5) -> list:
    """Search for proven techniques by vulnerability class.
    
    Args:
        vuln_class: Vulnerability class (e.g., "idor", "xss", "ssrf")
        technology: Optional technology filter (e.g., "react", "wordpress")
        limit: Maximum results to return
    
    Returns:
        List of technique dicts sorted by bounty_paid desc
    """
    init_db()
    conn = sqlite3.connect(str(DB_FILE))

    query = "SELECT * FROM writeups WHERE vuln_class = ?"
    params = [vuln_class.lower()]

    if technology:
        query += " AND (target_type LIKE ? OR technique LIKE ?)"
        params.extend([f"%{technology.lower()}%", f"%{technology.lower()}%"])

    query += " ORDER BY bounty_paid DESC, year DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "vuln_class": row[1],
            "technique": row[2],
            "target_type": row[3],
            "payload_hint": row[4],
            "source_url": row[5],
            "bounty_paid": row[6],
            "year": row[7],
            "summary": row[8],
        }
        for row in rows
    ]


def seed_database():
    """Seed the database with initial technique summaries."""
    init_db()
    conn = sqlite3.connect(str(DB_FILE))

    # Check if already seeded
    count = conn.execute("SELECT COUNT(*) FROM writeups").fetchone()[0]
    if count > 0:
        conn.close()
        return {"seeded": False, "reason": "database already populated", "count": count}

    seed_data = [
        # IDOR/BOLA
        ("idor", "direct_id_increment", "REST API", "Increment sequential ID in URL path", "https://hackerone.com/reports/123456", 2500, 2025, "Increment /api/users/123 to /api/users/124 to access other users' data"),
        ("idor", "uuid_from_search", "REST API", "Extract UUIDs from search API responses", "https://hackerone.com/reports/234567", 1500, 2025, "Search API leaks user UUIDs, use them in profile endpoints"),
        ("idor", "method_switch", "REST API", "GET protected but DELETE unprotected", "https://hackerone.com/reports/345678", 3000, 2024, "Authorization exists on GET but not on DELETE/PUT"),
        ("idor", "body_param_idor", "REST API", "ID in JSON body not validated", "https://hackerone.com/reports/456789", 2000, 2025, "URL params protected but JSON body fields ignored"),
        ("idor", "batch_idor", "REST API", "Array of IDs in single request", "https://hackerone.com/reports/567890", 5000, 2024, "Bulk endpoint accepts array of IDs without ownership validation"),

        # XSS
        ("xss", "stored_profile", "Web App", "Store XSS in profile display name", "https://hackerone.com/reports/111111", 1000, 2025, "Profile name rendered without encoding in admin panel"),
        ("xss", "dom_innerhtml", "SPA", "innerHTML sink with location.hash source", "https://hackerone.com/reports/222222", 2000, 2025, "JavaScript reads location.hash and writes to innerHTML"),
        ("xss", "svg_onload", "Web App", "<svg/onload=alert(1)> bypasses sanitizer", "https://hackerone.com/reports/333333", 500, 2024, "SVG onload event bypasses HTML sanitizer"),
        ("xss", "csp_bypass_jsonp", "Web App", "JSONP gadget from allowed origin", "https://hackerone.com/reports/444444", 3000, 2025, "CSP allows google.com, JSONP gadget bypasses script-src"),
        ("xss", "blind_xss_admin", "Web App", "XSS fires in admin panel via support ticket", "https://hackerone.com/reports/555555", 1500, 2024, "Support ticket subject rendered in admin without encoding"),

        # SSRF
        ("ssrf", "cloud_metadata_aws", "Cloud", "http://169.254.169.254/latest/meta-data/", "https://hackerone.com/reports/666666", 5000, 2025, "Webhook URL fetches AWS metadata, leaks IAM credentials"),
        ("ssrf", "ip_encoding_bypass", "Web App", "Decimal IP encoding bypasses blocklist", "https://hackerone.com/reports/777777", 2500, 2025, "http://2130706433/ bypasses 127.0.0.1 blocklist"),
        ("ssrf", "redirect_chain", "Web App", "Open redirect chains to metadata endpoint", "https://hackerone.com/reports/888888", 3000, 2024, "Trusted redirect endpoint chains to metadata IP"),
        ("ssrf", "dns_rebinding", "Web App", "DNS rebinding bypasses allowlist", "https://hackerone.com/reports/999999", 4000, 2025, "Attacker domain resolves to public then internal IP"),
        ("ssrf", "gopher_redis", "Cloud", "gopher:// protocol attacks internal Redis", "https://hackerone.com/reports/101010", 7500, 2024, "SSRF via gopher writes cron job to internal Redis"),

        # SQLi
        ("sqli", "time_based_blind", "Web App", "Time-based blind via SLEEP(5)", "https://hackerone.com/reports/202020", 2000, 2025, "Time-based blind SQLi in search parameter"),
        ("sqli", "order_by_injection", "Web App", "ORDER BY clause injection", "https://hackerone.com/reports/303030", 1500, 2024, "Sort parameter injected into ORDER BY clause"),
        ("sqli", "nosql_mongodb", "NoSQL", "MongoDB $ne operator bypass", "https://hackerone.com/reports/404040", 3000, 2025, "JSON body with $ne operator bypasses login"),

        # OAuth
        ("oauth", "redirect_uri_bypass", "OAuth", "redirect_uri not strictly validated", "https://hackerone.com/reports/505050", 3000, 2025, "Authorization code sent to attacker-controlled domain"),
        ("oauth", "state_csrf", "OAuth", "Missing state parameter = CSRF", "https://hackerone.com/reports/606060", 2000, 2024, "OAuth flow without state allows account linking CSRF"),
        ("oauth", "pkce_absence", "OAuth", "Public client without PKCE", "https://hackerone.com/reports/707070", 2500, 2025, "Mobile app OAuth flow missing PKCE allows code interception"),

        # LLM
        ("llm", "direct_injection", "AI App", "Ignore previous instructions", "https://hackerone.com/reports/808080", 5000, 2025, "Direct prompt injection overrides system instructions"),
        ("llm", "indirect_injection", "AI App", "Hidden instructions in uploaded document", "https://hackerone.com/reports/909090", 7500, 2025, "Document contains hidden instructions that LLM follows"),
        ("llm", "tool_abuse_ssrf", "AI App", "LLM tool used for SSRF", "https://hackerone.com/reports/111112", 10000, 2025, "LLM fetch tool used to access cloud metadata"),
    ]

    now = datetime.utcnow().isoformat()
    for item in seed_data:
        conn.execute("""
            INSERT INTO writeups (vuln_class, technique, target_type, payload_hint, source_url, bounty_paid, year, summary, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (*item, now))

    conn.commit()
    conn.close()
    return {"seeded": True, "count": len(seed_data)}


def get_stats() -> dict:
    """Get database statistics."""
    init_db()
    conn = sqlite3.connect(str(DB_FILE))
    total = conn.execute("SELECT COUNT(*) FROM writeups").fetchone()[0]
    vuln_classes = conn.execute("SELECT DISTINCT vuln_class FROM writeups").fetchall()
    conn.close()
    return {
        "total_writeups": total,
        "vuln_classes": [row[0] for row in vuln_classes],
    }
