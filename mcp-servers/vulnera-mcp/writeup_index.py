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
    """Seed the database with baseline technique summaries (idempotent, merges missing entries)."""
    init_db()
    conn = sqlite3.connect(str(DB_FILE))

    # Check if already seeded
    count = conn.execute("SELECT COUNT(*) FROM writeups").fetchone()[0]
    seed_had = count > 0

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

        # GraphQL
        ("graphql", "introspection_enabled", "GraphQL", "query { __schema { types { name } } }", "https://hackerone.com/reports/121212", 1500, 2025, "Introspection enabled exposes full schema"),
        ("graphql", "aliasing_idor", "GraphQL", "Aliased queries enumerate objects", "https://hackerone.com/reports/131313", 4000, 2024, "Field aliases used to access other users' objects in a single query"),
        ("graphql", "batching_dos", "GraphQL", "Hundreds of batched queries", "https://hackerone.com/reports/141414", 2000, 2025, "No query batching limit allows resource exhaustion"),
        ("graphql", "depth_attack", "GraphQL", "Deep nested queries crash backend", "https://hackerone.com/reports/151515", 1000, 2024, "No depth limit on nested query resolution"),

        # SSTI
        ("ssti", "jinja2_rce", "Web App", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "https://hackerone.com/reports/161616", 10000, 2025, "Jinja2 SSTI in email template name parameter"),
        ("ssti", "twig_filter_exec", "Web App", "{{_self.env.registerUndefinedFilterCallback('exec')}}", "https://hackerone.com/reports/171717", 8000, 2024, "Twig SSTI via filter callback registration"),
        ("ssti", "freemarker_exec", "Web App", "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "https://hackerone.com/reports/181818", 9000, 2024, "Freemarker SSTI in PDF template rendering"),

        # RCE
        ("rce", "command_injection_ping", "Web App", "; id || ping -c 1 $(id)", "https://hackerone.com/reports/191919", 15000, 2025, "Ping parameter command injection with OOB exfil"),
        ("rce", "pickle_deserialization", "Python App", "pickle.loads on base64 user data", "https://hackerone.com/reports/202021", 20000, 2024, "Base64 cookie decoded and pickle.loads'd - RCE"),
        ("rce", "java_gadget_chain", "Java App", "ysoserial CommonsCollections", "https://hackerone.com/reports/222222", 25000, 2025, "Java ObjectInputStream with CommonsCollections gadget"),
        ("rce", "php_unserialize", "PHP App", "O:8:StdClass:0:{} serialized payload", "https://hackerone.com/reports/232323", 12000, 2024, "PHPGGC gadget chain in cookie parameter"),
        ("rce", "jenkins_script_console", "CI/CD", "Script console Groovy execution", "https://hackerone.com/reports/242424", 18000, 2024, "Exposed Jenkins script console allows arbitrary Groovy"),

        # JWT
        ("jwt", "alg_none", "API", "alg:none header bypass", "https://hackerone.com/reports/252525", 3000, 2025, "Server accepts alg:none JWT and trusts unsigned payload"),
        ("jwt", "rs256_hs256", "API", "RS256->HS256 confusion", "https://hackerone.com/reports/262626", 5000, 2024, "Public key used as HMAC secret to forge tokens"),
        ("jwt", "kid_injection", "API", "kid pointing to attacker file", "https://hackerone.com/reports/272727", 7000, 2025, "kid header injects arbitrary file path as signing key"),
        ("jwt", "weak_secret", "API", "Hashcat crack of weak HMAC secret", "https://hackerone.com/reports/282828", 2500, 2024, "Weak JWT signing secret cracked in seconds"),

        # File Upload
        ("file_upload", "svg_xss", "Web App", "SVG with embedded script", "https://hackerone.com/reports/292929", 2000, 2025, "SVG upload rendered inline executes JS"),
        ("file_upload", "polyglot_php", "Web App", "GIF89a;<?php system($_GET['c']);", "https://hackerone.com/reports/303031", 10000, 2024, "Polyglot image with PHP backdoor executes"),
        ("file_upload", "path_traversal_name", "Web App", "filename=../../shell.php", "https://hackerone.com/reports/313131", 8000, 2025, "Upload filename traverses to webroot"),

        # Race Condition
        ("race", "coupon_reuse", "E-commerce", "50 parallel coupon redemptions", "https://hackerone.com/reports/323232", 5000, 2025, "Coupon redemption race enables unlimited reuse"),
        ("race", "balance_double_spend", "Fintech", "Parallel withdraw requests", "https://hackerone.com/reports/333333", 12000, 2024, "Withdraw race condition doubles balance"),
        ("race", "email_verify_race", "Web App", "Parallel email verification", "https://hackerone.com/reports/343434", 4000, 2025, "Email verification token reusable via race"),

        # LFI
        ("lfi", "php_filter", "PHP App", "php://filter/convert.base64-encode", "https://hackerone.com/reports/353535", 6000, 2025, "php://filter reads source code via LFI"),
        ("lfi", "null_byte", "PHP App", "%00.png path truncation", "https://hackerone.com/reports/363636", 3000, 2024, "Null byte truncates extension check"),
        ("lfi", "log_poisoning", "PHP App", "User-Agent log injection + include", "https://hackerone.com/reports/373737", 15000, 2025, "LFI + log poisoning achieves RCE"),

        # Prototype Pollution
        ("prototype_pollution", "json_merge", "Node.js", '{"__proto__":{"polluted":true}}', "https://hackerone.com/reports/383838", 5000, 2025, "JSON body merges into Object prototype via vulnerable merge"),
        ("prototype_pollution", "query_merge", "Node.js", "__proto__[isAdmin]=true", "https://hackerone.com/reports/393939", 4500, 2024, "Query params merged via defaults-deep => prototype pollution"),
        ("prototype_pollution", "pp_to_rce", "Node.js", "execArgv pollution", "https://hackerone.com/reports/404041", 20000, 2025, "Prototype pollution escalates to RCE via child_process options"),

        # NoSQLi
        ("nosqli", "mongo_ne", "NoSQL", '{"username":{"$ne":"admin"},"password":{"$ne":"x"}}', "https://hackerone.com/reports/414141", 4000, 2025, "MongoDB $ne operator bypasses authentication"),
        ("nosqli", "mongo_regex", "NoSQL", '{"username":{"$regex":".*"}}', "https://hackerone.com/reports/424242", 3500, 2024, "MongoDB regex injection extracts data"),
    ]

    now = datetime.utcnow().isoformat()
    inserted = 0
    for item in seed_data:
        # Insert only records that do not already exist (keyed by vuln_class + technique)
        exists = conn.execute(
            "SELECT 1 FROM writeups WHERE vuln_class = ? AND technique = ? LIMIT 1",
            (item[0], item[1]),
        ).fetchone()
        if exists:
            continue
        conn.execute("""
            INSERT INTO writeups (vuln_class, technique, target_type, payload_hint, source_url, bounty_paid, year, summary, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (*item, now))
        inserted += 1

    conn.commit()
    conn.close()
    return {"seeded": True, "count": inserted, "existing": seed_had, "total": count + inserted}


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
