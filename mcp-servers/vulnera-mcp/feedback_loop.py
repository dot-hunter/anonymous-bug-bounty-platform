#!/usr/bin/env python3
"""Submission Outcome Feedback Loop (P1-C)."""

from __future__ import annotations
import json
import logging
import sqlite3
import time
from pathlib import Path
from datetime import datetime
from typing import Any

logger = logging.getLogger("feedback-loop")

DATA_DIR = Path.home() / ".config" / "platform"
DB_FILE = DATA_DIR / "feedback.db"


def init_db():
    """Initialize the feedback database."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS outcomes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_class TEXT NOT NULL,
            technique TEXT NOT NULL,
            payload TEXT,
            platform TEXT NOT NULL,
            outcome TEXT NOT NULL,
            payout REAL DEFAULT 0,
            target TEXT,
            timestamp TEXT NOT NULL,
            notes TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS technique_weights (
            vuln_class TEXT NOT NULL,
            technique TEXT NOT NULL,
            platform TEXT NOT NULL,
            weight REAL DEFAULT 1.0,
            total_attempts INTEGER DEFAULT 0,
            total_bounties INTEGER DEFAULT 0,
            total_payout REAL DEFAULT 0,
            last_updated TEXT NOT NULL,
            PRIMARY KEY (vuln_class, technique, platform)
        )
    """)
    conn.commit()
    conn.close()


def record_outcome(vuln_class: str, technique: str, platform: str, outcome: str,
                   payout: float = 0, payload: str = None, target: str = None,
                   notes: str = None) -> dict:
    """Record submission outcome and update technique weights.
    
    Args:
        vuln_class: Vulnerability class (e.g., "idor", "xss", "ssrf")
        technique: Specific technique used (e.g., "direct_id_manipulation")
        platform: Bug bounty platform (e.g., "hackerone", "bugcrowd")
        outcome: One of "bounty", "duplicate", "informational", "na", "needs_more_info"
        payout: Bounty amount in USD (0 if not paid)
        payload: The payload that worked (optional)
        target: Target domain (optional)
        notes: Additional notes (optional)
    
    Returns:
        Dict with outcome record and updated weight
    """
    init_db()
    conn = sqlite3.connect(str(DB_FILE))
    timestamp = datetime.utcnow().isoformat()

    # Record the outcome
    conn.execute("""
        INSERT INTO outcomes (vuln_class, technique, payload, platform, outcome, payout, target, timestamp, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (vuln_class, technique, payload, platform, outcome, payout, target, timestamp, notes))

    # Update technique weight
    weight_delta = _calculate_weight_delta(outcome, payout)
    conn.execute("""
        INSERT INTO technique_weights (vuln_class, technique, platform, weight, total_attempts, total_bounties, total_payout, last_updated)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(vuln_class, technique, platform) DO UPDATE SET
            weight = weight + ?,
            total_attempts = total_attempts + 1,
            total_bounties = total_bounties + ?,
            total_payout = total_payout + ?,
            last_updated = ?
    """, (vuln_class, technique, platform, 1.0 + weight_delta, 1 if outcome == "bounty" else 0,
          payout, timestamp, weight_delta, 1 if outcome == "bounty" else 0, payout, timestamp))

    conn.commit()
    conn.close()

    return {
        "recorded": True,
        "vuln_class": vuln_class,
        "technique": technique,
        "outcome": outcome,
        "weight_delta": weight_delta,
    }


def _calculate_weight_delta(outcome: str, payout: float) -> float:
    """Calculate weight adjustment based on outcome."""
    if outcome == "bounty":
        # Bounty paid — boost weight significantly
        base = 0.3
        if payout > 0:
            # Additional boost for higher payouts (capped at 0.5)
            base += min(0.2, payout / 10000)
        return base
    elif outcome == "duplicate":
        # Duplicate — real issue but timing. Slight boost.
        return 0.05
    elif outcome == "needs_more_info":
        # Needs more info — partial success. Small boost.
        return 0.1
    elif outcome == "informational":
        # Informational — reduce weight
        return -0.15
    elif outcome == "na":
        # Not applicable — sharply reduce weight
        return -0.3
    return 0.0


def get_technique_weights(vuln_class: str = None, platform: str = None, limit: int = 20) -> list:
    """Get technique weights, optionally filtered."""
    init_db()
    conn = sqlite3.connect(str(DB_FILE))
    query = "SELECT * FROM technique_weights WHERE 1=1"
    params = []
    if vuln_class:
        query += " AND vuln_class = ?"
        params.append(vuln_class)
    if platform:
        query += " AND platform = ?"
        params.append(platform)
    query += " ORDER BY weight DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return [
        {
            "vuln_class": row[0],
            "technique": row[1],
            "platform": row[2],
            "weight": row[3],
            "total_attempts": row[4],
            "total_bounties": row[5],
            "total_payout": row[6],
            "last_updated": row[7],
        }
        for row in rows
    ]


def get_top_techniques(vuln_class: str, platform: str = None, limit: int = 5) -> list:
    """Get top techniques for a vulnerability class."""
    return get_technique_weights(vuln_class=vuln_class, platform=platform, limit=limit)
