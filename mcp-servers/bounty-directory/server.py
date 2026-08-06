#!/usr/bin/env python3
"""
Bounty Directory MCP Server — Program database for bug bounty hunters.
Provides tools to list, filter, rank, and get details on bug bounty programs.
Supports HackerOne, Bugcrowd, Immunefi, and independent programs.
"""

from __future__ import annotations
import json, logging, os, subprocess, sys, time
from pathlib import Path
from mcp.server import MCPServer
import sys, os
sys.path.insert(0, str(Path(__file__).resolve().parent))
from report_writer import generate_report, save_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", handlers=[logging.StreamHandler(sys.stderr)])
logger = logging.getLogger("bounty-directory")

DATA_DIR = Path.home() / ".config" / "vulnera-mcp"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROGRAMS_FILE = DATA_DIR / "programs.json"
CACHE_FILE = DATA_DIR / "programs_cache.json"

SAMPLE_PROGRAMS = [
    {"handle": "tinder", "name": "Tinder", "platform": "HackerOne", "base_bounty": "$250", "max_bounty": "$15,000", "url": "https://hackerone.com/tinder", "scope": ["mobile", "web"], "tags": ["dating", "mobile"]},
    {"handle": "uber", "name": "Uber", "platform": "HackerOne", "base_bounty": "$500", "max_bounty": "$50,000", "url": "https://hackerone.com/uber", "scope": ["web", "api", "mobile"], "tags": ["transport", "mobility"]},
    {"handle": "snapchat", "name": "Snapchat", "platform": "HackerOne", "base_bounty": "$250", "max_bounty": "$10,000", "url": "https://hackerone.com/snapchat", "scope": ["web", "mobile", "api"], "tags": ["social", "messaging"]},
    {"handle": "shopify", "name": "Shopify", "platform": "HackerOne", "base_bounty": "$500", "max_bounty": "$50,000", "url": "https://hackerone.com/shopify", "scope": ["web", "api", "mobile"], "tags": ["ecommerce"]},
    {"handle": "enter", "name": "Enter", "platform": "Bugcrowd", "base_bounty": "$250", "max_bounty": "$10,000", "url": "https://bugcrowd.com/enter", "scope": ["web", "api"], "tags": ["fintech"]},
    {"handle": "msdos", "name": "MS-DOS", "platform": "HackerOne", "base_bounty": "$500", "max_bounty": "$25,000", "url": "https://hackerone.com/msdos", "scope": ["web"], "tags": ["retro", "os"]},
    {"handle": "slack", "name": "Slack", "platform": "HackerOne", "base_bounty": "$500", "max_bounty": "$40,000", "url": "https://hackerone.com/slack", "scope": ["web", "api", "mobile"], "tags": ["communication", "productivity"]},
    {"handle": "phabricator", "name": "Phabricator", "platform": "HackerOne", "base_bounty": "$250", "max_bounty": "$10,000", "url": "https://hackerone.com/phabricator", "scope": ["web"], "tags": ["devtools"]},
    {"handle": "django", "name": "Django", "platform": "HackerOne", "base_bounty": "$500", "max_bounty": "$25,000", "url": "https://hackerone.com/django", "scope": ["web", "framework"], "tags": ["python", "framework", "oss"]},
    {"handle": "cloudflare", "name": "Cloudflare", "platform": "HackerOne", "base_bounty": "$500", "max_bounty": "$100,000", "url": "https://hackerone.com/cloudflare", "scope": ["web", "api", "network"], "tags": ["cdn", "security", "infrastructure"]},
]

class BountyDirectory:
    def __init__(self):
        self.programs = []
        self._load()

    def _load(self):
        if PROGRAMS_FILE.exists():
            try:
                self.programs = json.loads(PROGRAMS_FILE.read_text())
                return
            except (json.JSONDecodeError, OSError):
                pass
        self._generate_sample_programs()

    def _generate_sample_programs(self):
        self.programs = SAMPLE_PROGRAMS
        self._save()

    def _fetch_hackerone_programs(self):
        """Fetch live programs from HackerOne directory."""
        try:
            import urllib.request
            url = "https://api.hackerone.com/v1/programs?page[size]=100"
            # Use public program directory scraping as fallback
            pub_url = "https://hackerone.com/directory/programs?offers_bounties=true&view=all"
            req = urllib.request.Request(pub_url, headers={"User-Agent": "Mozilla/5.0"})
            # Note: HackerOne directory is JS-rendered; this is a best-effort approach
            return []
        except Exception:
            return []

    def _fetch_bugcrowd_programs(self):
        """Fetch live programs from Bugcrowd directory."""
        try:
            import urllib.request
            url = "https://bugcrowd.com/programs.json?sort[]=promoted-desc&hidden[]=false&page[]=1"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                programs = []
                for item in data.get("programs", []):
                    programs.append({
                        "handle": item.get("code", "").lower(),
                        "name": item.get("name", ""),
                        "platform": "Bugcrowd",
                        "base_bounty": f"${item.get('minimum_bounty', 0)}",
                        "max_bounty": f"${item.get('maximum_bounty', 0)}",
                        "url": f"https://bugcrowd.com/{item.get('code', '')}",
                        "scope": item.get("in_scope", []),
                        "tags": item.get("tags", []),
                    })
                return programs
        except Exception:
            return []

    def _save(self):
        try:
            PROGRAMS_FILE.write_text(json.dumps(self.programs, indent=2))
        except OSError:
            pass

    def _load_yaml(self, path):
        try:
            import yaml
            with open(path) as f:
                return yaml.safe_load(f)
        except (ImportError, OSError):
            return {}

    def list_programs(self, platform=None, min_bounty=None, max_results=None):
        results = self.programs
        if platform:
            results = [p for p in results if p.get("platform", "").lower() == platform.lower()]
        if min_bounty:
            results = [p for p in results if self._parse_bounty(p.get("base_bounty", "$0")) >= self._parse_bounty(min_bounty)]
        if max_results:
            results = results[:max_results]
        return results

    def get_program(self, handle):
        for p in self.programs:
            if p.get("handle", "").lower() == handle.lower():
                return p
        return None

    def rank_by_complexity_payout(self, top_n=10):
        ranked = sorted(self.programs, key=lambda p: self._parse_bounty(p.get("max_bounty", "$0")), reverse=True)
        return ranked[:top_n]

    def get_platforms(self):
        return list(set(p.get("platform", "Unknown") for p in self.programs))

    def get_stats(self):
        return {
            "total_programs": len(self.programs),
            "platforms": self.get_platforms(),
            "avg_bounty": self._avg_bounty(),
            "highest_bounty": max((self._parse_bounty(p.get("max_bounty", "$0")) for p in self.programs), default=0),
        }

    def _parse_bounty(self, bounty_str):
        if not bounty_str:
            return 0
        s = bounty_str.replace("$", "").replace(",", "").strip()
        try:
            return int(s)
        except ValueError:
            return 0

    def _avg_bounty(self):
        bounties = [self._parse_bounty(p.get("base_bounty", "$0")) for p in self.programs]
        return sum(bounties) / len(bounties) if bounties else 0

server = MCPServer(
    "bounty-directory",
    version="2026.1",
    description="Bug bounty program directory — list, filter, rank, and get details on HackerOne, Bugcrowd, Immunefi, and independent programs",
    instructions="You are a bug bounty program directory assistant. Use the available tools to list programs, filter by platform or bounty range, rank by complexity vs payout, and get detailed program information including scope and domains.",
)
directory = BountyDirectory()

@server.tool()
def list_programs(platform: str = None, min_bounty: str = None, max_results: int = 50) -> list:
    """List bug bounty programs with optional filtering."""
    return directory.list_programs(platform, min_bounty, max_results)

@server.tool()
def get_program(handle: str) -> dict:
    """Get detailed information about a specific program."""
    return directory.get_program(handle) or {"error": f"Program '{handle}' not found"}

@server.tool()
def rank(top_n: int = 10) -> list:
    """Rank programs by max bounty (highest first)."""
    return directory.rank_by_complexity_payout(top_n)

@server.tool()
def platforms() -> list:
    """List all available platforms."""
    return directory.get_platforms()

@server.tool()
def stats() -> dict:
    """Get directory statistics."""
    return directory.get_stats()

@server.tool()
def generate_bug_report(target: str, findings: list, format: str = "markdown") -> str:
    """Generate an AI-assisted bug bounty report from findings."""
    report = generate_report(findings, target, format)
    safe_target = target.replace(":", "_").replace("/", "_").replace(".", "_")
    path = save_report(report, f"report_{safe_target}_{int(time.time())}.md")
    return f"Report generated: {path}\\n{report[:2000]}"


if __name__ == "__main__":
    server.run(transport="stdio")
