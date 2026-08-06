#!/usr/bin/env python3
"""OPSEC Toolkit — VPN rotation, traffic shaping, identity management for anonymous hunting."""

from __future__ import annotations
import json
import logging
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger("opsec")

DATA_DIR = Path.home() / ".config" / "opsec"
DATA_DIR.mkdir(parents=True, exist_ok=True)


class VPNManager:
    """VPN rotation using WireGuard."""

    def __init__(self, config_dir=None):
        self.config_dir = Path(config_dir or DATA_DIR / "vpn_configs")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.interface = "wg0"

    def list_servers(self):
        """List available VPN server configs."""
        configs = []
        for cfg in self.config_dir.glob("*.conf"):
            configs.append({
                "name": cfg.stem,
                "path": str(cfg),
            })
        return configs

    def connect(self, server_name):
        """Connect to a VPN server."""
        config_path = self.config_dir / f"{server_name}.conf"
        if not config_path.exists():
            return {"error": f"Config not found: {config_path}"}

        # Disconnect existing
        self.disconnect()

        rc, stdout, stderr = self._run(
            ["wg-quick", "up", str(config_path)],
            timeout=15,
        )
        if rc == 0:
            return {"connected": True, "server": server_name}
        return {"connected": False, "error": stderr[:500]}

    def disconnect(self):
        """Disconnect current VPN."""
        self._run(["wg-quick", "down", self.interface], timeout=10)
        return {"disconnected": True}

    def rotate(self):
        """Rotate to a random VPN server."""
        servers = self.list_servers()
        if not servers:
            return {"error": "No VPN configs found", "hint": f"Add .conf files to {self.config_dir}"}

        server = random.choice(servers)
        result = self.connect(server["name"])
        result["rotated_from"] = self.get_current()
        return result

    def get_current(self):
        """Get current VPN connection info."""
        rc, stdout, _ = self._run(["wg", "show", self.interface], timeout=5)
        if rc == 0:
            return {"connected": True, "info": stdout[:500]}
        return {"connected": False}

    def status(self):
        """Get full VPN status."""
        current = self.get_current()
        servers = self.list_servers()
        return {
            "connected": current.get("connected", False),
            "current": current,
            "available_servers": len(servers),
            "servers": servers,
        }

    def _run(self, cmd, timeout=10):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return proc.returncode, proc.stdout, proc.stderr
        except Exception as exc:
            return -1, "", str(exc)


class TrafficShaper:
    """Request traffic shaping for anti-detection."""

    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
        ]
        self.accept_languages = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
        ]

    def get_random_headers(self):
        """Get randomized browser headers."""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept-Language": random.choice(self.accept_languages),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
        }

    def get_delay(self, base_delay=1.0, jitter=0.5):
        """Get randomized delay with Gaussian distribution."""
        return max(0.1, base_delay + random.gauss(0, jitter))


class IdentityManager:
    """Burner identity management for anonymous testing."""

    def __init__(self):
        self.identities_file = DATA_DIR / "identities.json"
        self.identities = self._load()

    def _load(self):
        if self.identities_file.exists():
            try:
                return json.loads(self.identities_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {"identities": [], "active": None}

    def _save(self):
        self.identities_file.write_text(json.dumps(self.identities, indent=2))

    def list_identities(self):
        return self.identities.get("identities", [])

    def get_active(self):
        active_id = self.identities.get("active")
        if active_id:
            for ident in self.identities.get("identities", []):
                if ident.get("id") == active_id:
                    return ident
        return None

    def rotate_identity(self):
        """Switch to a different identity."""
        identities = self.identities.get("identities", [])
        if len(identities) < 2:
            return {"error": "Need at least 2 identities to rotate"}

        current = self.identities.get("active")
        others = [i for i in identities if i.get("id") != current]
        if others:
            new_identity = random.choice(others)
            self.identities["active"] = new_identity["id"]
            self._save()
            return {"rotated_to": new_identity["id"], "platform": new_identity.get("platform")}
        return {"error": "No other identities available"}


# Global instances
vpn = VPNManager()
shaper = TrafficShaper()
identity = IdentityManager()
