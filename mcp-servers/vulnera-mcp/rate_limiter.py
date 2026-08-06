#!/usr/bin/env python3
"""Rate Limiter — Adaptive rate limiting per target to prevent bans."""

from __future__ import annotations
import logging
import time
from collections import defaultdict
from urllib.parse import urlparse

logger = logging.getLogger("rate-limiter")


class AdaptiveRateLimiter:
    """Per-target adaptive rate limiter with automatic backoff."""

    def __init__(self, initial_rpm=30, min_rpm=5, max_rpm=60):
        self.initial_rpm = initial_rpm
        self.min_rpm = min_rpm
        self.max_rpm = max_rpm
        self.targets = defaultdict(lambda: {
            "rpm": initial_rpm,
            "requests": [],
            "consecutive_errors": 0,
            "last_request": 0,
        })
        self._global_delay = 0.1  # minimum inter-request delay

    def wait(self, url):
        """Block if needed to respect rate limit for this target."""
        host = self._get_host(url)
        target = self.targets[host]
        now = time.time()

        # Clean old entries (older than 60s)
        target["requests"] = [t for t in target["requests"] if now - t < 60]

        # Check if over limit
        if len(target["requests"]) >= target["rpm"]:
            sleep_time = 60 - (now - target["requests"][0]) + 0.1
            if sleep_time > 0:
                logger.info("Rate limit: sleeping %.1fs for %s (rpm=%d)", sleep_time, host, target["rpm"])
                time.sleep(sleep_time)

        # Minimum inter-request delay
        time_since_last = now - target["last_request"]
        if time_since_last < self._global_delay:
            time.sleep(self._global_delay - time_since_last)

        target["requests"].append(time.time())
        target["last_request"] = time.time()

    def report_success(self, url):
        """Report successful request — can increase rate."""
        host = self._get_host(url)
        target = self.targets[host]
        target["consecutive_errors"] = 0
        if target["rpm"] < self.max_rpm:
            target["rpm"] = min(target["rpm"] + 1, self.max_rpm)

    def report_rate_limited(self, url):
        """Report 429/403 — decrease rate."""
        host = self._get_host(url)
        target = self.targets[host]
        target["consecutive_errors"] += 1
        target["rpm"] = max(target["rpm"] - 5, self.min_rpm)
        logger.warning("Rate limited on %s — reduced to %d rpm (consecutive errors: %d)",
                       host, target["rpm"], target["consecutive_errors"])

    def report_error(self, url):
        """Report other error — slight decrease."""
        host = self._get_host(url)
        target = self.targets[host]
        target["consecutive_errors"] += 1
        target["rpm"] = max(target["rpm"] - 2, self.min_rpm)

    def _get_host(self, url):
        try:
            return urlparse(url).netloc or url
        except Exception:
            return url

    def get_stats(self):
        """Get current rate limiter stats."""
        return {
            host: {
                "rpm": data["rpm"],
                "requests_last_60s": len(data["requests"]),
                "consecutive_errors": data["consecutive_errors"],
            }
            for host, data in self.targets.items()
        }


# Global instance
limiter = AdaptiveRateLimiter()
