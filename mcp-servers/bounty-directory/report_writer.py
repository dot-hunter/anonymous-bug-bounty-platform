#!/usr/bin/env python3
"""
AI-Assisted Bug Bounty Report Writer — 2026 Edition.
Generates submission-ready bug bounty reports with AI-assisted writing.
"""

from __future__ import annotations
import json, time
from pathlib import Path

REPORT_DIR = Path.home() / ".config" / "vulnera-mcp" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

def generate_report(findings: list, target: str, format: str = "markdown") -> str:
    """Generate a bug bounty report from findings."""
    if format == "markdown":
        return _generate_markdown_report(findings, target)
    elif format == "json":
        return _generate_json_report(findings, target)
    else:
        return _generate_markdown_report(findings, target)

def _generate_markdown_report(findings: list, target: str) -> str:
    """Generate a markdown bug bounty report."""
    lines = [
        f"# Bug Bounty Report — {target}",
        f"",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Target:** {target}",
        f"**Total Findings:** {len(findings)}",
        f"",
    ]
    
    # Group by severity
    by_severity = {}
    for f in findings:
        sev = f.get("severity", "medium")
        by_severity.setdefault(sev, []).append(f)
    
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_severity:
            lines.append(f"## {sev.upper()} Severity Findings ({len(by_severity[sev])})")
            lines.append("")
            for i, finding in enumerate(by_severity[sev], 1):
                lines.append(f"### {i}. {finding.get('title', 'Untitled')}")
                lines.append("")
                lines.append(f"**Type:** {finding.get('type', 'unknown')}")
                lines.append(f"**Severity:** {finding.get('severity', 'unknown')}")
                lines.append(f"**URL:** {finding.get('url', 'N/A')}")
                lines.append("")
                lines.append(f"**Description:**")
                lines.append(finding.get('description', 'No description provided.'))
                lines.append("")
                if finding.get('poc'):
                    lines.append(f"**Proof of Concept:**")
                    lines.append("```")
                    lines.append(finding['poc'])
                    lines.append("```")
                    lines.append("")
                if finding.get('impact'):
                    lines.append(f"**Impact:** {finding['impact']}")
                    lines.append("")
                if finding.get('remediation'):
                    lines.append(f"**Remediation:** {finding['remediation']}")
                    lines.append("")
                lines.append("---")
                lines.append("")
    
    lines.append("## Summary")
    lines.append("")
    lines.append(f"Total findings: {len(findings)}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = len(by_severity.get(sev, []))
        if count > 0:
            lines.append(f"- {sev.capitalize()}: {count}")
    lines.append("")
    
    return "\n".join(lines)

def _generate_json_report(findings: list, target: str) -> str:
    """Generate a JSON bug bounty report."""
    report = {
        "target": target,
        "generated": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        "total_findings": len(findings),
        "findings": findings,
        "summary": {
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
            "info": len([f for f in findings if f.get("severity") == "info"]),
        }
    }
    return json.dumps(report, indent=2)

def save_report(report: str, filename: str) -> Path:
    """Save a report to file."""
    path = REPORT_DIR / filename
    path.write_text(report)
    return path

if __name__ == "__main__":
    # Example usage
    sample_findings = [
        {
            "title": "Stored XSS on User Profile",
            "type": "XSS",
            "severity": "high",
            "url": "https://target.com/profile",
            "description": "User profile page stores unsanitized input that executes JavaScript.",
            "poc": "<script>alert(document.cookie)</script>",
            "impact": "Session hijacking, credential theft",
            "remediation": "Implement proper input sanitization and Content Security Policy"
        }
    ]
    report = generate_report(sample_findings, "target.com")
    print(report[:500] + "...")
