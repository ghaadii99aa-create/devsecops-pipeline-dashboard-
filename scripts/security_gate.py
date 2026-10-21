#!/usr/bin/env python3
"""
Security gate & report normalizer.

Reads the raw Bandit and Trivy JSON reports produced by the pipeline, merges
them into a single normalized ``scan-results.json`` (consumed by the
vulnerability dashboard), writes a Markdown summary for the GitHub Actions job
page, and fails the build when findings at or above ``--fail-on`` exist.

Usage:
    python scripts/security_gate.py --input-dir scan-reports \
        --output reports/scan-results.json --fail-on CRITICAL
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(SEVERITIES), start=1)}  # LOW=1 .. CRITICAL=4


def normalize_severity(value: str | None) -> str:
    value = (value or "").upper()
    # Trivy may report UNKNOWN; treat it as LOW so it is still surfaced.
    return value if value in SEVERITIES else "LOW"


def parse_bandit(report: dict) -> list[dict]:
    findings = []
    for issue in report.get("results", []):
        findings.append(
            {
                "scanner": "Bandit",
                "category": "SAST",
                "severity": normalize_severity(issue.get("issue_severity")),
                "id": issue.get("test_id", ""),
                "title": issue.get("test_name", "").replace("_", " ").title(),
                "description": issue.get("issue_text", ""),
                "target": issue.get("filename", ""),
                "location": f"line {issue.get('line_number', '?')}",
                "confidence": issue.get("issue_confidence", ""),
                "fix": "Review the flagged code and apply the recommended secure pattern.",
                "reference": issue.get("more_info", ""),
            }
        )
    return findings


def parse_trivy(report: dict, source: str) -> list[dict]:
    findings = []
    artifact = report.get("ArtifactName", "")
    for result in report.get("Results", []) or []:
        target = result.get("Target", artifact)
        for vuln in result.get("Vulnerabilities", []) or []:
            fixed = vuln.get("FixedVersion")
            findings.append(
                {
                    "scanner": source,
                    "category": "Vulnerability",
                    "severity": normalize_severity(vuln.get("Severity")),
                    "id": vuln.get("VulnerabilityID", ""),
                    "title": vuln.get("Title") or f"{vuln.get('PkgName')} vulnerability",
                    "description": vuln.get("Description", ""),
                    "target": target,
                    "location": f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}",
                    "fix": f"Upgrade to {fixed}" if fixed else "No fixed version available yet",
                    "reference": vuln.get("PrimaryURL", ""),
                }
            )
        for secret in result.get("Secrets", []) or []:
            findings.append(
                {
                    "scanner": source,
                    "category": "Secret",
                    "severity": normalize_severity(secret.get("Severity")),
                    "id": secret.get("RuleID", ""),
                    "title": secret.get("Title", "Exposed secret"),
                    "description": "Hard-coded secret detected. The value is redacted in this report.",
                    "target": target,
                    "location": f"line {secret.get('StartLine', '?')}",
                    "fix": "Revoke and rotate the credential, then load it from a secret manager.",
                    "reference": "",
                }
            )
        for misconf in result.get("Misconfigurations", []) or []:
            if misconf.get("Status") == "PASS":
                continue
            findings.append(
                {
                    "scanner": source,
                    "category": "Misconfiguration",
                    "severity": normalize_severity(misconf.get("Severity")),
                    "id": misconf.get("ID") or misconf.get("AVDID", ""),
                    "title": misconf.get("Title", ""),
                    "description": misconf.get("Message") or misconf.get("Description", ""),
                    "target": target,
                    "location": misconf.get("Type", ""),
                    "fix": misconf.get("Resolution", ""),
                    "reference": misconf.get("PrimaryURL", ""),
                }
            )
    return findings


def load_findings(input_dir: Path) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    sources: list[str] = []
    for path in sorted(input_dir.rglob("*.json")):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"::warning::Skipping unreadable report {path}: {exc}")
            continue
        if not isinstance(report, dict):
            continue
        if "results" in report and "metrics" in report:
            findings += parse_bandit(report)
            sources.append(f"Bandit ({path.name})")
        elif "SchemaVersion" in report or "ArtifactType" in report:
            label = "Trivy (image)" if report.get("ArtifactType") == "container_image" else "Trivy (filesystem)"
            findings += parse_trivy(report, label)
            sources.append(f"{label} ({path.name})")
    return findings, sources


def build_summary_markdown(summary: dict, findings: list[dict], fail_on: str, failed: bool) -> str:
    icons = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦"}
    lines = [
        "## 🛡️ DevSecOps Security Gate",
        "",
        "| Severity | Findings |",
        "|---|---:|",
    ]
    lines += [f"| {icons[s]} {s.title()} | {summary[s]} |" for s in SEVERITIES]
    lines += ["", f"**Gate policy:** fail on `{fail_on}` or above → **{'❌ FAILED' if failed else '✅ PASSED'}**", ""]
    top = sorted(findings, key=lambda f: -SEVERITY_RANK[f["severity"]])[:10]
    if top:
        lines += ["### Top findings", "", "| Severity | Scanner | ID | Target |", "|---|---|---|---|"]
        lines += [f"| {f['severity']} | {f['scanner']} | `{f['id']}` | {f['target']} |" for f in top]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input-dir", default="scan-reports", type=Path)
    parser.add_argument("--output", default="reports/scan-results.json", type=Path)
    parser.add_argument(
        "--fail-on",
        default=os.environ.get("FAIL_ON", "CRITICAL"),
        type=str.upper,
        choices=SEVERITIES + ["NONE"],
        help="Lowest severity that fails the build (NONE = report only).",
    )
    args = parser.parse_args()

    findings, sources = load_findings(args.input_dir)
    summary = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in SEVERITIES}

    failed = False
    if args.fail_on != "NONE":
        threshold = SEVERITY_RANK[args.fail_on]
        failed = any(SEVERITY_RANK[f["severity"]] >= threshold for f in findings)

    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "repository": repo,
            "branch": os.environ.get("GITHUB_REF_NAME", "local"),
            "commit": os.environ.get("GITHUB_SHA", "")[:7],
            "run_url": f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else "",
            "sources": sources,
            "gate": {"fail_on": args.fail_on, "status": "failed" if failed else "passed"},
        },
        "summary": summary,
        "findings": findings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")

    markdown = build_summary_markdown(summary, findings, args.fail_on, failed)
    print(markdown)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(markdown)

    if not sources:
        print("::error::No scan reports were found - refusing to pass the gate without evidence.")
        return 1
    if failed:
        print(f"::error::Security gate failed: findings at or above {args.fail_on} severity.")
        return 1
    print("Security gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
