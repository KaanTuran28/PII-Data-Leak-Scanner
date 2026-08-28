#!/usr/bin/env python3
"""Scans files/directories for accidentally leaked PII — a DLP/compliance-style tool.

Meant for scanning a data export, log dump, or repo *before* it's shared
externally (e.g. with a vendor, uploaded to a bug tracker, or committed to
git) — not for scanning live LLM output (see the companion
`LLM-Output-Guardrail` project for that) and not for credentials/API keys
(see `Git-Secrets-Scanner`). Every match is redacted before it's ever
written to a report; the raw value never leaves memory.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SSN_RE = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")
CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

DEFAULT_EXCLUDE_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache", ".ruff_cache"}

SEVERITY_BY_TYPE = {
    "ssn_us": "HIGH",
    "credit_card": "HIGH",
    "iban": "HIGH",
    "email": "MEDIUM",
    "phone_number": "LOW",
}


def luhn_valid(digits: str) -> bool:
    values = [int(d) for d in digits]
    parity = len(values) % 2
    checksum = 0
    for i, d in enumerate(values):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def iban_valid(candidate: str) -> bool:
    iban = candidate.upper().replace(" ", "")
    if not (15 <= len(iban) <= 34):
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False
    return int(numeric) % 97 == 1


def redact(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def find_credit_cards(line: str) -> list:
    hits = []
    for m in CARD_CANDIDATE_RE.finditer(line):
        digits = re.sub(r"[ -]", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            hits.append(m.group())
    return hits


def find_ibans(line: str) -> list:
    return [m.group() for m in IBAN_RE.finditer(line) if iban_valid(m.group())]


def scan_line(line: str) -> list:
    hits = []
    for m in EMAIL_RE.finditer(line):
        hits.append(("email", m.group()))
    for m in SSN_RE.finditer(line):
        hits.append(("ssn_us", m.group()))
    for value in find_credit_cards(line):
        hits.append(("credit_card", value))
    for value in find_ibans(line):
        hits.append(("iban", value))
    for m in PHONE_RE.finditer(line):
        hits.append(("phone_number", m.group()))
    return hits


def scan_text(text: str, source: str) -> list:
    findings = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pii_type, value in scan_line(line):
            findings.append({
                "severity": SEVERITY_BY_TYPE[pii_type],
                "type": pii_type,
                "file": source,
                "line": line_no,
                "redacted_value": redact(value),
            })
    return findings


def scan_file(path: Path) -> list:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    return scan_text(text, str(path))


def collect_files(path: Path, exclude_dirs: set | None = None) -> list:
    exclude_dirs = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    if path.is_file():
        return [path]
    files = []
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file():
            continue
        if any(part in exclude_dirs for part in candidate.parts):
            continue
        files.append(candidate)
    return files


def scan_directory(path: Path, exclude_dirs: set | None = None) -> list:
    findings = []
    for f in collect_files(path, exclude_dirs):
        findings.extend(scan_file(f))
    return findings


def build_report(findings: list, source: str) -> str:
    by_type = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")

    lines = [
        "# PII Data Leak Scan Report",
        "",
        f"- **Source:** {source}",
        f"- **Total findings:** {len(findings)} ({high} HIGH, {medium} MEDIUM, {low} LOW)",
    ]
    for pii_type, count in sorted(by_type.items()):
        lines.append(f"  - {pii_type}: {count}")
    lines.append("")

    if findings:
        lines += ["| Severity | Type | File | Line | Redacted Value |", "|---|---|---|---|---|"]
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for f in sorted(findings, key=lambda f: (order[f["severity"]], f["file"], f["line"])):
            lines.append(f"| {f['severity']} | {f['type']} | {f['file']} | {f['line']} | `{f['redacted_value']}` |")
    else:
        lines.append("No PII detected.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(findings: list, source: str) -> str:
    by_type = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    payload = {
        "source": source,
        "summary": {
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "by_type": by_type,
        },
        "findings": findings,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Scan a file or directory for accidentally leaked PII (emails, SSNs, credit cards, IBANs, phone numbers)."
    )
    parser.add_argument("--path", required=True, help="File or directory to scan.")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    target = Path(args.path)
    findings = scan_file(target) if target.is_file() else scan_directory(target)

    report = build_json_report(findings, args.path) if args.format == "json" else build_report(findings, args.path)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    print(f"Scanned {args.path}: {len(findings)} finding(s) ({high_count} HIGH, {medium_count} MEDIUM).")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
