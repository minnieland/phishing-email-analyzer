"""Markdown console report and JSON output generators."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import config


def _remediation_steps(classification: str, parsed: dict[str, Any], enrichment: dict[str, Any]) -> list[str]:
    steps = [
        "Quarantine the original message and any related mailbox copies.",
        "Do not click embedded links or open attachments from the message.",
    ]

    urls = parsed.get("iocs", {}).get("urls") or []
    if urls:
        steps.append(
            "Block extracted URLs/domains at the web proxy / DNS filter pending investigation."
        )

    if parsed.get("attachments"):
        steps.append(
            "Submit attachment hashes to the sandbox / EDR blocklist; scan endpoints for the same SHA256."
        )

    origin_ip = parsed.get("originating_ip")
    abuse = enrichment.get("abuseipdb") or {}
    if origin_ip and (
        (abuse.get("abuse_confidence_score") or 0) > config.ABUSEIPDB_CONFIDENCE_THRESHOLD
        or classification == "Malicious"
    ):
        steps.append(
            f"Consider temporary ingress blocking / heightened monitoring for originating IP `{origin_ip}`."
        )

    if parsed.get("sender_mismatch") or _auth_looks_bad(parsed):
        steps.append(
            "Review SPF/DKIM/DMARC alignment for the apparent From domain; escalate spoofed-brand cases to the brand owner if confirmed."
        )

    if classification == "Low Risk":
        steps.append("Document findings and close as benign / informational unless user reports persist.")
    elif classification == "Suspicious":
        steps.append("Open a phishing ticket, notify the recipient, and hunt for similar subjects/senders in the last 72 hours.")
    else:
        steps.append(
            "Treat as confirmed phishing/malware delivery: reset credentials if links were clicked, isolate affected hosts, and notify IR."
        )

    return steps


def _auth_looks_bad(parsed: dict[str, Any]) -> bool:
    auth = parsed.get("authentication") or {}
    for key in ("spf", "dkim", "dmarc"):
        if (auth.get(key) or "").lower() in {"fail", "softfail", "permerror"}:
            return True
    return False


def _ioc_rows(parsed: dict[str, Any], enrichment: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return rows of (type, value, enrichment summary)."""
    rows: list[tuple[str, str, str]] = []

    origin = parsed.get("originating_ip")
    abuse = enrichment.get("abuseipdb") or {}
    if origin:
        if abuse.get("error"):
            summary = f"AbuseIPDB: {abuse['error']}"
        else:
            summary = (
                f"AbuseIPDB confidence={abuse.get('abuse_confidence_score', 0)}%, "
                f"ISP={abuse.get('isp') or 'n/a'}, "
                f"CC={abuse.get('country_code') or 'n/a'}"
            )
        rows.append(("Originating IP", origin, summary))

    vt_by_url = {r.get("url"): r for r in enrichment.get("urls", [])}
    for url in parsed.get("iocs", {}).get("urls") or []:
        vt = vt_by_url.get(url)
        if not vt:
            summary = "VirusTotal: not queried"
        elif vt.get("error"):
            summary = f"VirusTotal: {vt['error']}"
        else:
            summary = f"VirusTotal detections={vt.get('detection_ratio', '0/0')}"
        rows.append(("URL", url, summary))

    for domain in parsed.get("iocs", {}).get("domains") or []:
        rows.append(("Domain", domain, "Extracted from message content/headers"))

    for ip in parsed.get("iocs", {}).get("ipv4") or []:
        if ip == origin:
            continue
        rows.append(("IPv4", ip, "Extracted from message content/headers"))

    for att in enrichment.get("attachments") or parsed.get("attachments") or []:
        vt = att.get("virustotal") or {}
        if vt.get("error"):
            summary = f"SHA256={att.get('sha256')}; VT: {vt['error']}"
        elif vt:
            summary = f"SHA256={att.get('sha256')}; VT detections={vt.get('detection_ratio', '0/0')}"
        else:
            summary = f"SHA256={att.get('sha256')}"
        rows.append(("Attachment", att.get("filename") or "unnamed", summary))

    return rows


def build_markdown_report(analysis: dict[str, Any]) -> str:
    parsed = analysis["parsed"]
    enrichment = analysis["enrichment"]
    scoring = analysis["scoring"]

    headers = parsed.get("headers") or {}
    auth = parsed.get("authentication") or {}
    classification = scoring["classification"]
    score = scoring["risk_score"]

    lines: list[str] = []
    lines.append("# Phishing Email Analysis Report")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"| --- | --- |")
    lines.append(f"| **Classification** | **{classification}** |")
    lines.append(f"| **Risk Score** | **{score}/100** |")
    lines.append(f"| Source File | `{parsed.get('source_file')}` |")
    lines.append("")

    lines.append("## Header Summary")
    lines.append("")
    lines.append("| Header | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| From | {headers.get('from') or 'n/a'} |")
    lines.append(f"| Return-Path | {headers.get('return_path') or 'n/a'} |")
    lines.append(f"| Reply-To | {headers.get('reply_to') or 'n/a'} |")
    lines.append(f"| Subject | {headers.get('subject') or 'n/a'} |")
    lines.append(f"| Date | {headers.get('date') or 'n/a'} |")
    lines.append(f"| Originating IP | {parsed.get('originating_ip') or 'n/a'} |")
    lines.append(
        f"| SPF / DKIM / DMARC | "
        f"{auth.get('spf') or 'n/a'} / {auth.get('dkim') or 'n/a'} / {auth.get('dmarc') or 'n/a'} |"
    )
    lines.append(
        f"| Sender Mismatch | "
        f"{'Yes' if parsed.get('sender_mismatch') else 'No'} "
        f"(`{parsed.get('from_domain')}` vs `{parsed.get('return_path_domain')}`) |"
    )
    lines.append("")

    lines.append("## Score Breakdown")
    lines.append("")
    lines.append("| Condition | Triggered | Points |")
    lines.append("| --- | --- | --- |")
    for item in scoring.get("breakdown") or []:
        lines.append(
            f"| {item['condition']} | {'Yes' if item.get('triggered') else 'No'} | {item.get('points', 0)} |"
        )
    lines.append("")

    lines.append("## Enriched IOC Table")
    lines.append("")
    lines.append("| Type | Value | Enrichment |")
    lines.append("| --- | --- | --- |")
    rows = _ioc_rows(parsed, enrichment)
    if not rows:
        lines.append("| — | No IOCs extracted | — |")
    else:
        for ioc_type, value, summary in rows:
            safe_value = str(value).replace("|", "\\|")
            safe_summary = str(summary).replace("|", "\\|")
            lines.append(f"| {ioc_type} | `{safe_value}` | {safe_summary} |")
    lines.append("")

    lines.append("## Recommended Remediation")
    lines.append("")
    for step in _remediation_steps(classification, parsed, enrichment):
        lines.append(f"- {step}")
    lines.append("")

    lines.append("---")
    lines.append("*Generated by phishing-email-analyzer for SOC triage.*")
    lines.append("")

    return "\n".join(lines)


def print_markdown_report(analysis: dict[str, Any]) -> None:
    print(build_markdown_report(analysis))


def save_json_report(analysis: dict[str, Any], output_path: str | Path | None = None) -> Path:
    path = Path(output_path or config.DEFAULT_JSON_OUTPUT)
    path.write_text(json.dumps(analysis, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path
