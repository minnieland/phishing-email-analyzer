#!/usr/bin/env python3
"""CLI entry point for end-to-end phishing email (.eml) analysis."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import config
from enrichment import enrich_analysis
from parser import parse_eml
from reporter import print_markdown_report, save_json_report
from scorer import calculate_risk


def build_analysis(eml_path: Path, skip_enrichment: bool = False) -> dict:
    parsed = parse_eml(eml_path)

    if skip_enrichment:
        enrichment = {
            "attachments": [
                {**att, "virustotal": {"queried": False, "detections": 0, "detection_ratio": "0/0", "error": "skipped"}}
                for att in parsed.get("attachments", [])
            ],
            "urls": [
                {"url": u, "queried": False, "detections": 0, "detection_ratio": "0/0", "error": "skipped"}
                for u in parsed.get("iocs", {}).get("urls", [])
            ],
            "abuseipdb": {
                "queried": False,
                "ip": parsed.get("originating_ip"),
                "abuse_confidence_score": 0,
                "error": "skipped",
            },
        }
    else:
        enrichment = enrich_analysis(parsed)

    scoring = calculate_risk(parsed, enrichment)

    return {
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "tool": "phishing-email-analyzer",
        "parsed": parsed,
        "enrichment": enrichment,
        "scoring": scoring,
        "api_keys_configured": {
            "virustotal": not (
                not config.VT_API_KEY
                or config.VT_API_KEY.startswith("YOUR_")
            ),
            "abuseipdb": not (
                not config.ABUSEIPDB_API_KEY
                or config.ABUSEIPDB_API_KEY.startswith("YOUR_")
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a raw phishing email (.eml): extract IOCs, enrich, score, and report.",
    )
    parser.add_argument(
        "eml_file",
        type=Path,
        help="Path to the .eml file to analyze",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(config.DEFAULT_JSON_OUTPUT),
        help=f"JSON output path (default: {config.DEFAULT_JSON_OUTPUT})",
    )
    parser.add_argument(
        "--skip-enrichment",
        action="store_true",
        help="Skip VirusTotal / AbuseIPDB API calls (offline parse + score only)",
    )
    args = parser.parse_args(argv)

    eml_path = args.eml_file.expanduser().resolve()
    if not eml_path.is_file():
        print(f"Error: file not found: {eml_path}", file=sys.stderr)
        return 1
    if eml_path.suffix.lower() != ".eml":
        print(f"Warning: expected a .eml file, got: {eml_path.name}", file=sys.stderr)

    analysis = build_analysis(eml_path, skip_enrichment=args.skip_enrichment)
    print_markdown_report(analysis)
    out = save_json_report(analysis, args.output)
    print(f"\nSaved full analysis to `{out.resolve()}`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
