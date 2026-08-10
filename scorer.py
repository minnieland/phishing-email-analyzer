"""Risk score calculation based on extracted and enriched features."""

from __future__ import annotations

from typing import Any

import config

FAIL_AUTH_STATUSES = {"fail", "softfail", "permerror"}


def _auth_failed(authentication: dict[str, Any]) -> bool:
    for key in ("spf", "dkim", "dmarc"):
        status = (authentication.get(key) or "").lower()
        if status in FAIL_AUTH_STATUSES:
            return True
    return False


def _max_vt_detections(enrichment: dict[str, Any]) -> int:
    detections = 0
    for att in enrichment.get("attachments", []):
        vt = att.get("virustotal") or {}
        detections = max(detections, int(vt.get("detections") or 0))
    for url_result in enrichment.get("urls", []):
        detections = max(detections, int(url_result.get("detections") or 0))
    return detections


def classify(score: int) -> str:
    if score <= config.CLASSIFICATION_LOW_MAX:
        return "Low Risk"
    if score <= config.CLASSIFICATION_SUSPICIOUS_MAX:
        return "Suspicious"
    return "Malicious"


def calculate_risk(parsed: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, Any]:
    """
    Calculate a dynamic Risk Score (0–100) from weighted conditions:

    - Authentication Failures (SPF/DKIM/DMARC fail): +30
    - AbuseIPDB confidence score > 50%: +25
    - VirusTotal detections > 3 engines: +35
    - Sender Mismatch (From domain != Return-Path domain): +15
    """
    breakdown: list[dict[str, Any]] = []
    score = 0

    auth_fail = _auth_failed(parsed.get("authentication") or {})
    if auth_fail:
        score += config.SCORE_AUTH_FAILURE
        breakdown.append(
            {
                "condition": "Authentication Failures (SPF/DKIM/DMARC fail)",
                "points": config.SCORE_AUTH_FAILURE,
                "triggered": True,
                "detail": {
                    "spf": parsed.get("authentication", {}).get("spf"),
                    "dkim": parsed.get("authentication", {}).get("dkim"),
                    "dmarc": parsed.get("authentication", {}).get("dmarc"),
                },
            }
        )
    else:
        breakdown.append(
            {
                "condition": "Authentication Failures (SPF/DKIM/DMARC fail)",
                "points": 0,
                "triggered": False,
                "detail": parsed.get("authentication"),
            }
        )

    abuse_score = int(
        (enrichment.get("abuseipdb") or {}).get("abuse_confidence_score") or 0
    )
    if abuse_score > config.ABUSEIPDB_CONFIDENCE_THRESHOLD:
        score += config.SCORE_ABUSEIPDB_HIGH
        breakdown.append(
            {
                "condition": f"AbuseIPDB confidence score > {config.ABUSEIPDB_CONFIDENCE_THRESHOLD}%",
                "points": config.SCORE_ABUSEIPDB_HIGH,
                "triggered": True,
                "detail": {"abuse_confidence_score": abuse_score},
            }
        )
    else:
        breakdown.append(
            {
                "condition": f"AbuseIPDB confidence score > {config.ABUSEIPDB_CONFIDENCE_THRESHOLD}%",
                "points": 0,
                "triggered": False,
                "detail": {"abuse_confidence_score": abuse_score},
            }
        )

    vt_detections = _max_vt_detections(enrichment)
    if vt_detections > config.VT_DETECTION_THRESHOLD:
        score += config.SCORE_VT_DETECTIONS
        breakdown.append(
            {
                "condition": f"VirusTotal detections > {config.VT_DETECTION_THRESHOLD} engines",
                "points": config.SCORE_VT_DETECTIONS,
                "triggered": True,
                "detail": {"max_detections": vt_detections},
            }
        )
    else:
        breakdown.append(
            {
                "condition": f"VirusTotal detections > {config.VT_DETECTION_THRESHOLD} engines",
                "points": 0,
                "triggered": False,
                "detail": {"max_detections": vt_detections},
            }
        )

    sender_mismatch = bool(parsed.get("sender_mismatch"))
    if sender_mismatch:
        score += config.SCORE_SENDER_MISMATCH
        breakdown.append(
            {
                "condition": "Sender Mismatch (From domain != Return-Path domain)",
                "points": config.SCORE_SENDER_MISMATCH,
                "triggered": True,
                "detail": {
                    "from_domain": parsed.get("from_domain"),
                    "return_path_domain": parsed.get("return_path_domain"),
                },
            }
        )
    else:
        breakdown.append(
            {
                "condition": "Sender Mismatch (From domain != Return-Path domain)",
                "points": 0,
                "triggered": False,
                "detail": {
                    "from_domain": parsed.get("from_domain"),
                    "return_path_domain": parsed.get("return_path_domain"),
                },
            }
        )

    score = max(0, min(100, score))
    classification = classify(score)

    return {
        "risk_score": score,
        "classification": classification,
        "breakdown": breakdown,
    }
