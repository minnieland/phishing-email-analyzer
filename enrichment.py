"""Threat intelligence enrichment via VirusTotal and AbuseIPDB."""

from __future__ import annotations

import time
from typing import Any

import requests

import config


class RateLimitError(Exception):
    """Raised when an upstream API returns HTTP 429."""


def _placeholder_key(key: str) -> bool:
    return not key or key.startswith("YOUR_") or key.endswith("_HERE")


def _handle_rate_limit(response: requests.Response, service: str) -> None:
    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After", "60")
        raise RateLimitError(
            f"{service} rate limit exceeded (HTTP 429). Retry-After: {retry_after}s"
        )


def query_virustotal_file(sha256: str) -> dict[str, Any]:
    """Query VirusTotal API v3 for a file hash detection ratio."""
    if _placeholder_key(config.VT_API_KEY):
        return {
            "queried": False,
            "sha256": sha256,
            "error": "VT_API_KEY not configured",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "detection_ratio": "0/0",
            "detections": 0,
        }

    url = f"{config.VT_BASE_URL}/files/{sha256}"
    headers = {"x-apikey": config.VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=config.VT_TIMEOUT_SECONDS)
        _handle_rate_limit(resp, "VirusTotal")
        if resp.status_code == 404:
            return {
                "queried": True,
                "sha256": sha256,
                "error": None,
                "not_found": True,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "detection_ratio": "0/0",
                "detections": 0,
            }
        resp.raise_for_status()
        stats = (
            resp.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        detections = malicious + suspicious
        return {
            "queried": True,
            "sha256": sha256,
            "error": None,
            "not_found": False,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "detection_ratio": f"{detections}/{total}",
            "detections": detections,
        }
    except RateLimitError as exc:
        return {
            "queried": False,
            "sha256": sha256,
            "error": str(exc),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "detection_ratio": "0/0",
            "detections": 0,
        }
    except requests.RequestException as exc:
        return {
            "queried": False,
            "sha256": sha256,
            "error": f"VirusTotal request failed: {exc}",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "detection_ratio": "0/0",
            "detections": 0,
        }


def query_virustotal_url(target_url: str) -> dict[str, Any]:
    """Query VirusTotal API v3 for a URL detection ratio."""
    if _placeholder_key(config.VT_API_KEY):
        return {
            "queried": False,
            "url": target_url,
            "error": "VT_API_KEY not configured",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "detection_ratio": "0/0",
            "detections": 0,
        }

    # VT identifies URLs by base64url-encoded form without padding,
    # but the POST /urls + GET /urls/{id} flow is more reliable.
    headers = {"x-apikey": config.VT_API_KEY}

    try:
        submit = requests.post(
            f"{config.VT_BASE_URL}/urls",
            headers=headers,
            data={"url": target_url},
            timeout=config.VT_TIMEOUT_SECONDS,
        )
        _handle_rate_limit(submit, "VirusTotal")
        submit.raise_for_status()
        analysis_id = submit.json().get("data", {}).get("id")
        if not analysis_id:
            return {
                "queried": False,
                "url": target_url,
                "error": "VirusTotal did not return an analysis id",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "detection_ratio": "0/0",
                "detections": 0,
            }

        # Brief pause then fetch URL report via analysis → url object
        time.sleep(1)
        analysis = requests.get(
            f"{config.VT_BASE_URL}/analyses/{analysis_id}",
            headers=headers,
            timeout=config.VT_TIMEOUT_SECONDS,
        )
        _handle_rate_limit(analysis, "VirusTotal")
        analysis.raise_for_status()
        stats = (
            analysis.json()
            .get("data", {})
            .get("attributes", {})
            .get("stats", {})
        )
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        detections = malicious + suspicious
        return {
            "queried": True,
            "url": target_url,
            "error": None,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "detection_ratio": f"{detections}/{total}",
            "detections": detections,
        }
    except RateLimitError as exc:
        return {
            "queried": False,
            "url": target_url,
            "error": str(exc),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "detection_ratio": "0/0",
            "detections": 0,
        }
    except requests.RequestException as exc:
        return {
            "queried": False,
            "url": target_url,
            "error": f"VirusTotal request failed: {exc}",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "detection_ratio": "0/0",
            "detections": 0,
        }


def query_abuseipdb(ip: str) -> dict[str, Any]:
    """Query AbuseIPDB for abuse confidence score and ISP data."""
    if not ip:
        return {
            "queried": False,
            "ip": ip,
            "error": "No originating IP available",
            "abuse_confidence_score": 0,
            "isp": None,
            "country_code": None,
            "usage_type": None,
            "total_reports": 0,
        }

    if _placeholder_key(config.ABUSEIPDB_API_KEY):
        return {
            "queried": False,
            "ip": ip,
            "error": "ABUSEIPDB_API_KEY not configured",
            "abuse_confidence_score": 0,
            "isp": None,
            "country_code": None,
            "usage_type": None,
            "total_reports": 0,
        }

    headers = {
        "Key": config.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": config.ABUSEIPDB_MAX_AGE_DAYS,
        "verbose": "",
    }

    try:
        resp = requests.get(
            f"{config.ABUSEIPDB_BASE_URL}/check",
            headers=headers,
            params=params,
            timeout=config.ABUSEIPDB_TIMEOUT_SECONDS,
        )
        _handle_rate_limit(resp, "AbuseIPDB")
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "queried": True,
            "ip": ip,
            "error": None,
            "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0)),
            "isp": data.get("isp"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "total_reports": int(data.get("totalReports", 0) or 0),
            "domain": data.get("domain"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
    except RateLimitError as exc:
        return {
            "queried": False,
            "ip": ip,
            "error": str(exc),
            "abuse_confidence_score": 0,
            "isp": None,
            "country_code": None,
            "usage_type": None,
            "total_reports": 0,
        }
    except requests.RequestException as exc:
        return {
            "queried": False,
            "ip": ip,
            "error": f"AbuseIPDB request failed: {exc}",
            "abuse_confidence_score": 0,
            "isp": None,
            "country_code": None,
            "usage_type": None,
            "total_reports": 0,
        }


def enrich_analysis(parsed: dict[str, Any], max_urls: int = 5) -> dict[str, Any]:
    """
    Enrich parsed email data with VT (hashes + URLs) and AbuseIPDB (origin IP).

    Limits URL lookups to avoid free-tier rate limits.
    """
    attachment_results = []
    for att in parsed.get("attachments", []):
        attachment_results.append(
            {
                **att,
                "virustotal": query_virustotal_file(att["sha256"]),
            }
        )
        time.sleep(0.25)

    url_results = []
    for url in parsed.get("iocs", {}).get("urls", [])[:max_urls]:
        url_results.append(query_virustotal_url(url))
        time.sleep(0.25)

    abuse = query_abuseipdb(parsed.get("originating_ip"))

    return {
        "attachments": attachment_results,
        "urls": url_results,
        "abuseipdb": abuse,
    }
