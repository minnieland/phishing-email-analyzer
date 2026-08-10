"""Parse .eml files and extract headers, IOCs, and attachment hashes."""

from __future__ import annotations

import email
import hashlib
import re
from email import policy
from email.message import EmailMessage, Message
from email.utils import parseaddr
from pathlib import Path
from typing import Any

# IPv4 (including common Received-header forms)
IPV4_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
)

# URLs in body / headers
URL_RE = re.compile(
    r"https?://[^\s<>\"'\]\)]+",
    re.IGNORECASE,
)

# Domain extraction from URLs or bare host-like tokens
DOMAIN_RE = re.compile(
    r"(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})",
    re.IGNORECASE,
)

# Authentication-Results tokens
SPF_RE = re.compile(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I)
DKIM_RE = re.compile(r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b", re.I)
DMARC_RE = re.compile(r"\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b", re.I)

# Skip noise / false-positive domains when listing IOC domains
NOISE_DOMAINS = {
    "localhost",
    "header.from",
    "smtp.mailfrom",
    "smtp.helo",
    "header.d",
}

# Common Authentication-Results tokens mistaken for domains
AUTH_TOKEN_RE = re.compile(
    r"\b(?:spf|dkim|dmarc|smtp\.(?:mailfrom|helo)|header\.(?:from|d))=",
    re.IGNORECASE,
)


def _decode_payload(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            raw = part.get_payload()
            return raw if isinstance(raw, str) else ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""


def _extract_body_text(msg: Message) -> str:
    chunks: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disposition:
                continue
            if ctype in ("text/plain", "text/html"):
                chunks.append(_decode_payload(part))
    else:
        chunks.append(_decode_payload(msg))
    return "\n".join(chunks)


def _domain_from_address(addr: str | None) -> str | None:
    if not addr:
        return None
    _, email_addr = parseaddr(addr)
    if "@" not in email_addr:
        return None
    return email_addr.split("@", 1)[1].lower().strip()


def _parse_auth_results(auth_header: str | None) -> dict[str, str | None]:
    if not auth_header:
        return {"spf": None, "dkim": None, "dmarc": None, "raw": None}

    # Multiple Authentication-Results headers may be joined with newlines
    joined = auth_header if isinstance(auth_header, str) else "\n".join(auth_header)

    spf = SPF_RE.search(joined)
    dkim = DKIM_RE.search(joined)
    dmarc = DMARC_RE.search(joined)

    return {
        "spf": spf.group(1).lower() if spf else None,
        "dkim": dkim.group(1).lower() if dkim else None,
        "dmarc": dmarc.group(1).lower() if dmarc else None,
        "raw": joined,
    }


def _originating_ip_from_received(msg: Message) -> str | None:
    """
    Identify the true originating IP from the lowest (oldest) Received header.

    In SMTP, Received headers are prepended, so the last header in the message
    is typically the earliest hop (closest to the origin).
    """
    received_headers = msg.get_all("Received", failobj=[])
    if not received_headers:
        return None

    # Lowest / oldest Received header
    oldest = received_headers[-1]

    # Prefer IP in brackets, then "from ... [ip]", then any IPv4
    bracketed = re.search(r"\[(" + IPV4_RE.pattern + r")\]", oldest)
    if bracketed:
        ip = bracketed.group(1)
        if not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168."):
            return ip
        # Still return private if that's all we have later
        candidate = ip
    else:
        candidate = None

    from_match = re.search(
        r"from\s+\S+\s+\((" + IPV4_RE.pattern + r")\)",
        oldest,
        re.IGNORECASE,
    )
    if from_match:
        return from_match.group(1)

    all_ips = IPV4_RE.findall(oldest)
    # Filter out common non-origin noise when possible
    publicish = [
        ip
        for ip in all_ips
        if not ip.startswith("127.")
        and not ip.startswith("0.")
        and ip != "255.255.255.255"
    ]
    if publicish:
        return publicish[0]
    if candidate:
        return candidate
    return all_ips[0] if all_ips else None


def _extract_attachments(msg: Message) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = str(part.get("Content-Disposition", "")).lower()
        is_attachment = bool(filename) or "attachment" in disposition
        if not is_attachment:
            continue

        payload = part.get_payload(decode=True) or b""
        sha256 = hashlib.sha256(payload).hexdigest()
        attachments.append(
            {
                "filename": filename or "unnamed",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": sha256,
            }
        )
    return attachments


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?)>]\"'")


def extract_iocs(text: str, headers_blob: str) -> dict[str, list[str]]:
    # Strip Authentication-Results key=value tokens before domain scanning
    scrubbed_headers = AUTH_TOKEN_RE.sub("", headers_blob)
    haystack = f"{scrubbed_headers}\n{text}"

    urls = sorted({_clean_url(u) for u in URL_RE.findall(haystack)})
    ipv4s = sorted(set(IPV4_RE.findall(haystack)))

    domains: set[str] = set()
    for url in urls:
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0]
        host = host.split("@")[-1].split(":")[0].lower()
        if DOMAIN_RE.fullmatch(host) and host not in NOISE_DOMAINS:
            domains.add(host)

    # Prefer domains from email addresses in headers
    for addr_match in re.findall(r"[\w.+-]+@([\w.-]+\.[a-z]{2,})", scrubbed_headers, re.I):
        d = addr_match.lower()
        if d not in NOISE_DOMAINS:
            domains.add(d)

    for match in DOMAIN_RE.findall(haystack):
        d = match.lower()
        if d in NOISE_DOMAINS:
            continue
        # Skip bare labels that look like auth/header artifacts
        if d.startswith(("header.", "smtp.")):
            continue
        domains.add(d)

    return {
        "urls": urls,
        "domains": sorted(domains),
        "ipv4": ipv4s,
    }


def parse_eml(path: str | Path) -> dict[str, Any]:
    """Read a raw .eml file and return structured extraction results."""
    path = Path(path)
    raw_bytes = path.read_bytes()
    msg: EmailMessage | Message = email.message_from_bytes(raw_bytes, policy=policy.default)

    # Collect possibly multi-valued Authentication-Results
    auth_headers = msg.get_all("Authentication-Results", failobj=[])
    auth_joined = "\n".join(auth_headers) if auth_headers else None

    headers = {
        "from": msg.get("From"),
        "return_path": msg.get("Return-Path"),
        "reply_to": msg.get("Reply-To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "authentication_results": auth_joined,
    }

    auth = _parse_auth_results(auth_joined)
    originating_ip = _originating_ip_from_received(msg)
    body = _extract_body_text(msg)
    attachments = _extract_attachments(msg)

    header_blob = "\n".join(
        f"{k}: {v}" for k, v in headers.items() if v
    )
    iocs = extract_iocs(body, header_blob)

    # Ensure originating IP is represented in IOC list
    if originating_ip and originating_ip not in iocs["ipv4"]:
        iocs["ipv4"] = sorted(set(iocs["ipv4"] + [originating_ip]))

    from_domain = _domain_from_address(headers["from"])
    return_path_domain = _domain_from_address(headers["return_path"])

    return {
        "source_file": str(path.resolve()),
        "headers": headers,
        "authentication": auth,
        "originating_ip": originating_ip,
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "sender_mismatch": bool(
            from_domain
            and return_path_domain
            and from_domain != return_path_domain
        ),
        "iocs": iocs,
        "attachments": attachments,
        "body_preview": body[:500],
    }
