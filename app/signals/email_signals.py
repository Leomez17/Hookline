"""Email signal extraction — Week 1 spike.

Works entirely off text the caller pastes in (raw email source, or just
headers + body). No live SPF/DKIM/DMARC verification — that needs the
receiving mail server's view. If the pasted source already has an
Authentication-Results header (most webmail "show original" views include
one), we read its verdict; otherwise we simply note that alignment
couldn't be checked, which is itself useful signal for a reviewer.
"""
from __future__ import annotations

import re
from email import message_from_string
from email.utils import parseaddr
from typing import List

from app.signals.brand_watchlist import WATCHED_BRANDS
from app.signals.url_signals import extract_url_features

Finding = dict

URGENT_PHRASES = [
    "verify your account", "account will be suspended", "confirm your password",
    "unusual activity", "act now", "immediate action", "click here immediately",
    "your account has been limited", "update your payment", "security alert",
    "urgent action required", "will be closed", "final notice", "reactivate your account",
    "confirm your identity", "suspicious login",
]

URL_RE = re.compile(r"https?://[^\s\"'<>]+|(?<![\w@.])www\.[^\s\"'<>]+", re.IGNORECASE)


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def extract_email_features(raw_email: str) -> List[Finding]:
    findings: List[Finding] = []
    text = raw_email or ""

    msg = message_from_string(text)

    from_header = msg.get("From", "")
    reply_to_header = msg.get("Reply-To", "")
    auth_results = msg.get("Authentication-Results", "")

    from_name, from_addr = parseaddr(from_header)
    from_domain = _domain_of(from_addr)

    if reply_to_header:
        _, reply_addr = parseaddr(reply_to_header)
        reply_domain = _domain_of(reply_addr)
        if reply_domain and from_domain and reply_domain != from_domain:
            findings.append({
                "signal": "reply-to-mismatch",
                "detail": f"Replies go to '{reply_domain}', a different domain than the sender ('{from_domain}')",
                "points": 25,
            })

    if from_name:
        lowered_name = from_name.lower()
        for brand in WATCHED_BRANDS:
            if brand in lowered_name and from_domain and brand not in from_domain:
                findings.append({
                    "signal": "display-name-spoofing",
                    "detail": f"Display name references '{brand}' but the address domain is '{from_domain or 'unknown'}'",
                    "points": 30,
                })
                break

    if auth_results:
        lowered_auth = auth_results.lower()
        for mechanism in ("spf", "dkim", "dmarc"):
            if f"{mechanism}=fail" in lowered_auth or f"{mechanism}=softfail" in lowered_auth:
                findings.append({
                    "signal": f"{mechanism}-fail",
                    "detail": f"Mail server reported {mechanism.upper()} failed for this message",
                    "points": 20,
                })
    else:
        findings.append({
            "signal": "no-auth-results",
            "detail": "No Authentication-Results header present — SPF/DKIM/DMARC alignment couldn't be checked from this copy",
            "points": 0,
        })

    body = text
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_payload(decode=True).decode(errors="ignore"))
                except Exception:
                    pass
        if parts:
            body = "\n".join(parts)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                body = payload.decode(errors="ignore")
            except Exception:
                body = text

    lowered_body = body.lower()
    matched_phrases = [p for p in URGENT_PHRASES if p in lowered_body]
    if matched_phrases:
        points = min(30, 10 + 5 * (len(matched_phrases) - 1))
        sample = "; ".join(matched_phrases[:3])
        findings.append({
            "signal": "urgency-language",
            "detail": f"Body uses credential-harvesting / urgency phrasing (e.g. \"{sample}\")",
            "points": points,
        })

    urls = URL_RE.findall(body)
    for url in urls[:5]:
        for f in extract_url_features(url):
            f = dict(f)
            f["signal"] = f"link:{f['signal']}"
            f["detail"] = f"In linked URL ({url}): {f['detail']}"
            findings.append(f)

    return findings
