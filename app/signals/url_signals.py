"""URL signal extraction — Week 1 spike.

Everything here is pure string/structure analysis on the URL itself. No
network calls (no WHOIS, no TLS cert fetch, no redirect-following yet) —
those are Phase 2, once real threat-intel clients replace the stub in
app/threat_intel. Each finding is a small dict the scorer turns into
Evidence: {"signal", "detail", "points"}. Points are suspicion points,
0 = no concern.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from app.signals.brand_watchlist import closest_brand_match

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "work", "click", "gq", "tk", "cf", "ml",
    "country", "kim", "science", "party",
}

Finding = dict


def _is_ip_literal(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def extract_url_features(raw_url: str) -> List[Finding]:
    findings: List[Finding] = []

    url = raw_url.strip()
    if not url:
        return findings

    # Tolerate URLs pasted without a scheme.
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    scheme_present = "://" in url

    if not host:
        findings.append({
            "signal": "unparseable-url",
            "detail": f"Could not parse a host from '{raw_url}'",
            "points": 15,
        })
        return findings

    if scheme_present and parsed.scheme == "http":
        findings.append({
            "signal": "no-tls",
            "detail": "Link uses plain HTTP, not HTTPS",
            "points": 10,
        })

    if _is_ip_literal(host):
        findings.append({
            "signal": "ip-literal-host",
            "detail": f"Link points directly at an IP address ({host}) instead of a domain",
            "points": 25,
        })

    if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
        findings.append({
            "signal": "userinfo-in-url",
            "detail": "URL contains an '@' before the host — classic way to hide the real destination",
            "points": 30,
        })

    if host in SHORTENER_DOMAINS:
        findings.append({
            "signal": "url-shortener",
            "detail": f"Uses a link shortener ({host}) that hides the real destination until clicked",
            "points": 15,
        })

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append({
            "signal": "suspicious-tld",
            "detail": f"Uses a TLD ('.{tld}') disproportionately favoured by cheap, disposable phishing domains",
            "points": 10,
        })

    labels = host.split(".")
    subdomain_count = max(0, len(labels) - 2)
    if subdomain_count >= 3:
        findings.append({
            "signal": "excessive-subdomains",
            "detail": f"Host has {subdomain_count} subdomain levels ({host}) — often used to bury the real domain",
            "points": 10,
        })

    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        findings.append({
            "signal": "excessive-hyphens",
            "detail": f"Host contains {hyphen_count} hyphens ({host}) — common in generated phishing domains",
            "points": 8,
        })

    if len(host) > 40:
        findings.append({
            "signal": "long-host",
            "detail": f"Unusually long host name ({len(host)} characters)",
            "points": 5,
        })

    # Typosquat / brand-impersonation check against the watch-list.
    registrable_label = labels[-2] if len(labels) >= 2 else host
    match = closest_brand_match(registrable_label)
    if match:
        if match.distance == 0:
            findings.append({
                "signal": "brand-impersonation",
                "detail": f"Domain contains the brand name '{match.brand}' but isn't {match.brand}'s real domain",
                "points": 35,
            })
        else:
            findings.append({
                "signal": "typosquat",
                "detail": f"Domain '{registrable_label}' is a near-miss for '{match.brand}' (edit distance {match.distance})",
                "points": 30,
            })

    return findings
