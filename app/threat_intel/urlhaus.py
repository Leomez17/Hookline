"""URLhaus lookup (abuse.ch). Replaces PhishTank as Hookline's third
threat-intel source.

Why the swap: PhishTank closed new-user registration ("temporarily
disabled" as of September 2026), so no new API key could be issued.
URLhaus is free, community-run by abuse.ch, and actively maintained.

What URLhaus actually tracks: URLs *distributing malware* (payload
droppers, malicious downloads, compromised sites serving malware), not
credential-harvesting pages specifically. That still lines up with
Hookline's scope — malicious links and attachments in phishing email
(T1566.002 / T1566.001) — but a "not listed" result here means "not a
known malware-distribution URL", not "not a phishing page". The detail
string says exactly that so the evidence trail doesn't overclaim.

Requires URLHAUS_AUTH_KEY. abuse.ch requires an Auth-Key on all API
calls; get one free at https://auth.abuse.ch/ (sign in, then copy the
Auth-Key from your profile).
"""
from __future__ import annotations

from typing import Optional

import requests

from app.threat_intel.base import ThreatIntelResult

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
SOURCE = "URLhaus"
USER_AGENT = "hookline (+https://github.com/Leomez17/Hookline)"


class URLhausClient:
    def __init__(self, auth_key: Optional[str], timeout: float = 5.0):
        self._auth_key = auth_key
        self._timeout = timeout

    def check_url(self, url: str) -> ThreatIntelResult:
        if not self._auth_key:
            return ThreatIntelResult(
                source=SOURCE, checked=False, is_known_malicious=False,
                detail="No URLHAUS_AUTH_KEY configured",
            )

        headers = {"Auth-Key": self._auth_key, "User-Agent": USER_AGENT}
        try:
            resp = requests.post(API_URL, data={"url": url}, headers=headers, timeout=self._timeout)
        except requests.RequestException as exc:
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail=f"Request failed: {exc}")

        if resp.status_code in (401, 403):
            return ThreatIntelResult(
                source=SOURCE, checked=False, is_known_malicious=False,
                detail=f"Auth-Key rejected (HTTP {resp.status_code}) — check URLHAUS_AUTH_KEY",
            )
        if resp.status_code != 200:
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail=f"API error (HTTP {resp.status_code})")

        try:
            body = resp.json()
        except ValueError:
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail="Unreadable response from URLhaus")

        status = body.get("query_status")

        if status == "ok":
            threat = body.get("threat") or "malware_download"
            url_status = body.get("url_status") or "unknown"
            tags = body.get("tags") or []
            tag_text = f", tags: {', '.join(tags)}" if tags else ""
            ref = body.get("urlhaus_reference", "")
            ref_text = f" ({ref})" if ref else ""
            return ThreatIntelResult(
                source=SOURCE, checked=True, is_known_malicious=True,
                detail=f"Listed as {threat} (currently {url_status}{tag_text}){ref_text}",
            )

        if status == "no_results":
            return ThreatIntelResult(
                source=SOURCE, checked=True, is_known_malicious=False,
                detail="Not listed as a known malware-distribution URL",
            )

        if status == "invalid_url":
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail="URLhaus rejected the URL as invalid")

        # e.g. "unknown_auth_key" returned with HTTP 200, or anything new.
        return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail=f"Unexpected URLhaus status: {status}")
