"""Google Safe Browsing v4 lookup.

No cost, but licensed for non-commercial use only — fine for a portfolio
build, worth revisiting (Web Risk is the commercial equivalent) if this
ever monetises. See the concept brief.

Requires GOOGLE_SAFE_BROWSING_API_KEY. Get one by enabling the "Safe
Browsing API" on a project at https://console.cloud.google.com/ and
creating an API key — full walkthrough at
https://developers.google.com/safe-browsing/v4/get-started
"""
from __future__ import annotations

from typing import Optional

import requests

from app.threat_intel.base import ThreatIntelResult

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SOURCE = "Google Safe Browsing"

THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


class SafeBrowsingClient:
    def __init__(self, api_key: Optional[str], timeout: float = 5.0):
        self._api_key = api_key
        self._timeout = timeout

    def check_url(self, url: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(
                source=SOURCE, checked=False, is_known_malicious=False,
                detail="No GOOGLE_SAFE_BROWSING_API_KEY configured",
            )

        body = {
            "client": {"clientId": "hookline", "clientVersion": "0.2.0"},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            resp = requests.post(API_URL, params={"key": self._api_key}, json=body, timeout=self._timeout)
        except requests.RequestException as exc:
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail=f"Request failed: {exc}")

        if resp.status_code != 200:
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail=f"API error (HTTP {resp.status_code})")

        matches = resp.json().get("matches", [])
        if matches:
            threat_types = ", ".join(sorted({m.get("threatType", "UNKNOWN") for m in matches}))
            return ThreatIntelResult(source=SOURCE, checked=True, is_known_malicious=True, detail=f"Listed for: {threat_types}")
        return ThreatIntelResult(source=SOURCE, checked=True, is_known_malicious=False, detail="Not listed as unsafe")
