"""PhishTank verified-phish lookup. Maintained by Cisco Talos.

Gated behind PHISHTANK_API_KEY even though PhishTank's API technically
allows keyless use (just at a stricter rate limit) — kept consistent with
the other two clients so nothing calls out to a third party until you've
deliberately opted in.

Sign up and generate an app key at https://phishtank.net (Developer
Info page, after registering).
"""
from __future__ import annotations

from typing import Optional

import requests

from app.threat_intel.base import ThreatIntelResult

API_URL = "https://checkurl.phishtank.com/checkurl/"
SOURCE = "PhishTank"
USER_AGENT = "phishtank/hookline"  # PhishTank requires a descriptive User-Agent, or risks extra throttling


class PhishTankClient:
    def __init__(self, api_key: Optional[str], timeout: float = 5.0):
        self._api_key = api_key
        self._timeout = timeout

    def check_url(self, url: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(
                source=SOURCE, checked=False, is_known_malicious=False,
                detail="No PHISHTANK_API_KEY configured",
            )

        data = {"url": url, "format": "json", "app_key": self._api_key}
        try:
            resp = requests.post(API_URL, data=data, headers={"User-Agent": USER_AGENT}, timeout=self._timeout)
        except requests.RequestException as exc:
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail=f"Request failed: {exc}")

        if resp.status_code != 200:
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail=f"API error (HTTP {resp.status_code})")

        results = resp.json().get("results", {})
        in_db = results.get("in_database", False)
        valid = results.get("valid", False)
        if in_db and valid:
            page = results.get("phish_detail_page", "")
            return ThreatIntelResult(source=SOURCE, checked=True, is_known_malicious=True, detail=f"Verified phish in PhishTank's database ({page})")
        return ThreatIntelResult(source=SOURCE, checked=True, is_known_malicious=False, detail="Not found in PhishTank's verified database")
