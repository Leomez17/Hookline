"""VirusTotal v3 URL lookup.

Reads an existing report only — never submits a new scan. Submitting
burns free-tier quota fast and needs a poll-for-completion step, which is
out of scope for Week 2. If VirusTotal has never seen the URL before,
that's reported as "not previously scanned," not as an error.

Requires VIRUSTOTAL_API_KEY. Sign up at
https://www.virustotal.com/gui/join-us, then copy your key from
https://www.virustotal.com/gui/my-apikey
"""
from __future__ import annotations

import base64
from typing import Optional

import requests

from app.threat_intel.base import ThreatIntelResult

API_URL = "https://www.virustotal.com/api/v3/urls/{id}"
SOURCE = "VirusTotal"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VirusTotalClient:
    def __init__(self, api_key: Optional[str], timeout: float = 5.0):
        self._api_key = api_key
        self._timeout = timeout

    def check_url(self, url: str) -> ThreatIntelResult:
        if not self._api_key:
            return ThreatIntelResult(
                source=SOURCE, checked=False, is_known_malicious=False,
                detail="No VIRUSTOTAL_API_KEY configured",
            )

        endpoint = API_URL.format(id=_url_id(url))
        try:
            resp = requests.get(endpoint, headers={"x-apikey": self._api_key}, timeout=self._timeout)
        except requests.RequestException as exc:
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail=f"Request failed: {exc}")

        if resp.status_code == 404:
            return ThreatIntelResult(source=SOURCE, checked=True, is_known_malicious=False, detail="Not previously scanned by VirusTotal")

        if resp.status_code != 200:
            return ThreatIntelResult(source=SOURCE, checked=False, is_known_malicious=False, detail=f"API error (HTTP {resp.status_code})")

        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0 or suspicious > 0:
            return ThreatIntelResult(
                source=SOURCE, checked=True, is_known_malicious=True,
                detail=f"{malicious} engines flagged malicious, {suspicious} suspicious",
            )
        return ThreatIntelResult(source=SOURCE, checked=True, is_known_malicious=False, detail="No engines flagged this URL")
