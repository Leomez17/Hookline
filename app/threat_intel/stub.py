"""Week 1 default: a threat-intel client that always says "couldn't check."

This keeps the app honest — it never fabricates a threat-intel hit — while
proving out the exact seam Phase 2 real clients (Safe Browsing, VirusTotal,
PhishTank) will plug into. See app/threat_intel/base.py.
"""
from __future__ import annotations

from app.threat_intel.base import ThreatIntelResult


class NullThreatIntelClient:
    def check_url(self, url: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            source="none (Week 1 spike — no threat-intel APIs wired up yet)",
            checked=False,
            is_known_malicious=False,
            detail="Live threat-intel lookups aren't wired up yet; verdict is based on local signals only",
        )
