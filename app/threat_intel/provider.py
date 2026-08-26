"""Builds the set of threat-intel clients a run will use.

Each real client already degrades gracefully with no key configured (see
their check_url — it short-circuits without a network call), so this just
constructs all three and wraps them with the shared TTL cache. Add a
fourth source later by adding one line here — nothing else changes.
"""
from __future__ import annotations

import os
from typing import List

from app.threat_intel.base import ThreatIntelClient
from app.threat_intel.cache import CachedThreatIntelClient, TTLCache
from app.threat_intel.phishtank import PhishTankClient
from app.threat_intel.safe_browsing import SafeBrowsingClient
from app.threat_intel.virustotal import VirusTotalClient

_cache = TTLCache()


def build_threat_intel_clients() -> List[ThreatIntelClient]:
    raw_clients = [
        ("safe-browsing", SafeBrowsingClient(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"))),
        ("virustotal", VirusTotalClient(os.environ.get("VIRUSTOTAL_API_KEY"))),
        ("phishtank", PhishTankClient(os.environ.get("PHISHTANK_API_KEY"))),
    ]
    return [CachedThreatIntelClient(client, name=name, cache=_cache) for name, client in raw_clients]
