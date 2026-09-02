"""The interface every enrichment source implements — same idea as
ThreatIntelClient (app/threat_intel/base.py), except an enrichment check
can surface more than one named finding per call (a TLS probe can flag
both "recently issued" and "expired" in the same handshake), so it
returns a list of findings directly instead of a single result object.
"""
from __future__ import annotations

from typing import List, Protocol

Finding = dict


class EnrichmentClient(Protocol):
    def inspect(self, url: str) -> List[Finding]:
        ...
