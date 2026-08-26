"""The interface every threat-intel source implements.

Week 1 ships only `NullThreatIntelClient` (app/threat_intel/stub.py), which
returns "no data" for everything so the app runs with zero API keys and zero
network calls. Phase 2 (see the concept brief) adds real clients for Google
Safe Browsing, VirusTotal, and PhishTank behind this exact same interface,
each reading its key from the environment — main.py won't need to change,
just which client it constructs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class ThreatIntelResult:
    source: str
    checked: bool          # False if the lookup couldn't be made (no key, no data, error)
    is_known_malicious: bool
    detail: str


class ThreatIntelClient(Protocol):
    def check_url(self, url: str) -> ThreatIntelResult:
        ...
