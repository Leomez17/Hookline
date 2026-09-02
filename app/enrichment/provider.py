"""Builds the enrichment client set.

Both RDAP and TLS checks are gated behind a single ENABLE_LIVE_ENRICHMENT
flag, off by default. That's a different default from the threat-intel
sources in app/threat_intel/, which just skip themselves silently with no
key configured: those only ever talk to Google/VirusTotal/PhishTank.
Live enrichment, by contrast, actively connects out to whatever host a
user — or an attacker crafting the input — supplies, so it needs an
explicit opt-in rather than an implicit one. See tls_client.py's own SSRF
guard for the other half of that story.
"""
from __future__ import annotations

import os
from typing import List

from app.enrichment.base import EnrichmentClient
from app.enrichment.cache import CachedEnrichmentClient, TTLCache
from app.enrichment.rdap_client import RdapClient
from app.enrichment.tls_client import TlsClient

_cache = TTLCache()


def _live_enrichment_enabled() -> bool:
    return os.environ.get("ENABLE_LIVE_ENRICHMENT", "").strip().lower() in ("1", "true", "yes")


def build_enrichment_clients() -> List[EnrichmentClient]:
    enabled = _live_enrichment_enabled()
    raw_clients = [
        ("rdap", RdapClient(enabled=enabled)),
        ("tls", TlsClient(enabled=enabled)),
    ]
    return [CachedEnrichmentClient(client, name=name, cache=_cache) for name, client in raw_clients]
