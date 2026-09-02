"""TTL cache for enrichment findings — same shape and TTL as
app/threat_intel/cache.py, kept as a separate small implementation rather
than shared because an enrichment client returns a *list* of findings per
call, not a single result object. Same "swap for Redis/SQLite once this
is a long-lived service" note applies.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

from app.enrichment.base import EnrichmentClient, Finding

DEFAULT_TTL_SECONDS = 24 * 60 * 60


class TTLCache:
    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._ttl = ttl_seconds
        self._store: Dict[Tuple[str, str], Tuple[float, List[Finding]]] = {}

    def get(self, namespace: str, key: str) -> Optional[List[Finding]]:
        entry = self._store.get((namespace, key))
        if entry is None:
            return None
        expires_at, value = entry
        if time.time() >= expires_at:
            del self._store[(namespace, key)]
            return None
        return value

    def set(self, namespace: str, key: str, value: List[Finding]) -> None:
        self._store[(namespace, key)] = (time.time() + self._ttl, value)


class CachedEnrichmentClient:
    """Wraps an EnrichmentClient so repeated lookups for the same URL,
    within the TTL, don't re-probe the target (or re-spend an RDAP/TLS
    round trip for no reason)."""

    def __init__(self, client: EnrichmentClient, name: str, cache: TTLCache):
        self._client = client
        self._name = name
        self._cache = cache

    def inspect(self, url: str) -> List[Finding]:
        cached = self._cache.get(self._name, url)
        if cached is not None:
            return cached
        result = self._client.inspect(url)
        self._cache.set(self._name, url, result)
        return result
