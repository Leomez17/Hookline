"""A tiny in-memory TTL cache, plus a wrapper that adds caching to any
ThreatIntelClient.

Deliberately not persistent across restarts — fine for a dev server, and
in scope for Week 2. Once this runs as a long-lived service rather than
`uvicorn --reload`, swap the in-memory dict for SQLite or Redis; nothing
above this layer needs to change.
"""
from __future__ import annotations

import time
from typing import Dict, Optional, Tuple

from app.threat_intel.base import ThreatIntelClient, ThreatIntelResult

DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24h — matches the caching guidance in the concept brief


class TTLCache:
    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._ttl = ttl_seconds
        self._store: Dict[Tuple[str, str], Tuple[float, ThreatIntelResult]] = {}

    def get(self, namespace: str, key: str) -> Optional[ThreatIntelResult]:
        entry = self._store.get((namespace, key))
        if entry is None:
            return None
        expires_at, value = entry
        if time.time() >= expires_at:
            del self._store[(namespace, key)]
            return None
        return value

    def set(self, namespace: str, key: str, value: ThreatIntelResult) -> None:
        self._store[(namespace, key)] = (time.time() + self._ttl, value)


class CachedThreatIntelClient:
    """Wraps a ThreatIntelClient so repeated lookups for the same URL,
    within the TTL, don't spend API quota."""

    def __init__(self, client: ThreatIntelClient, name: str, cache: TTLCache):
        self._client = client
        self._name = name
        self._cache = cache

    def check_url(self, url: str) -> ThreatIntelResult:
        cached = self._cache.get(self._name, url)
        if cached is not None:
            return cached
        result = self._client.check_url(url)
        self._cache.set(self._name, url, result)
        return result
