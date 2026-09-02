"""RDAP domain-age lookup.

Uses rdap.org as a bootstrap/proxy — it resolves the right registry RDAP
server for any domain and hands back one normalised JSON response, so
Hookline never needs its own IANA bootstrap table. Unlike the TLS check
next to this file, this never opens a connection to the attacker-supplied
host directly: the only outbound call is to rdap.org itself, so there's no
SSRF surface here the way there is for the TLS probe.

A domain registered a handful of days ago is a meaningfully different
thing than one registered a decade ago — phishing infrastructure is
disposable and short-lived almost by definition. Age alone is a weak
signal in isolation (plenty of legitimate sites are new), which is why
it's a moderate number of points, not a verdict on its own.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

import requests

RDAP_URL = "https://rdap.org/domain/{domain}"
NEW_DOMAIN_DAYS = 30
NEWLY_REGISTERED_POINTS = 20


def _registrable_domain(url: str) -> Optional[str]:
    host = urlparse(url if "://" in url else f"http://{url}").hostname
    if not host:
        return None
    labels = host.lower().split(".")
    # Simplification: last two labels. Doesn't correctly handle multi-part
    # public suffixes like ".co.uk" (would need the Public Suffix List) —
    # a known gap, same spirit as the typosquat check's registrable-label
    # logic in app/signals/url_signals.py.
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _registration_date(rdap_json: dict) -> Optional[datetime]:
    for event in rdap_json.get("events", []):
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate")
            if raw:
                try:
                    return datetime.fromisoformat(raw.replace("Z", "+00:00"))
                except ValueError:
                    return None
    return None


class RdapClient:
    def __init__(self, enabled: bool = True, timeout: float = 5.0):
        self._enabled = enabled
        self._timeout = timeout

    def inspect(self, url: str) -> List[dict]:
        if not self._enabled:
            return [{
                "signal": "enrich:rdap:unavailable",
                "detail": "Live domain-age lookups are disabled (set ENABLE_LIVE_ENRICHMENT=true)",
                "points": 0,
            }]

        domain = _registrable_domain(url)
        if not domain:
            return []

        try:
            resp = requests.get(
                RDAP_URL.format(domain=domain),
                timeout=self._timeout,
                headers={"Accept": "application/rdap+json"},
            )
        except requests.RequestException as exc:
            return [{"signal": "enrich:rdap:unavailable", "detail": f"RDAP lookup for {domain} failed: {exc}", "points": 0}]

        if resp.status_code == 404:
            return [{"signal": "enrich:rdap:not-found", "detail": f"No RDAP record found for {domain}", "points": 0}]
        if resp.status_code != 200:
            return [{"signal": "enrich:rdap:unavailable", "detail": f"RDAP lookup for {domain} returned HTTP {resp.status_code}", "points": 0}]

        try:
            data = resp.json()
        except ValueError:
            return [{"signal": "enrich:rdap:unavailable", "detail": f"RDAP response for {domain} wasn't valid JSON", "points": 0}]

        registered_at = _registration_date(data)
        if registered_at is None:
            return [{"signal": "enrich:rdap:unknown-age", "detail": f"RDAP record for {domain} had no registration event", "points": 0}]

        age_days = (datetime.now(timezone.utc) - registered_at).days
        if age_days < NEW_DOMAIN_DAYS:
            return [{
                "signal": "enrich:newly-registered-domain",
                "detail": f"{domain} was registered {age_days} day(s) ago ({registered_at.date()}) — "
                          f"phishing domains are frequently used within days of registration",
                "points": NEWLY_REGISTERED_POINTS,
            }]
        return [{
            "signal": "enrich:established-domain",
            "detail": f"{domain} was registered {age_days} days ago ({registered_at.date()})",
            "points": 0,
        }]
