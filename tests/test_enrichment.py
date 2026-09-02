"""Enrichment client tests. Every live call (RDAP's requests.get, TLS's
socket/ssl calls) is mocked or exercised against loopback — nothing here
makes a real outbound network call, same rule as tests/test_threat_intel.py.
"""
from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

from app.enrichment.rdap_client import RdapClient, _registrable_domain
from app.enrichment.tls_client import TlsClient, _is_safe_ip
from app.enrichment.cache import CachedEnrichmentClient, TTLCache


# --- RDAP --------------------------------------------------------------

def test_rdap_disabled_by_default_makes_no_network_call():
    client = RdapClient(enabled=False)
    with patch("app.enrichment.rdap_client.requests.get") as mock_get:
        findings = client.inspect("https://example.com")
    mock_get.assert_not_called()
    assert findings == [{
        "signal": "enrich:rdap:unavailable",
        "detail": "Live domain-age lookups are disabled (set ENABLE_LIVE_ENRICHMENT=true)",
        "points": 0,
    }]


def test_rdap_flags_newly_registered_domain():
    from datetime import datetime, timedelta, timezone
    registered = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"events": [{"eventAction": "registration", "eventDate": registered}]}
    with patch("app.enrichment.rdap_client.requests.get", return_value=mock_resp):
        findings = RdapClient(enabled=True).inspect("https://freshly-registered-example.top")
    assert len(findings) == 1
    assert findings[0]["signal"] == "enrich:newly-registered-domain"
    assert findings[0]["points"] == 20


def test_rdap_established_domain_scores_zero():
    from datetime import datetime, timedelta, timezone
    registered = (datetime.now(timezone.utc) - timedelta(days=3650)).isoformat()
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"events": [{"eventAction": "registration", "eventDate": registered}]}
    with patch("app.enrichment.rdap_client.requests.get", return_value=mock_resp):
        findings = RdapClient(enabled=True).inspect("https://old-established-example.com")
    assert findings[0]["signal"] == "enrich:established-domain"
    assert findings[0]["points"] == 0


def test_rdap_not_found_is_scoreless():
    mock_resp = MagicMock(status_code=404)
    with patch("app.enrichment.rdap_client.requests.get", return_value=mock_resp):
        findings = RdapClient(enabled=True).inspect("https://no-such-record-example.zzz")
    assert findings[0]["signal"] == "enrich:rdap:not-found"
    assert findings[0]["points"] == 0


def test_rdap_request_failure_degrades_gracefully():
    import requests
    with patch("app.enrichment.rdap_client.requests.get", side_effect=requests.RequestException("timeout")):
        findings = RdapClient(enabled=True).inspect("https://example.com")
    assert findings[0]["signal"] == "enrich:rdap:unavailable"
    assert findings[0]["points"] == 0


def test_registrable_domain_strips_subdomains():
    assert _registrable_domain("https://mail.example.com/path") == "example.com"
    assert _registrable_domain("") is None


# --- TLS -----------------------------------------------------------------

def test_tls_disabled_by_default_makes_no_network_call():
    client = TlsClient(enabled=False)
    with patch("app.enrichment.tls_client.socket.getaddrinfo") as mock_resolve:
        findings = client.inspect("https://example.com")
    mock_resolve.assert_not_called()
    assert findings == [{
        "signal": "enrich:tls:unavailable",
        "detail": "Live TLS certificate checks are disabled (set ENABLE_LIVE_ENRICHMENT=true)",
        "points": 0,
    }]


def test_tls_refuses_private_address_ssrf_guard():
    # example.com resolving only to a loopback/private address is exactly
    # the DNS-rebinding shape this guard exists to stop.
    fake_infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    with patch("app.enrichment.tls_client.socket.getaddrinfo", return_value=fake_infos):
        with patch("app.enrichment.tls_client.socket.create_connection") as mock_connect:
            findings = TlsClient(enabled=True).inspect("https://internal-service.example")
    mock_connect.assert_not_called()
    assert findings[0]["signal"] == "enrich:tls:refused-private-address"
    assert findings[0]["points"] == 0


def test_is_safe_ip_rejects_private_and_loopback_ranges():
    assert _is_safe_ip("8.8.8.8") is True
    assert _is_safe_ip("127.0.0.1") is False
    assert _is_safe_ip("10.0.0.5") is False
    assert _is_safe_ip("169.254.1.1") is False
    assert _is_safe_ip("::1") is False
    assert _is_safe_ip("not-an-ip") is False


def test_tls_handshake_failure_is_scored():
    fake_infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    with patch("app.enrichment.tls_client.socket.getaddrinfo", return_value=fake_infos):
        with patch("app.enrichment.tls_client.socket.create_connection", side_effect=OSError("connection refused")):
            findings = TlsClient(enabled=True).inspect("https://unreachable-example.com")
    assert findings[0]["signal"] == "enrich:tls:handshake-failed"
    assert findings[0]["points"] == 15


# --- Cache -----------------------------------------------------------------

def test_cached_enrichment_client_only_calls_once_within_ttl():
    calls = []

    class RecordingClient:
        def inspect(self, url):
            calls.append(url)
            return [{"signal": "enrich:test", "detail": "x", "points": 0}]

    cache = TTLCache(ttl_seconds=3600)
    wrapped = CachedEnrichmentClient(RecordingClient(), name="test", cache=cache)
    wrapped.inspect("https://example.com")
    wrapped.inspect("https://example.com")
    assert len(calls) == 1
