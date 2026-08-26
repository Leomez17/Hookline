from unittest.mock import MagicMock, patch

from app.threat_intel.base import ThreatIntelResult
from app.threat_intel.cache import CachedThreatIntelClient, TTLCache
from app.threat_intel.phishtank import PhishTankClient
from app.threat_intel.safe_browsing import SafeBrowsingClient
from app.threat_intel.virustotal import VirusTotalClient


# --- Safe Browsing ---------------------------------------------------

def test_safe_browsing_without_key_short_circuits():
    client = SafeBrowsingClient(api_key=None)
    with patch("app.threat_intel.safe_browsing.requests.post") as mock_post:
        result = client.check_url("http://example.com")
    mock_post.assert_not_called()
    assert result.checked is False


def test_safe_browsing_flags_match():
    client = SafeBrowsingClient(api_key="fake-key")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
    with patch("app.threat_intel.safe_browsing.requests.post", return_value=fake_resp):
        result = client.check_url("http://evil.example")
    assert result.checked is True
    assert result.is_known_malicious is True
    assert "SOCIAL_ENGINEERING" in result.detail


def test_safe_browsing_clean_response():
    client = SafeBrowsingClient(api_key="fake-key")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {}
    with patch("app.threat_intel.safe_browsing.requests.post", return_value=fake_resp):
        result = client.check_url("http://example.com")
    assert result.checked is True
    assert result.is_known_malicious is False


def test_safe_browsing_http_error():
    client = SafeBrowsingClient(api_key="fake-key")
    fake_resp = MagicMock(status_code=403)
    with patch("app.threat_intel.safe_browsing.requests.post", return_value=fake_resp):
        result = client.check_url("http://example.com")
    assert result.checked is False


# --- VirusTotal --------------------------------------------------------

def test_virustotal_without_key_short_circuits():
    client = VirusTotalClient(api_key=None)
    with patch("app.threat_intel.virustotal.requests.get") as mock_get:
        result = client.check_url("http://example.com")
    mock_get.assert_not_called()
    assert result.checked is False


def test_virustotal_not_previously_scanned():
    client = VirusTotalClient(api_key="fake-key")
    fake_resp = MagicMock(status_code=404)
    with patch("app.threat_intel.virustotal.requests.get", return_value=fake_resp):
        result = client.check_url("http://example.com")
    assert result.checked is True
    assert result.is_known_malicious is False


def test_virustotal_flags_malicious():
    client = VirusTotalClient(api_key="fake-key")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1}}}}
    with patch("app.threat_intel.virustotal.requests.get", return_value=fake_resp):
        result = client.check_url("http://evil.example")
    assert result.checked is True
    assert result.is_known_malicious is True


def test_virustotal_clean():
    client = VirusTotalClient(api_key="fake-key")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}
    with patch("app.threat_intel.virustotal.requests.get", return_value=fake_resp):
        result = client.check_url("http://example.com")
    assert result.is_known_malicious is False


# --- PhishTank -----------------------------------------------------------

def test_phishtank_without_key_short_circuits():
    client = PhishTankClient(api_key=None)
    with patch("app.threat_intel.phishtank.requests.post") as mock_post:
        result = client.check_url("http://example.com")
    mock_post.assert_not_called()
    assert result.checked is False


def test_phishtank_verified_phish():
    client = PhishTankClient(api_key="fake-key")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {"results": {"in_database": True, "valid": True, "phish_detail_page": "https://phishtank.net/x"}}
    with patch("app.threat_intel.phishtank.requests.post", return_value=fake_resp):
        result = client.check_url("http://evil.example")
    assert result.checked is True
    assert result.is_known_malicious is True


def test_phishtank_not_in_database():
    client = PhishTankClient(api_key="fake-key")
    fake_resp = MagicMock(status_code=200)
    fake_resp.json.return_value = {"results": {"in_database": False, "valid": False}}
    with patch("app.threat_intel.phishtank.requests.post", return_value=fake_resp):
        result = client.check_url("http://example.com")
    assert result.is_known_malicious is False


# --- Cache -----------------------------------------------------------------

def test_cache_avoids_second_call():
    calls = []

    class CountingClient:
        def check_url(self, url):
            calls.append(url)
            return ThreatIntelResult(source="test", checked=True, is_known_malicious=False, detail="ok")

    cache = TTLCache(ttl_seconds=60)
    wrapped = CachedThreatIntelClient(CountingClient(), name="test", cache=cache)

    wrapped.check_url("http://example.com")
    wrapped.check_url("http://example.com")

    assert len(calls) == 1


def test_cache_is_per_source():
    cache = TTLCache(ttl_seconds=60)

    class CountingClient:
        def __init__(self):
            self.calls = 0

        def check_url(self, url):
            self.calls += 1
            return ThreatIntelResult(source="test", checked=True, is_known_malicious=False, detail="ok")

    client_a = CountingClient()
    client_b = CountingClient()
    wrapped_a = CachedThreatIntelClient(client_a, name="source-a", cache=cache)
    wrapped_b = CachedThreatIntelClient(client_b, name="source-b", cache=cache)

    wrapped_a.check_url("http://example.com")
    wrapped_b.check_url("http://example.com")

    assert client_a.calls == 1
    assert client_b.calls == 1
