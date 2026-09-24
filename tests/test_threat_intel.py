from unittest.mock import MagicMock, patch

from app.threat_intel.base import ThreatIntelResult
from app.threat_intel.cache import CachedThreatIntelClient, TTLCache
from app.threat_intel.safe_browsing import SafeBrowsingClient
from app.threat_intel.urlhaus import URLhausClient
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


# --- URLhaus (replaced PhishTank) -----------------------------------------

def _urlhaus_resp(status_code=200, body=None):
    resp = MagicMock(status_code=status_code)
    resp.json.return_value = body or {}
    return resp


def test_urlhaus_without_key_short_circuits():
    client = URLhausClient(auth_key=None)
    with patch("app.threat_intel.urlhaus.requests.post") as mock_post:
        result = client.check_url("http://example.com")
    mock_post.assert_not_called()
    assert result.checked is False
    assert "URLHAUS_AUTH_KEY" in result.detail


def test_urlhaus_sends_auth_key_header_and_url():
    client = URLhausClient(auth_key="fake-key")
    resp = _urlhaus_resp(body={"query_status": "no_results"})
    with patch("app.threat_intel.urlhaus.requests.post", return_value=resp) as mock_post:
        client.check_url("http://example.com/x")
    _, kwargs = mock_post.call_args
    assert kwargs["headers"]["Auth-Key"] == "fake-key"
    assert kwargs["data"] == {"url": "http://example.com/x"}


def test_urlhaus_listed_url_is_a_hit():
    client = URLhausClient(auth_key="fake-key")
    resp = _urlhaus_resp(body={
        "query_status": "ok",
        "threat": "malware_download",
        "url_status": "online",
        "tags": ["elf", "mozi"],
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
    })
    with patch("app.threat_intel.urlhaus.requests.post", return_value=resp):
        result = client.check_url("http://evil.example/bin")
    assert result.checked is True
    assert result.is_known_malicious is True
    assert "malware_download" in result.detail
    assert "online" in result.detail
    assert "mozi" in result.detail


def test_urlhaus_no_results_is_clean():
    client = URLhausClient(auth_key="fake-key")
    resp = _urlhaus_resp(body={"query_status": "no_results"})
    with patch("app.threat_intel.urlhaus.requests.post", return_value=resp):
        result = client.check_url("http://example.com")
    assert result.checked is True
    assert result.is_known_malicious is False


def test_urlhaus_rejected_key_is_unavailable_not_clean():
    client = URLhausClient(auth_key="wrong-key")
    with patch("app.threat_intel.urlhaus.requests.post", return_value=_urlhaus_resp(status_code=401)):
        result = client.check_url("http://example.com")
    assert result.checked is False
    assert "Auth-Key rejected" in result.detail


def test_urlhaus_unexpected_status_is_unavailable_not_clean():
    client = URLhausClient(auth_key="fake-key")
    resp = _urlhaus_resp(body={"query_status": "unknown_auth_key"})
    with patch("app.threat_intel.urlhaus.requests.post", return_value=resp):
        result = client.check_url("http://example.com")
    assert result.checked is False


def test_urlhaus_network_error_is_unavailable():
    import requests
    client = URLhausClient(auth_key="fake-key")
    with patch("app.threat_intel.urlhaus.requests.post", side_effect=requests.ConnectionError("boom")):
        result = client.check_url("http://example.com")
    assert result.checked is False
    assert "Request failed" in result.detail


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
