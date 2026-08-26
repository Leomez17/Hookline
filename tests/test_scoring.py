from pathlib import Path

from app.models import CheckType, Verdict
from app.scoring import run_check
from app.threat_intel.base import ThreatIntelResult

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"

# Local-rules tests explicitly pass threat_intel_clients=[] so they never
# depend on (or accidentally hit) live network/API keys — deterministic
# regardless of what's in the environment or a real .env file.


def test_phishing_email_scores_malicious():
    raw = (SAMPLE_DIR / "phishing_email_1.txt").read_text()
    result = run_check(CheckType.email, raw, threat_intel_clients=[])
    assert result.verdict == Verdict.malicious
    assert result.score >= 70
    assert "T1598" in result.mitre_techniques  # urgency / credential harvesting
    assert any(t.startswith("T1566") for t in result.mitre_techniques)


def test_legit_email_scores_safe():
    raw = (SAMPLE_DIR / "legit_email_1.txt").read_text()
    result = run_check(CheckType.email, raw, threat_intel_clients=[])
    assert result.verdict == Verdict.safe
    assert result.score == 0
    assert result.mitre_techniques == []


def test_clean_url_scores_safe():
    result = run_check(CheckType.url, "https://github.com/Leomez17", threat_intel_clients=[])
    assert result.verdict == Verdict.safe
    assert result.score == 0


def test_malicious_url_scores_high():
    result = run_check(CheckType.url, "https://paypa1-secure-login.top/verify", threat_intel_clients=[])
    assert result.score >= 30
    assert result.verdict in (Verdict.suspicious, Verdict.malicious)
    assert "T1566.002" in result.mitre_techniques


# --- Threat-intel integration (fake clients, no real network) --------------

class _FakeMaliciousClient:
    def __init__(self, source="Fake TI"):
        self._source = source

    def check_url(self, url):
        return ThreatIntelResult(source=self._source, checked=True, is_known_malicious=True, detail="known bad")


class _FakeUnconfiguredClient:
    def check_url(self, url):
        return ThreatIntelResult(source="Fake Unconfigured", checked=False, is_known_malicious=False, detail="No key configured")


def test_threat_intel_hit_boosts_score_and_is_cited():
    result = run_check(
        CheckType.url,
        "https://totally-unremarkable-example.org",
        threat_intel_clients=[_FakeMaliciousClient()],
    )
    assert result.score >= 45
    assert result.verdict in (Verdict.suspicious, Verdict.malicious)
    assert any("Fake TI" in e.detail for e in result.evidence)
    assert "T1566.002" in result.mitre_techniques


def test_unconfigured_threat_intel_is_noted_but_scoreless():
    result = run_check(
        CheckType.url,
        "https://totally-unremarkable-example.org",
        threat_intel_clients=[_FakeUnconfiguredClient()],
    )
    assert result.score == 0
    assert result.verdict == Verdict.safe
    assert result.notes is not None
    assert "API keys are configured" in result.notes


def test_email_threat_intel_capped_at_two_links():
    raw = (
        "From: someone@example.com\n"
        "Subject: links\n\n"
        "https://one.example.com https://two.example.com https://three.example.com\n"
    )
    calls = []

    class RecordingClient:
        def check_url(self, url):
            calls.append(url)
            return ThreatIntelResult(source="Recorder", checked=True, is_known_malicious=False, detail="ok")

    run_check(CheckType.email, raw, threat_intel_clients=[RecordingClient()])
    assert len(calls) == 2  # capped, not 3
