from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from app.models import CheckType, Verdict
from app.scoring import run_check
from app.threat_intel.base import ThreatIntelResult

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"

# Every test below explicitly passes threat_intel_clients=[], enrichment_clients=[]
# and (where the case involves triggered signals) a fake ml_predict — so no test
# in this file depends on, or can accidentally hit, live network/API keys or the
# real trained model. Deterministic regardless of what's in the environment,
# what's in .env, or how app/ml/weights.json gets retrained later.


def test_phishing_email_scores_malicious():
    raw = (SAMPLE_DIR / "phishing_email_1.txt").read_text()
    result = run_check(CheckType.email, raw, threat_intel_clients=[], enrichment_clients=[])
    assert result.verdict == Verdict.malicious
    assert result.score >= 70
    assert "T1598" in result.mitre_techniques  # urgency / credential harvesting
    assert any(t.startswith("T1566") for t in result.mitre_techniques)


def test_legit_email_scores_safe():
    raw = (SAMPLE_DIR / "legit_email_1.txt").read_text()
    result = run_check(CheckType.email, raw, threat_intel_clients=[], enrichment_clients=[])
    assert result.verdict == Verdict.safe
    assert result.score == 0
    assert result.mitre_techniques == []


def test_clean_url_scores_safe():
    result = run_check(CheckType.url, "https://github.com/Leomez17", threat_intel_clients=[], enrichment_clients=[])
    assert result.verdict == Verdict.safe
    assert result.score == 0


def test_malicious_url_scores_high():
    result = run_check(CheckType.url, "https://paypa1-secure-login.top/verify", threat_intel_clients=[], enrichment_clients=[])
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
        enrichment_clients=[],
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
        enrichment_clients=[],
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

    run_check(CheckType.email, raw, threat_intel_clients=[RecordingClient()], enrichment_clients=[])
    assert len(calls) == 2  # capped, not 3


# --- Enrichment (Week 3): fake clients, no real network ---------------------

class _FakeEnrichmentClient:
    def __init__(self, findings):
        self._findings = findings

    def inspect(self, url):
        return self._findings


def test_enrichment_finding_is_scored_and_cited():
    finding = {"signal": "enrich:newly-registered-domain", "detail": "registered 2 days ago", "points": 20}
    result = run_check(
        CheckType.url,
        "https://totally-unremarkable-example.org",
        threat_intel_clients=[],
        enrichment_clients=[_FakeEnrichmentClient([finding])],
    )
    assert result.score == 20
    assert any(e.signal == "enrich:newly-registered-domain" for e in result.evidence)
    assert "T1566.002" in result.mitre_techniques  # enrich: signals count as link-related, same as ti:


def test_enrichment_disabled_by_default_is_noted_but_scoreless():
    # No enrichment_clients override — exercises the real provider, which
    # defaults ENABLE_LIVE_ENRICHMENT to off and so must make no network call.
    result = run_check(CheckType.url, "https://totally-unremarkable-example.org", threat_intel_clients=[])
    assert result.score == 0
    assert result.notes is not None
    assert "domain-age/TLS" in result.notes


def test_email_enrichment_capped_at_one_link():
    raw = (
        "From: someone@example.com\n"
        "Subject: links\n\n"
        "https://one.example.com https://two.example.com\n"
    )
    calls = []

    class RecordingClient:
        def inspect(self, url):
            calls.append(url)
            return []

    run_check(CheckType.email, raw, threat_intel_clients=[], enrichment_clients=[RecordingClient()])
    assert len(calls) == 1  # capped tighter than threat-intel's 2


# --- ML calibration layer (Week 3): fake predict function -------------------

def test_ml_layer_adds_high_confidence_points_for_combined_signals():
    result = run_check(
        CheckType.url,
        "https://paypa1-secure-login.top/verify",  # triggers typosquat + suspicious-tld locally
        threat_intel_clients=[],
        enrichment_clients=[],
        ml_predict=lambda features: 0.9,
    )
    assert any(e.signal == "ml:high-confidence" for e in result.evidence)
    ml_evidence = next(e for e in result.evidence if e.signal == "ml:high-confidence")
    assert ml_evidence.points == 25
    assert "90%" in ml_evidence.detail


def test_ml_layer_adds_moderate_confidence_points():
    result = run_check(
        CheckType.url,
        "https://paypa1-secure-login.top/verify",
        threat_intel_clients=[],
        enrichment_clients=[],
        ml_predict=lambda features: 0.7,
    )
    assert any(e.signal == "ml:moderate-confidence" for e in result.evidence)
    ml_evidence = next(e for e in result.evidence if e.signal == "ml:moderate-confidence")
    assert ml_evidence.points == 12


def test_ml_layer_contributes_nothing_below_moderate_threshold():
    result = run_check(
        CheckType.url,
        "https://paypa1-secure-login.top/verify",
        threat_intel_clients=[],
        enrichment_clients=[],
        ml_predict=lambda features: 0.1,
    )
    assert not any(e.signal.startswith("ml:") for e in result.evidence)


def test_ml_layer_skipped_entirely_with_no_positive_findings():
    calls = []

    def recording_predict(features):
        calls.append(features)
        return 0.99

    result = run_check(
        CheckType.url,
        "https://github.com/Leomez17",
        threat_intel_clients=[],
        enrichment_clients=[],
        ml_predict=recording_predict,
    )
    assert calls == []  # never invoked — nothing to calibrate on
    assert result.score == 0


# --- Attachment parsing (Week 4): earning T1566.001 honestly ----------------

def _email_with_dangerous_attachment() -> str:
    msg = MIMEMultipart()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Invoice attached"
    msg.attach(MIMEText("Please see the attached invoice.", "plain"))
    part = MIMEBase("application", "octet-stream")
    part.set_payload("placeholder, not a real executable")
    part.add_header("Content-Disposition", "attachment", filename="invoice.pdf.exe")
    msg.attach(part)
    return msg.as_string()


def test_dangerous_attachment_earns_t1566_001():
    result = run_check(
        CheckType.email,
        _email_with_dangerous_attachment(),
        threat_intel_clients=[],
        enrichment_clients=[],
    )
    assert "T1566.001" in result.mitre_techniques
    assert any(e.signal == "attachment-dangerous-extension" for e in result.evidence)
    assert any(e.signal == "attachment-double-extension" for e in result.evidence)
    assert result.score > 0


def test_no_attachment_never_claims_t1566_001():
    raw = (
        "From: someone@example.com\nSubject: hi\n\n"
        "Just a plain email with no attachment at all.\n"
    )
    result = run_check(CheckType.email, raw, threat_intel_clients=[], enrichment_clients=[])
    assert "T1566.001" not in result.mitre_techniques


def test_phishing_sample_still_never_claims_t1566_001():
    # phishing_email_1.txt has no MIME attachment parts — it should keep
    # scoring malicious on its existing signals without ever claiming an
    # attachment technique it didn't actually check for.
    raw = (SAMPLE_DIR / "phishing_email_1.txt").read_text()
    result = run_check(CheckType.email, raw, threat_intel_clients=[], enrichment_clients=[])
    assert "T1566.001" not in result.mitre_techniques


def test_ml_layer_normalises_link_prefixed_and_threat_intel_signal_names():
    """Feature keys passed to the predict function should already be
    normalised (link: stripped, per-source ti hits collapsed to ti-hit) —
    the model was trained on that normalised vocabulary, not the raw
    evidence-trail signal names."""
    seen = {}

    def recording_predict(features):
        seen["features"] = features
        return 0.0

    raw = (
        "From: PayPal Support <support@paypa1-secure-login.top>\n"
        "Subject: verify\n\n"
        "https://paypa1-secure-login.top/verify\n"
    )
    run_check(
        CheckType.email,
        raw,
        threat_intel_clients=[_FakeMaliciousClient(source="Safe Browsing")],
        enrichment_clients=[],
        ml_predict=recording_predict,
    )
    assert "typosquat" in seen["features"]  # not "link:typosquat"
    assert "ti-hit" in seen["features"]  # not "ti:safe-browsing:hit"
