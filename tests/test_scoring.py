from pathlib import Path

from app.models import CheckType, Verdict
from app.scoring import run_check

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"


def test_phishing_email_scores_malicious():
    raw = (SAMPLE_DIR / "phishing_email_1.txt").read_text()
    result = run_check(CheckType.email, raw)
    assert result.verdict == Verdict.malicious
    assert result.score >= 70
    assert "T1598" in result.mitre_techniques  # urgency / credential harvesting
    assert any(t.startswith("T1566") for t in result.mitre_techniques)


def test_legit_email_scores_safe():
    raw = (SAMPLE_DIR / "legit_email_1.txt").read_text()
    result = run_check(CheckType.email, raw)
    assert result.verdict == Verdict.safe
    assert result.score == 0
    assert result.mitre_techniques == []


def test_clean_url_scores_safe():
    result = run_check(CheckType.url, "https://github.com/Leomez17")
    assert result.verdict == Verdict.safe
    assert result.score == 0


def test_malicious_url_scores_high():
    result = run_check(CheckType.url, "https://paypa1-secure-login.top/verify")
    assert result.score >= 30
    assert result.verdict in (Verdict.suspicious, Verdict.malicious)
    assert "T1566.002" in result.mitre_techniques
