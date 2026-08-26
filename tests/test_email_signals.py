from pathlib import Path

from app.signals.email_signals import extract_email_features

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"


def signal_names(findings):
    return {f["signal"] for f in findings}


def test_phishing_sample_trips_multiple_signals():
    raw = (SAMPLE_DIR / "phishing_email_1.txt").read_text()
    findings = extract_email_features(raw)
    names = signal_names(findings)

    assert "reply-to-mismatch" in names
    assert "urgency-language" in names
    assert "spf-fail" in names
    assert "dkim-fail" in names
    assert "dmarc-fail" in names
    # The linked URL's own signals should be pulled in too, prefixed.
    assert any(n.startswith("link:") for n in names)


def test_legit_sample_stays_quiet():
    raw = (SAMPLE_DIR / "legit_email_1.txt").read_text()
    findings = extract_email_features(raw)
    total_points = sum(f["points"] for f in findings)
    assert total_points == 0


def test_no_auth_results_noted_but_zero_points():
    raw = (
        "From: A Friend <friend@example.com>\n"
        "Subject: Hey\n\n"
        "Just checking in, no rush."
    )
    findings = extract_email_features(raw)
    names = signal_names(findings)
    assert "no-auth-results" in names
    assert sum(f["points"] for f in findings) == 0
