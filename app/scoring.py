"""The rules-based scorer. Deliberately simple and fully explainable —
every point is traceable to a named signal. The logistic-regression layer
planned for Week 3 sits alongside this, not instead of it: rules stay as a
transparent floor even once a model is added.
"""
from __future__ import annotations

from typing import List

from app.mitre import techniques_for
from app.models import CheckResponse, CheckType, Evidence, Verdict
from app.signals.email_signals import extract_email_features
from app.signals.url_signals import extract_url_features

SAFE_MAX = 29
SUSPICIOUS_MAX = 69


def _verdict_for(score: int) -> Verdict:
    if score <= SAFE_MAX:
        return Verdict.safe
    if score <= SUSPICIOUS_MAX:
        return Verdict.suspicious
    return Verdict.malicious


def run_check(check_type: CheckType, content: str) -> CheckResponse:
    if check_type == CheckType.url:
        findings = extract_url_features(content)
    else:
        findings = extract_email_features(content)

    score = min(100, sum(f["points"] for f in findings))
    verdict = _verdict_for(score)

    evidence: List[Evidence] = [
        Evidence(signal=f["signal"], detail=f["detail"], points=f["points"])
        for f in findings
    ]
    # Surface the strongest signals first.
    evidence.sort(key=lambda e: e.points, reverse=True)

    signal_names = [f["signal"] for f in findings if f["points"] > 0]
    mitre = techniques_for(check_type, signal_names, score)

    notes = None
    if not findings:
        notes = "No signals triggered — that means nothing on the local checklist looked wrong, not a guarantee of safety."
    elif score > 0:
        notes = "Verdict is based on local rules only; live threat-intel lookups (VirusTotal, Safe Browsing, PhishTank) are stubbed in this Week 1 build."

    return CheckResponse(
        verdict=verdict,
        score=score,
        evidence=evidence,
        mitre_techniques=mitre,
        notes=notes,
    )
