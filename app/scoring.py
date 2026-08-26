"""The scorer. Local rules stay fully explainable; threat-intel results
(Week 2) layer on top the same way — every point is still traceable to a
named signal in the evidence list, whether it came from a local heuristic
or an external source. The logistic-regression layer planned for Week 3
sits alongside both, not instead of them.
"""
from __future__ import annotations

from typing import List, Optional

from app.mitre import techniques_for
from app.models import CheckResponse, CheckType, Evidence, Verdict
from app.signals.email_signals import extract_email_features, extract_links
from app.signals.url_signals import extract_url_features
from app.threat_intel.base import ThreatIntelClient
from app.threat_intel.provider import build_threat_intel_clients

SAFE_MAX = 29
SUSPICIOUS_MAX = 69

THREAT_INTEL_HIT_POINTS = 45
THREAT_INTEL_LINK_CAP = 2  # cap threat-intel calls per email so one message can't fan out unbounded


def _verdict_for(score: int) -> Verdict:
    if score <= SAFE_MAX:
        return Verdict.safe
    if score <= SUSPICIOUS_MAX:
        return Verdict.suspicious
    return Verdict.malicious


def _normalize(url: str) -> str:
    return url if "://" in url else f"http://{url}"


def _slug(source: str) -> str:
    return source.lower().replace(" ", "-")


def _threat_intel_findings(clients: List[ThreatIntelClient], url: str) -> List[dict]:
    findings: List[dict] = []
    target = _normalize(url)
    for client in clients:
        result = client.check_url(target)
        slug = _slug(result.source)
        if not result.checked:
            findings.append({"signal": f"ti:{slug}:unavailable", "detail": f"{result.source}: {result.detail}", "points": 0})
        elif result.is_known_malicious:
            findings.append({"signal": f"ti:{slug}:hit", "detail": f"{result.source}: {result.detail}", "points": THREAT_INTEL_HIT_POINTS})
        else:
            findings.append({"signal": f"ti:{slug}:clean", "detail": f"{result.source}: {result.detail}", "points": 0})
    return findings


def run_check(
    check_type: CheckType,
    content: str,
    threat_intel_clients: Optional[List[ThreatIntelClient]] = None,
) -> CheckResponse:
    clients = threat_intel_clients if threat_intel_clients is not None else build_threat_intel_clients()

    if check_type == CheckType.url:
        findings = extract_url_features(content)
        if content.strip():
            findings += _threat_intel_findings(clients, content.strip())
    else:
        findings = extract_email_features(content)
        for link in extract_links(content, limit=THREAT_INTEL_LINK_CAP):
            findings += _threat_intel_findings(clients, link)

    score = min(100, sum(f["points"] for f in findings))
    verdict = _verdict_for(score)

    evidence: List[Evidence] = [
        Evidence(signal=f["signal"], detail=f["detail"], points=f["points"])
        for f in findings
    ]
    evidence.sort(key=lambda e: e.points, reverse=True)

    signal_names = [f["signal"] for f in findings if f["points"] > 0]
    mitre = techniques_for(check_type, signal_names, score)

    positive_findings = [f for f in findings if f["points"] > 0]
    ti_findings = [f for f in findings if f["signal"].startswith("ti:")]
    ti_all_unconfigured = bool(ti_findings) and all(f["signal"].endswith(":unavailable") for f in ti_findings)

    notes_parts: List[str] = []
    if not positive_findings:
        notes_parts.append("No signals triggered — that means nothing checked looked wrong, not a guarantee of safety.")
    if ti_all_unconfigured:
        notes_parts.append("No threat-intel API keys are configured yet (see .env.example) — those checks were skipped.")
    notes = " ".join(notes_parts) or None

    return CheckResponse(
        verdict=verdict,
        score=score,
        evidence=evidence,
        mitre_techniques=mitre,
        notes=notes,
    )
