"""The scorer. Local rules stay fully explainable; threat-intel results
(Week 2) and live enrichment + a logistic-regression calibration layer
(Week 3) all layer on top the same way — every point on the score, no
matter which stage produced it, is still traceable to a named signal in
the evidence list. Nothing here replaces the rules engine; it's additive
findings sources feeding the same additive score.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from app.enrichment.base import EnrichmentClient
from app.enrichment.provider import build_enrichment_clients
from app.ml import model as ml_model
from app.ml.features import feature_key
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

ENRICHMENT_LINK_CAP = 1  # RDAP + TLS is two live round trips per target — even tighter cap than threat-intel

ML_MODERATE_CONFIDENCE = 0.65
ML_HIGH_CONFIDENCE = 0.85
ML_MODERATE_POINTS = 12
ML_HIGH_POINTS = 25

PredictFn = Callable[[List[str]], float]


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


def _enrichment_findings(clients: List[EnrichmentClient], url: str) -> List[dict]:
    findings: List[dict] = []
    target = _normalize(url)
    for client in clients:
        findings += client.inspect(target)
    return findings


def _ml_findings(positive_signal_names: List[str], predict: PredictFn) -> List[dict]:
    """Additive calibration on top of whatever local/TI/enrichment signals
    already fired — mirrors _threat_intel_findings and _enrichment_findings
    in shape: a bolt-on findings source, never a replacement score. Skipped
    entirely if nothing else fired, so it never manufactures an opinion
    from zero evidence."""
    if not positive_signal_names:
        return []

    triggered = sorted({feature_key(name) for name in positive_signal_names})
    probability = predict(triggered)
    detail_suffix = f"from this signal combination ({', '.join(triggered)})"

    if probability >= ML_HIGH_CONFIDENCE:
        return [{
            "signal": "ml:high-confidence",
            "detail": f"Logistic regression model (trained offline — see app/ml/) estimates a {probability:.0%} phishing probability {detail_suffix}",
            "points": ML_HIGH_POINTS,
        }]
    if probability >= ML_MODERATE_CONFIDENCE:
        return [{
            "signal": "ml:moderate-confidence",
            "detail": f"Logistic regression model estimates a {probability:.0%} phishing probability {detail_suffix}",
            "points": ML_MODERATE_POINTS,
        }]
    return []


def run_check(
    check_type: CheckType,
    content: str,
    threat_intel_clients: Optional[List[ThreatIntelClient]] = None,
    enrichment_clients: Optional[List[EnrichmentClient]] = None,
    ml_predict: Optional[PredictFn] = None,
) -> CheckResponse:
    clients = threat_intel_clients if threat_intel_clients is not None else build_threat_intel_clients()
    enrichers = enrichment_clients if enrichment_clients is not None else build_enrichment_clients()
    predict = ml_predict if ml_predict is not None else ml_model.predict_proba

    if check_type == CheckType.url:
        findings = extract_url_features(content)
        if content.strip():
            findings += _threat_intel_findings(clients, content.strip())
            findings += _enrichment_findings(enrichers, content.strip())
    else:
        findings = extract_email_features(content)
        for link in extract_links(content, limit=THREAT_INTEL_LINK_CAP):
            findings += _threat_intel_findings(clients, link)
        for link in extract_links(content, limit=ENRICHMENT_LINK_CAP):
            findings += _enrichment_findings(enrichers, link)

    # ML calibration runs last and sees everything gathered so far, but
    # never itself feeds back into further stages.
    positive_signal_names = [f["signal"] for f in findings if f["points"] > 0]
    findings += _ml_findings(positive_signal_names, predict)

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
    enrich_findings = [f for f in findings if f["signal"].startswith("enrich:")]
    enrich_all_disabled = bool(enrich_findings) and all(f["signal"].endswith(":unavailable") for f in enrich_findings)

    notes_parts: List[str] = []
    if not positive_findings:
        notes_parts.append("No signals triggered — that means nothing checked looked wrong, not a guarantee of safety.")
    if ti_all_unconfigured:
        notes_parts.append("No threat-intel API keys are configured yet (see .env.example) — those checks were skipped.")
    if enrich_all_disabled:
        notes_parts.append("Live domain-age/TLS checks are disabled by default (set ENABLE_LIVE_ENRICHMENT=true in .env) — those checks were skipped.")
    notes = " ".join(notes_parts) or None

    return CheckResponse(
        verdict=verdict,
        score=score,
        evidence=evidence,
        mitre_techniques=mitre,
        notes=notes,
    )
