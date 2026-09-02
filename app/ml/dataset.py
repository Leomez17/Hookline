"""The calibration set the Week 3 logistic-regression layer is trained on.

Be clear-eyed about what this is: a small, hand-curated set of realistic
signal *combinations* and how a reviewer would label them, not a corpus of
real captured phishing traffic. Hookline doesn't have access to a labeled
breach dataset, and pretending otherwise would go against everything the
evidence-trail design is trying to do. What this buys us is still real,
though — the rules engine assigns every signal a fixed point value by
hand (10 for this, 30 for that), and hand-tuned weights don't know that
"typosquat" and "reply-to-mismatch" together are far more damning than
either alone. Logistic regression, even trained on a small curated set,
learns that interaction. The model's job here is narrow and explainable
on purpose: given which named signals already fired, estimate how
confident a reviewer should be that they add up to phishing — not to
invent new signals of its own.

Every row is `{"features": [...], "label": 0 or 1}`, where each feature is
a bare signal name (see app/ml/features.py for how a live signal name gets
normalised down to this form). Retrain with `python scripts/train_model.py`
after editing this file — see that script for how weights.json is produced.
"""
from __future__ import annotations

from typing import List, TypedDict


class Example(TypedDict):
    features: List[str]
    label: int


DATASET: List[Example] = [
    # --- Nothing fired: the overwhelming common case -----------------------
    {"features": [], "label": 0},
    {"features": [], "label": 0},
    {"features": [], "label": 0},
    {"features": [], "label": 0},
    {"features": [], "label": 0},
    {"features": [], "label": 0},
    {"features": [], "label": 0},
    {"features": [], "label": 0},

    # --- One weak signal alone: individually common on legitimate sites ----
    {"features": ["no-tls"], "label": 0},
    {"features": ["no-tls"], "label": 0},
    {"features": ["suspicious-tld"], "label": 0},
    {"features": ["suspicious-tld"], "label": 0},
    {"features": ["excessive-subdomains"], "label": 0},
    {"features": ["excessive-subdomains"], "label": 0},
    {"features": ["excessive-hyphens"], "label": 0},
    {"features": ["long-host"], "label": 0},
    {"features": ["long-host"], "label": 0},
    {"features": ["enrich:tls:recently-issued-certificate"], "label": 0},
    {"features": ["enrich:tls:recently-issued-certificate"], "label": 0},
    {"features": ["urgency-language"], "label": 0},  # a single reminder email isn't a phish

    # --- Two weak signals together: starting to look deliberate ------------
    {"features": ["no-tls", "suspicious-tld"], "label": 1},
    {"features": ["excessive-hyphens", "suspicious-tld"], "label": 1},
    {"features": ["long-host", "excessive-subdomains"], "label": 0},  # still plausible on a large legit org
    {"features": ["no-tls", "long-host"], "label": 0},
    {"features": ["excessive-subdomains", "excessive-hyphens"], "label": 1},

    # --- One strong signal alone: rarely a false alarm ----------------------
    {"features": ["typosquat"], "label": 1},
    {"features": ["typosquat"], "label": 1},
    {"features": ["brand-impersonation"], "label": 1},
    {"features": ["brand-impersonation"], "label": 1},
    {"features": ["ip-literal-host"], "label": 1},
    {"features": ["userinfo-in-url"], "label": 1},
    {"features": ["userinfo-in-url"], "label": 1},
    {"features": ["url-shortener"], "label": 0},  # ubiquitous on legitimate social/marketing links too
    {"features": ["reply-to-mismatch"], "label": 1},
    {"features": ["display-name-spoofing"], "label": 1},
    {"features": ["display-name-spoofing"], "label": 1},
    {"features": ["spf-fail"], "label": 1},
    {"features": ["dmarc-fail"], "label": 1},
    {"features": ["dkim-fail"], "label": 0},  # DKIM alone fails surprisingly often on legit mail (relays, mailing lists)
    {"features": ["enrich:newly-registered-domain"], "label": 0},  # weak alone — plenty of new legit domains
    {"features": ["enrich:tls:expired-certificate"], "label": 0},  # often just neglect, not malice
    {"features": ["enrich:tls:handshake-failed"], "label": 0},

    # --- Strong + weak: the weak signal now reads as confirmation ----------
    {"features": ["typosquat", "no-tls"], "label": 1},
    {"features": ["typosquat", "suspicious-tld"], "label": 1},
    {"features": ["typosquat", "excessive-hyphens"], "label": 1},
    {"features": ["brand-impersonation", "no-tls"], "label": 1},
    {"features": ["brand-impersonation", "long-host"], "label": 1},
    {"features": ["reply-to-mismatch", "urgency-language"], "label": 1},
    {"features": ["display-name-spoofing", "urgency-language"], "label": 1},
    {"features": ["spf-fail", "dmarc-fail"], "label": 1},
    {"features": ["spf-fail", "dkim-fail", "dmarc-fail"], "label": 1},
    {"features": ["enrich:newly-registered-domain", "typosquat"], "label": 1},
    {"features": ["enrich:newly-registered-domain", "suspicious-tld"], "label": 1},
    {"features": ["enrich:tls:recently-issued-certificate", "typosquat"], "label": 1},
    {"features": ["enrich:tls:expired-certificate", "brand-impersonation"], "label": 1},

    # --- Two+ strong signals: high confidence -------------------------------
    {"features": ["typosquat", "reply-to-mismatch"], "label": 1},
    {"features": ["typosquat", "reply-to-mismatch", "urgency-language"], "label": 1},
    {"features": ["brand-impersonation", "display-name-spoofing"], "label": 1},
    {"features": ["brand-impersonation", "spf-fail", "dmarc-fail"], "label": 1},
    {"features": ["display-name-spoofing", "reply-to-mismatch", "urgency-language"], "label": 1},
    {"features": ["ip-literal-host", "userinfo-in-url"], "label": 1},
    {"features": ["typosquat", "urgency-language", "enrich:newly-registered-domain"], "label": 1},

    # --- Confirmed threat-intel hit: near-certain regardless of company ----
    {"features": ["ti-hit"], "label": 1},
    {"features": ["ti-hit"], "label": 1},
    {"features": ["ti-hit"], "label": 1},
    {"features": ["ti-hit", "typosquat"], "label": 1},
    {"features": ["ti-hit", "no-tls"], "label": 1},
    {"features": ["ti-hit", "urgency-language", "reply-to-mismatch"], "label": 1},
]
