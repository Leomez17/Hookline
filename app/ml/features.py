"""Signal-name → ML feature-key normalisation.

Shared by the training data (app/ml/dataset.py, via scripts/train_model.py)
and the live scorer (app/scoring.py) so both sides agree on what counts as
"the same feature". Two normalisations happen: a link-scoped finding found
inside an email body is prefixed "link:" by app/signals/email_signals.py
(e.g. "link:typosquat") and needs that prefix stripped to match the bare
feature the model was trained on; and a threat-intel hit from any of the
three sources ("ti:safe-browsing:hit", "ti:virustotal:hit",
"ti:phishtank:hit") collapses to one shared "ti-hit" feature, because for
calibration purposes a confirmed hit from any one source carries the same
weight — there isn't enough labeled data to justify three separate
per-source coefficients.
"""
from __future__ import annotations


def feature_key(signal_name: str) -> str:
    if signal_name.startswith("link:"):
        signal_name = signal_name.split("link:", 1)[1]
    if signal_name.startswith("ti:") and signal_name.endswith(":hit"):
        return "ti-hit"
    return signal_name
