"""Tests for the pure-Python inference side of the ML layer
(app/ml/model.py, app/ml/features.py) — not the training script, which
needs scikit-learn and isn't a runtime dependency. These exercise the
weights.json actually committed to the repo, so they'll need a small
tolerance if the model is ever retrained on an updated dataset.
"""
from __future__ import annotations

from app.ml import model
from app.ml.features import feature_key


def test_no_ml_library_import_at_runtime():
    # model.py must not import sklearn — regenerating weights.json is a
    # dev-time step (scripts/train_model.py), never a runtime dependency.
    import ast
    import inspect
    source = inspect.getsource(model)
    tree = ast.parse(source)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert "sklearn" not in imported


def test_predict_proba_returns_valid_probability():
    p = model.predict_proba(["typosquat"])
    assert 0.0 <= p <= 1.0


def test_predict_proba_is_monotonic_for_stacking_strong_signals():
    baseline = model.predict_proba([])
    one_signal = model.predict_proba(["typosquat"])
    two_signals = model.predict_proba(["typosquat", "reply-to-mismatch"])
    assert baseline < one_signal < two_signals


def test_unknown_feature_key_contributes_nothing():
    baseline = model.predict_proba([])
    with_unknown = model.predict_proba(["some-feature-the-model-has-never-heard-of"])
    assert baseline == with_unknown


def test_known_signals_is_nonempty_and_matches_weights_file():
    assert len(model.KNOWN_SIGNALS) > 0
    assert model.KNOWN_SIGNALS == frozenset(model.FEATURE_WEIGHTS)


# --- feature_key normalisation ----------------------------------------------

def test_feature_key_strips_link_prefix():
    assert feature_key("link:typosquat") == "typosquat"
    assert feature_key("typosquat") == "typosquat"


def test_feature_key_collapses_threat_intel_hits():
    assert feature_key("ti:safe-browsing:hit") == "ti-hit"
    assert feature_key("ti:virustotal:hit") == "ti-hit"
    assert feature_key("ti:phishtank:hit") == "ti-hit"


def test_feature_key_leaves_threat_intel_non_hits_alone():
    # Only ":hit" collapses — "clean"/"unavailable" aren't positive-point
    # findings anyway, so they never reach _ml_findings, but the function
    # itself shouldn't silently mangle them either.
    assert feature_key("ti:safe-browsing:clean") == "ti:safe-browsing:clean"


def test_feature_key_leaves_enrichment_signals_alone():
    assert feature_key("enrich:newly-registered-domain") == "enrich:newly-registered-domain"
