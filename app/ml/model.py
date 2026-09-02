"""Loads the logistic-regression weights trained offline by
scripts/train_model.py (from the labeled examples in app/ml/dataset.py)
and scores a set of already-triggered signal names.

Deliberately has zero ML-library dependency at runtime: weights.json is a
plain JSON file of coefficients, and inference here is nothing more than
a dot product and a sigmoid, both pure Python. scikit-learn is only
needed to regenerate weights.json, never to run the app or its tests.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Dict, Iterable

WEIGHTS_PATH = Path(__file__).resolve().parent / "weights.json"

with WEIGHTS_PATH.open() as _f:
    _WEIGHTS: dict = json.load(_f)

INTERCEPT: float = _WEIGHTS["intercept"]
FEATURE_WEIGHTS: Dict[str, float] = _WEIGHTS["weights"]
KNOWN_SIGNALS = frozenset(FEATURE_WEIGHTS)


def predict_proba(feature_keys: Iterable[str]) -> float:
    """Probability of phishing given which known feature keys fired.

    A key the model has no coefficient for (wasn't in the training
    vocabulary) contributes nothing rather than raising — same
    "degrade, don't guess" approach as the rest of Hookline.
    """
    logit = INTERCEPT + sum(FEATURE_WEIGHTS.get(key, 0.0) for key in feature_keys)
    return 1.0 / (1.0 + math.exp(-logit))
