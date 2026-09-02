#!/usr/bin/env python3
"""Regenerates app/ml/weights.json from app/ml/dataset.py.

This is a dev-only script — scikit-learn is NOT a runtime dependency of
the app itself (see app/ml/model.py: inference at request time is a plain
dot product plus a sigmoid, both pure Python). Install scikit-learn only
to run this:

    pip install scikit-learn
    python scripts/train_model.py

Run it again after editing app/ml/dataset.py, and commit the regenerated
weights.json — the app loads it as a static file at import time.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.ml.dataset import DATASET  # noqa: E402

WEIGHTS_PATH = ROOT / "app" / "ml" / "weights.json"


def main() -> None:
    try:
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        print("scikit-learn isn't installed. Run: pip install scikit-learn", file=sys.stderr)
        sys.exit(1)

    vocab = sorted({feature for row in DATASET for feature in row["features"]})
    if not vocab:
        print("app/ml/dataset.py has no features to train on.", file=sys.stderr)
        sys.exit(1)

    X = [[1.0 if feature in row["features"] else 0.0 for feature in vocab] for row in DATASET]
    y = [row["label"] for row in DATASET]

    model = LogisticRegression(C=1.0, max_iter=2000)
    model.fit(X, y)

    weights = {feature: round(coef, 4) for feature, coef in zip(vocab, model.coef_[0])}
    payload = {
        "intercept": round(float(model.intercept_[0]), 4),
        "weights": weights,
        "trained_on_examples": len(DATASET),
    }

    WEIGHTS_PATH.write_text(json.dumps(payload, indent=2) + "\n")

    train_acc = model.score(X, y)
    print(f"Trained on {len(DATASET)} examples ({sum(y)} positive, {len(y) - sum(y)} negative).")
    print(f"Training-set accuracy: {train_acc:.0%} (expected to be high — this is a small, separable, hand-built set, not a held-out test).")
    print(f"Wrote {WEIGHTS_PATH.relative_to(ROOT)}")
    print()
    print("Per-feature coefficients (higher = more phishing-leaning):")
    for feature, coef in sorted(weights.items(), key=lambda kv: kv[1], reverse=True):
        print(f"  {coef:+.3f}  {feature}")


if __name__ == "__main__":
    main()
