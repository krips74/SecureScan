from __future__ import annotations

import os
import logging
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

import joblib
import pandas as pd

from .phishing_features import extract_features


logger = logging.getLogger(__name__)


def _debug_enabled() -> bool:
    return os.getenv("PHISHING_ML_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")


def _default_model_path() -> str:
    # backend/ml/phishing_model.py -> backend -> project root
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))
    return os.path.join(root, "models", "phishing_model.pkl")


@lru_cache(maxsize=1)
def load_model_artifact(model_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    path = model_path or _default_model_path()
    if not os.path.exists(path):
        return None
    try:
        artifact = joblib.load(path)
        if _debug_enabled():
            cols = artifact.get("feature_columns") or []
            logger.info(f"[Phishing-ML] MODEL LOADED: {path}")
            logger.info(f"[Phishing-ML] FEATURE LENGTH: {len(cols)}")
        return artifact
    except Exception:
        return None


def predict_probability(url: str, *, timeout: int = 10) -> Tuple[Optional[float], Optional[str]]:
    """Return (phishing_probability, error_message)."""
    artifact = load_model_artifact()
    if not artifact:
        return None, "model_not_found"

    pipe = artifact.get("sklearn_pipeline")
    feature_columns = artifact.get("feature_columns")
    if pipe is None or not feature_columns:
        return None, "invalid_model_artifact"

    try:
        feats = extract_features(url, feature_columns, timeout=timeout)
        X = pd.DataFrame([feats], columns=list(feature_columns))
        if _debug_enabled():
            logger.info(f"[Phishing-ML] PREDICTION INPUT SHAPE: {X.shape}")
        proba = pipe.predict_proba(X)[0]
        # label_map: phishing=1, legitimate=0 (we trained y as 1=phishing)
        phishing_proba = float(proba[1])
        return phishing_proba, None
    except Exception as e:
        return None, f"predict_failed:{type(e).__name__}"


def risk_from_probability(p: Optional[float]) -> Optional[str]:
    if p is None:
        return None
    if p >= 0.80:
        return "HIGH"
    if p >= 0.50:
        return "MEDIUM"
    return "LOW"
