"""Desk-side statistical second opinion. Loaded lazily and fully optional:

if joblib/sklearn or the model file are missing, available() is False and the Desk
falls back to the rules alone — nothing breaks. The rules stay the explainable first
pass; this only escalates veiled abuse they can't pattern-match (no slur, no "I will").
"""
import os
import threading

_MODEL = None
_LOCK = threading.Lock()
_PATH = os.path.join(os.path.dirname(__file__), "..", "model", "abuse_model.joblib")

# Tuned on held-out novel probes: benign hard-negatives top out ~0.31, veiled abuse >=0.72.
REVIEW = 0.55
HIGH = 0.80


def _load():
    global _MODEL
    if _MODEL is None:
        with _LOCK:
            if _MODEL is None:
                try:
                    import joblib
                    _MODEL = joblib.load(os.path.abspath(_PATH))
                except Exception:
                    _MODEL = False
    return _MODEL


def available():
    return bool(_load())


def score(text):
    """P(abusive) in [0,1], or None if the model is unavailable."""
    model = _load()
    if not model:
        return None
    try:
        return float(model.predict_proba([text])[0][1])
    except Exception:
        return None
