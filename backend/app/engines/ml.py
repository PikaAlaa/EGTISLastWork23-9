from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from app.core.config import settings


def _normalize_text(text: str) -> str:
    text = text.casefold()
    text = re.sub(r"[إأآٱ]", "ا", text)
    text = re.sub(r"ى", "ي", text)
    text = re.sub(r"ؤ", "و", text)
    text = re.sub(r"ئ", "ي", text)
    text = re.sub(r"[ًٌٍَُِّْـ]", "", text)
    text = re.sub(r"https?://\S+", " <url> ", text)
    return " ".join(text.split())


@lru_cache(maxsize=1)
def _load_bilstm(path: str):
    try:
        import tensorflow as tf

        return tf.keras.models.load_model(path)
    except (FileNotFoundError, ImportError, OSError, ValueError):
        return None


@lru_cache(maxsize=1)
def _load_baseline(path: str):
    try:
        import joblib

        return joblib.load(path)
    except (FileNotFoundError, ImportError, OSError, ValueError):
        return None


def model_available() -> bool:
    if Path(settings.model_path).is_file() and _load_baseline(str(settings.model_path)) is not None:
        return True
    return Path(settings.bilstm_model_path).is_file() and _load_bilstm(str(settings.bilstm_model_path)) is not None


def calculate_ml_score(text: str | None) -> dict:
    if not text:
        return {"applicable": False, "score": None, "model": None, "reason": "No text supplied"}
    baseline = _load_baseline(str(settings.model_path))
    if baseline is not None:
        probability = float(baseline.predict_proba([text])[0][1])
        return {"applicable": True, "score": round(probability * 100, 2), "model": "tfidf_logistic_regression", "reason": "Validation-selected text-model phishing probability"}
    bilstm = _load_bilstm(str(settings.bilstm_model_path))
    if bilstm is not None:
        probability = float(bilstm.predict([_normalize_text(text)], verbose=0).reshape(-1)[0])
        return {"applicable": True, "score": round(probability * 100, 2), "model": "bilstm", "reason": "Fallback BiLSTM phishing probability"}
    return {"applicable": False, "score": None, "model": None, "reason": "No trained text-model artifact is installed"}
