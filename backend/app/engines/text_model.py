import hashlib
from functools import lru_cache
import joblib
from pathlib import Path
from app.core.settings import settings
from app.core.text_utils import normalize_arabic_text, text_windows

@lru_cache(maxsize=2)
def load_character_model(path):
    artifact=joblib.load(path)
    artifact['version']=hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]
    return artifact

def score_text(text):
    if settings.model_backend == 'bilstm':
        from app.engines.deep_learning.lstm_inference import calculate_lstm_phishing_score
        return calculate_lstm_phishing_score(text)
    if settings.model_backend != 'char':
        raise ValueError('unsupported_model')
    artifact = load_character_model(settings.model_path)
    windows = text_windows(text)
    probabilities = artifact['pipeline'].predict_proba([normalize_arabic_text(w) for w in windows])[:, 1]
    probability = float(max(probabilities))
    return {'score': round(probability*100, 2), 'probability': probability,
            'model': artifact.get('model_name', 'char'), 'version': artifact['version'], 'windows': len(windows),
            'low_threshold': artifact['low_threshold'], 'high_threshold': artifact['high_threshold']}
