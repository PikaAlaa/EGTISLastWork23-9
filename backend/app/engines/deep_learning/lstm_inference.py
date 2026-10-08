"""Lazy BiLSTM loading. Optional TensorFlow failure does not stop URL scanning."""
import pickle
import os
from pathlib import Path
import threading
from app.core.settings import PROJECT_ROOT
from app.core.text_utils import normalize_arabic_text, text_windows
from app.core.exceptions import InvalidScanInputError

MODEL_PATH = PROJECT_ROOT / os.getenv('ETIS_BILSTM_MODEL_PATH','ml/models/lstm_phishing_classifier.keras')
TOKENIZER_PATH = PROJECT_ROOT / os.getenv('ETIS_BILSTM_TOKENIZER_PATH','ml/data/tokenizer.pkl')
_model = _tokenizer = _inference = None
_lock = threading.RLock()

def _load_artifacts():
    global _model, _tokenizer, _inference
    with _lock:
        if _model is None:
            from tensorflow.keras.models import load_model
            # Only trusted, repository-owned artifacts are loaded.
            _model = load_model(MODEL_PATH)
            import tensorflow as tf
            _inference=tf.function(lambda values:_model(values,training=False),reduce_retracing=True)
        if _tokenizer is None:
            with TOKENIZER_PATH.open('rb') as stream:
                _tokenizer = pickle.load(stream)

def calculate_lstm_phishing_score(text: str) -> dict:
    if not isinstance(text, str) or not text.strip():
        raise InvalidScanInputError('invalid_text')
    _load_artifacts()
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    windows = text_windows(text)
    sequences = _tokenizer.texts_to_sequences([normalize_arabic_text(w) for w in windows])
    padded = pad_sequences(sequences, maxlen=200, padding='post', truncating='post')
    with _lock:
        probability = float(_inference(padded).numpy().max())
    return {'score': round(probability*100, 2), 'probability': probability,
            'model': 'bilstm', 'version': __import__('hashlib').sha256(MODEL_PATH.read_bytes()).hexdigest()[:16], 'windows': len(windows)}
