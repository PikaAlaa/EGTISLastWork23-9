"""Batch prediction for final comparisons; all candidates use the same runtime window policy."""
import hashlib,json,pickle,sys
from pathlib import Path
import joblib,numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
from app.core.text_utils import normalize_arabic_text,text_windows
def predict(texts,name):
    windows=[];bounds=[]
    for text in texts:
        start=len(windows);windows.extend(normalize_arabic_text(w) for w in text_windows(text));bounds.append((start,len(windows)))
    extension='keras' if name=='bilstm' else 'joblib';path=ROOT/f'ml/models/{name}_candidate.{extension}'
    report=json.loads(path.with_suffix('.json').read_text())
    if name=='bilstm':
        import tensorflow as tf
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        model=tf.keras.models.load_model(path)
        with path.with_suffix('.tokenizer.pkl').open('rb') as f:tokenizer=pickle.load(f)
        encoded=pad_sequences(tokenizer.texts_to_sequences(windows),maxlen=200,padding='post',truncating='post')
        infer=tf.function(lambda batch:model(batch,training=False),reduce_retracing=True)
        scores=np.concatenate([infer(encoded[i:i+128]).numpy().ravel() for i in range(0,len(encoded),128)])
    else:
        artifact=joblib.load(path);scores=artifact['pipeline'].predict_proba(windows)[:,1]
    probabilities=[float(scores[start:end].max()) for start,end in bounds]
    return probabilities,report['high_threshold'],hashlib.sha256(path.read_bytes()).hexdigest()
