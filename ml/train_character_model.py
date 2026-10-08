"""Candidate model, selected and thresholded using validation only; no test-set access."""
import argparse,hashlib,json,sys
from pathlib import Path
import joblib,pandas as pd,numpy as np
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
from app.core.text_utils import normalize_arabic_text,text_windows
from validation import summarize

def train(dataset,output):
    d=pd.read_csv(dataset,low_memory=False).fillna('');d=d[d.content_type.isin(['text','email'])]
    tr=d[d.split=='train'];val=d[d.split=='val']
    if not len(tr) or not len(val):raise ValueError('Training and validation data required')
    model=make_pipeline(TfidfVectorizer(analyzer='char_wb',ngram_range=(2,5),sublinear_tf=True),
                        LogisticRegression(C=10,max_iter=2000,class_weight='balanced',random_state=42))
    model.fit(tr.text.map(normalize_arabic_text),(tr.label=='phishing').astype(int))
    # Match runtime max-over-windows behavior when choosing thresholds.
    predict=lambda s:float(model.predict_proba([normalize_arabic_text(w) for w in text_windows(s)])[:,1].max())
    probabilities=np.array([predict(s) for s in val.text]);y=(val.label=='phishing').astype(int).values
    report=summarize(Path(dataset),'character_candidate',y,probabilities,val)
    artifact={'pipeline':model,'version':report['dataset_sha256'][:16],**report,
              'selection':'candidate; compare all three models on this validation split'}
    Path(output).parent.mkdir(parents=True,exist_ok=True);joblib.dump(artifact,output)
    report['artifact_sha256']=hashlib.sha256(Path(output).read_bytes()).hexdigest()
    Path(output).with_suffix('.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--dataset',default=str(ROOT/'data/processed/v2/dataset.csv'))
    p.add_argument('--output',default=str(ROOT/'ml/models/char_candidate.joblib'));a=p.parse_args()
    print(json.dumps(train(a.dataset,a.output),indent=2))
