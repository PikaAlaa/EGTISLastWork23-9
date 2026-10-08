"""Comparison baseline: word TF-IDF and LightGBM, training-only vocabulary and validation thresholds."""
import argparse,json,sys,hashlib
from pathlib import Path
import joblib,pandas as pd
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from lightgbm import LGBMClassifier
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'))
from app.core.text_utils import normalize_arabic_text,text_windows
from validation import summarize
def train(dataset,output):
    d=pd.read_csv(dataset,low_memory=False).fillna('');d=d[d.content_type.isin(['text','email'])]
    tr=d[d.split=='train'];val=d[d.split=='val']
    model=make_pipeline(TfidfVectorizer(max_features=5000),LGBMClassifier(n_estimators=300,class_weight='balanced',random_state=42,n_jobs=2,verbosity=-1))
    model.fit(tr.text.map(normalize_arabic_text),(tr.label=='phishing').astype(int))
    probabilities=[float(model.predict_proba([normalize_arabic_text(w) for w in text_windows(text)])[:,1].max()) for text in val.text]
    report=summarize(Path(dataset),'lightgbm_candidate',(val.label=='phishing').astype(int),probabilities,val)
    artifact={'pipeline':model,'version':report['dataset_sha256'][:16],**report}
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True);joblib.dump(artifact,output)
    report['artifact_sha256']=hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix('.json').write_text(json.dumps(report,indent=2),encoding='utf-8');return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--dataset',default=str(ROOT/'data/processed/v2/dataset.csv'))
    p.add_argument('--output',default=str(ROOT/'ml/models/lightgbm_candidate.joblib'));a=p.parse_args()
    print(json.dumps(train(a.dataset,a.output),indent=2))
