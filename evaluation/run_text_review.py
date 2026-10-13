"""Apply the frozen 13 October selection rule to every local candidate, without test access.

LOSO thresholds and BiLSTM early stopping see other-source validation only.
The already exposed everyday fixtures are selection diagnostics, never accuracy estimates.
"""
import importlib.util
import json
import os
import pickle
import subprocess
import sys
import time
from pathlib import Path
os.environ.setdefault('TF_CPP_MIN_LOG_LEVEL','2')
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT),str(ROOT/'backend')]
import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import make_pipeline
from evaluation.review_common import OUT, PREVIOUS, DIALECT, PROVENANCE, read_frozen, write, language
from evaluation.run_text_v3 import _expand, _score_windows, make_models, model_metrics, sha
from evaluation.run_loso_text_v3 import metrics
from app.core.text_utils import normalize_arabic_text, text_windows

def load_bilstm(path):
    import tensorflow as tf
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    model = tf.keras.models.load_model(path, compile=False)
    tokenizer = pickle.loads(path.with_suffix('.tokenizer.pkl').read_bytes())
    class Wrapper:
        def predict_proba(self, texts):
            x = pad_sequences(tokenizer.texts_to_sequences(texts),maxlen=200,padding='post',truncating='post')
            p = np.concatenate([model(x[i:i+128],training=False).numpy().ravel() for i in range(0,len(x),128)])
            return np.c_[1-p,p]
    return Wrapper()

def probe_results(model, high, probes):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.core.database import Base
    from app.engines import risk_scoring
    from app.services.registry import populate_registry
    engine=create_engine('sqlite://'); Base.metadata.create_all(engine)
    original, health = risk_scoring.score_text, risk_scoring.blacklist_health
    def score(text):
        start=time.perf_counter()
        windows=[normalize_arabic_text(w) for w in text_windows(text)]
        p=float(model.predict_proba(windows)[:,1].max())
        durations.append((time.perf_counter()-start)*1000)
        return {'probability':p,'score':p*100,'high_threshold':high,'low_threshold':.2}
    durations=[]; result=[]
    risk_scoring.score_text=score
    risk_scoring.blacklist_health=lambda db:{'available':True,'reason':None}
    try:
        with Session(engine) as db:
            populate_registry(db)
            for i,text in enumerate(probes):
                r=risk_scoring.calculate_final_risk_score(text=text,db=db)
                result.append({'probe_index':i+1,'verdict':r['verdict'],'reason':r['decisive_reason'],'probability':r['text_finding']['probability']})
    finally:
        risk_scoring.score_text=original; risk_scoring.blacklist_health=health; engine.dispose()
    return {'provenance':PROVENANCE['everyday_probes'],'rows':result,'n':len(result),
      'high_n':sum(r['verdict']=='HIGH' for r in result),
      'medium_or_high_n':sum(r['verdict'] in {'MEDIUM','HIGH'} for r in result),
      'incomplete_n':sum(r['verdict']=='INCOMPLETE' for r in result),
      'medium_or_high_rate':np.mean([r['verdict'] in {'MEDIUM','HIGH'} for r in result]),
      'cpu_p95_ms':float(np.percentile(durations,95))}

def main():
    rows, manifest=read_frozen(); frozen_hash=sha(PREVIOUS/'text_split.json')
    rule=json.loads((OUT/'model_selection_rule.json').read_text(encoding='utf-8'))
    assert rule['frozen_before_new_results'] and rule['data_sha256']==manifest['data_sha256']
    val=rows[rows.split=='val'].reset_index(drop=True)
    eligible=val.source!=DIALECT
    val['corrected_language']=val.apply(lambda r:language(r.text) if r.source==DIALECT else r.language,axis=1)
    overlay=[{'row_id':r.id,'split':r.split,'old_language':r.language,'corrected_language':language(r.text)} for r in rows[rows.source==DIALECT].itertuples()]
    write('language_overlay.json',{'frozen_manifest_file_sha256':frozen_hash,'frozen_split_changed':False,'method':'Arabic-script and Latin-letter detection, applied only to dialectal source metadata','provenance':PROVENANCE[DIALECT],'rows':overlay})
    spec=importlib.util.spec_from_file_location('existing_probes',ROOT/'evaluation/review-evidence/cases.py')
    cases=importlib.util.module_from_spec(spec); spec.loader.exec_module(cases)
    previous=json.loads((PREVIOUS/'text_local_metrics.json').read_text())
    results={}
    modeldir=OUT/'models/text_loso'; modeldir.mkdir(parents=True,exist_ok=True)
    work=ROOT/'evaluation/local-results/review-2026-10-13'; work.mkdir(parents=True,exist_ok=True)
    for name in rule['simplicity_order']:
        path=PREVIOUS/'models'/('bilstm_candidate.keras' if name=='bilstm' else name+'.joblib')
        assert sha(path)==previous['models'][name]['model_sha256']
        model=load_bilstm(path) if name=='bilstm' else joblib.load(path)['pipeline']
        pred=json.loads((PREVIOUS/'predictions'/f'{name}_seed42.json').read_text())
        assert pred['data_sha256']==manifest['data_sha256'] and pred['model_sha256']==sha(path)
        scores_by_id={r['row_id']:r['score'] for r in pred['rows']}
        scores=np.array([scores_by_id[r.id] for r in val.itertuples()]); labels=(val.label=='phishing').astype(int).to_numpy()
        vm=model_metrics(labels[eligible],scores[eligible]); high=vm['threshold_at_recall_95']
        sources={}
        for source,ix in val.groupby('source').indices.items():
            sources[source]={'provenance':PROVENANCE.get(source,'unverified'),
              'selection_eligible':source!=DIALECT,'metrics':metrics(labels[ix],scores[ix],high)}
        languages={lang:metrics(labels[ix],scores[ix],high) for lang,ix in val.groupby('corrected_language').indices.items()}
        probes=probe_results(model,high,cases.EVERYDAY_SMS)
        current={'model_sha256':sha(path),'validation':{'provenance':'translated UCI ham/fraud letters and translated parallel emails; dialectal validation excluded','metrics':vm},
          'corrected_validation_by_source':sources,'corrected_validation_by_language':languages,
          'everyday':probes,'loso':{},'latency':previous['models'][name]['latency']}
        for source in rule['primary_sources']:
            hv=rows[rows.source==source].reset_index(drop=True); groups=set(hv.group_id)
            available=rows[(rows.source!=source)&~rows.group_id.isin(groups)]
            tr=available[available.split=='train'].reset_index(drop=True)
            iv=available[(available.split=='val')&(available.source!=DIALECT)].reset_index(drop=True)
            assert set(tr.group_id).isdisjoint(hv.group_id) and set(tr.source).isdisjoint({source})
            if name=='bilstm':
                mp=modeldir/f'{name}_{source}.keras'; dataset=work/f'{source}_bilstm_trainval.csv'
                pd.concat([tr,iv]).to_csv(dataset,index=False)
                # Separate processes keep TensorFlow pools bounded and early-stopping source isolated.
                subprocess.run([sys.executable,'-m','ml.train_bilstm_candidate','--dataset',str(dataset),'--output',str(mp),'--epochs','20'],cwd=ROOT,check=True)
                candidate=load_bilstm(mp)
                side=json.loads(mp.with_suffix('.json').read_text()); side.update(data_sha256=manifest['data_sha256'],model_sha256=sha(mp),libraries=previous['libraries'])
                mp.with_suffix('.json').write_text(json.dumps(side,indent=2),encoding='utf-8')
            else:
                vec,clf=make_models()[name]
                if clf is None:
                    from lightgbm import LGBMClassifier
                    clf=LGBMClassifier(n_estimators=300,class_weight='balanced',random_state=42,n_jobs=2,verbosity=-1)
                candidate=make_pipeline(vec,clf); tx,ty,_=_expand(tr); candidate.fit(tx,ty)
                mp=modeldir/f'{name}_{source}.joblib'; joblib.dump(candidate,mp)
            ix,_,io=_expand(iv); hx,_,ho=_expand(hv)
            ip=_score_windows(candidate,ix,io,len(iv)); hp=_score_windows(candidate,hx,ho,len(hv))
            iy=(iv.label=='phishing').astype(int).to_numpy(); hy=(hv.label=='phishing').astype(int).to_numpy()
            threshold=model_metrics(iy,ip)['threshold_at_recall_95']
            current['loso'][source]={'provenance':PROVENANCE[source],
                'threshold_selection_provenance':sorted({PROVENANCE[s] for s in iv.source}),
                'training_rows':len(tr),'threshold_validation_rows':len(iv),'model_sha256':sha(mp),
                'in_source_validation':metrics(iy,ip,threshold),'held_source':metrics(hy,hp,threshold)}
            print(name,source,current['loso'][source]['held_source'],flush=True)
        loss=(np.mean([1-r['held_source']['phishing_recall'] for r in current['loso'].values()])+
              np.mean([r['held_source']['legitimate_fpr'] for r in current['loso'].values()])+probes['medium_or_high_rate'])/3
        current['primary_loss']=float(loss); results[name]=current
        write('text_review_metrics.json',{'rule_sha256':sha(OUT/'model_selection_rule.json'),'models':results,'provenance':PROVENANCE,'status':'IN_PROGRESS'})
    eligible_models=[n for n,m in results.items() if m['latency']['p95_ms']<=rule['max_p95_cpu_ms'] and not m['everyday']['incomplete_n']]
    best=min(results[n]['primary_loss'] for n in eligible_models)
    tied=[n for n in eligible_models if results[n]['primary_loss']<=best+rule['tie_tolerance']]
    winner=sorted(tied,key=lambda n:(-results[n]['validation']['metrics']['macro_f1_at_recall_95'],rule['simplicity_order'].index(n)))[0]
    assert sha(PREVIOUS/'text_split.json')==frozen_hash
    write('text_review_metrics.json',{'rule_sha256':sha(OUT/'model_selection_rule.json'),'models':results,'provenance':PROVENANCE,'status':'COMPLETE','provisional_winner':winner,'final_choice':False,'deployed_text_model_changed':False,
       'limitations':['Source-held-out evidence remains translated/non-Egyptian; not an Egyptian SMS benchmark.','Everyday fixtures are exposed and invented; using them for selection precludes calling them an independent test.','Historical mixed language metrics are superseded by this report; no frozen row or label changed.']})
    print('PROVISIONAL_WINNER',winner,flush=True)

if __name__=='__main__': main()
