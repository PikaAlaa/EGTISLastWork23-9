"""Source-held-out text evaluation on train/validation rows only."""
import hashlib,json,sys
from pathlib import Path
import joblib,numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'backend')]
from evaluation.run_text_v3 import build_split,_expand,_score_windows,versions,sha
REPORT=ROOT/'evaluation/reports/2026-10-v3';OUT=REPORT/'models'/'loso';DATA=ROOT/'evaluation/local-results/v3-data/dataset.csv'
TRANSLATION={'kaggle_arabic_phishing_fully_dataset':'translated 419/advance-fee fraud and translated UCI ham, per docs/arabic_sources_citations.md','salloum_gaber_bilingual_corpus':'English/Arabic parallel phishing email corpus; translated/parallel, per cited corpus title','kaggle_dialectal_arabic_sms':'non-Egyptian and templated, per project context; not treated as authentic Egyptian SMS'}
def threshold(y,p):
 y=np.asarray(y,int);p=np.asarray(p,float);pos=y==1
 return max(float(t) for t in np.unique(p[pos]) if float((p[pos]>=t).mean())>=.95)
def metrics(y,p,t):
 y=np.asarray(y,int);p=np.asarray(p,float);pred=p>=t;tp=int(((y==1)&pred).sum());fp=int(((y==0)&pred).sum());fn=int(((y==1)&~pred).sum());tn=int(((y==0)&~pred).sum())
 f1p=2*tp/max(2*tp+fp+fn,1);f1n=2*tn/max(2*tn+fp+fn,1)
 return {'n':len(y),'phishing_n':int((y==1).sum()),'legitimate_n':int((y==0).sum()),'threshold_from_id_validation':t,'macro_f1':(f1p+f1n)/2,'phishing_recall':tp/max(tp+fn,1),'legitimate_fpr':fp/max(fp+tn,1),'confusion':{'tp':tp,'fp':fp,'fn':fn,'tn':tn}}
def main():
 rows,manifest=build_split(DATA);OUT.mkdir(parents=True,exist_ok=True)
 eligible=[]
 for source,g in rows.groupby('source'):
  counts=g.groupby('label').size().to_dict()
  if counts.get('phishing',0)>=100 and counts.get('legitimate',0)>=100:eligible.append(source)
 results={}
 for held in eligible:
  hv=rows[rows.source==held].reset_index(drop=True)
  held_groups=set(hv.group_id.astype(str))
  available=rows[(rows.source!=held)&~rows.group_id.astype(str).isin(held_groups)]
  tr=available[available.split=='train'].reset_index(drop=True)
  idv=available[available.split=='val'].reset_index(drop=True)
  if tr.empty or idv.empty or hv.empty:continue
  tx,ty,_=_expand(tr);vx,_,vo=_expand(idv);hx,_,ho=_expand(hv)
  model=make_pipeline(TfidfVectorizer(analyzer='char_wb',ngram_range=(2,5),sublinear_tf=True),LogisticRegression(C=10,max_iter=2000,class_weight='balanced',random_state=42))
  model.fit(tx,ty);idp=_score_windows(model,vx,vo,len(idv));hp=_score_windows(model,hx,ho,len(hv));iy=(idv.label=='phishing').astype(int).to_numpy();hy=(hv.label=='phishing').astype(int).to_numpy();th=threshold(iy,idp)
  idm=metrics(iy,idp,th);hm=metrics(hy,hp,th);path=OUT/f'{held}.joblib';joblib.dump(model,path)
  results[held]={'translated_or_dataset_caveat':TRANSLATION.get(held,'Source translation status not confirmed.'),'source_trainval_rows':len(rows[rows.source==held]),'source_phishing_n':int((rows[(rows.source==held)].label=='phishing').sum()),'source_legitimate_n':int((rows[(rows.source==held)].label=='legitimate').sum()),'training_rows':len(tr),'id_validation_rows':len(idv),'heldout_source_validation_rows':len(hv),'in_distribution_validation':idm,'heldout_source_validation':hm,'macro_f1_drop_vs_id_validation':idm['macro_f1']-hm['macro_f1'],'model_sha256':sha(path),'model_size_bytes':path.stat().st_size}
 out={'stage':'development_validation_leave_one_source_out','final_test_run':False,'data_sha256':manifest['dataset_identity']['dataset_sha256'],'text_split_sha256':manifest['text_split_sha256'],'model_sha256':None,'libraries':versions(),'criteria':'Each source with at least 100 train+validation rows per class; train only on other sources train rows, excluding any near-duplicate group present in the held-out source; threshold from other-source validation; evaluate all train+validation rows of the excluded source. No split=test rows used.','eligible_sources':eligible,'sources':results,'limitations':['Kaggle dialectal SMS is non-Egyptian and templated per project context.','Translated/parallel sources are labelled separately; no authentic Egyptian SMS cohort exists.']}
 (REPORT/'loso_text_metrics.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps({k:v['macro_f1_drop_vs_id_validation'] for k,v in results.items()},indent=2))
if __name__=='__main__':main()
