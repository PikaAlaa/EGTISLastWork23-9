"""Three-source-setting, two-representation comparison; official PhreshPhish test is evaluation only."""
import gc,hashlib,json,sys,time,warnings
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'backend')]
import joblib,numpy as np,pandas as pd,pyarrow.parquet as pq
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.exceptions import ConvergenceWarning
from threadpoolctl import threadpool_limits
from lightgbm import LGBMClassifier
from data.scripts.download_phreshphish import COLUMNS,OUT as DATA,LOCK,REVISION
from evaluation.phreshphish_utils import *
from evaluation.run_url_v3 import ext,domain,read_dev,PSL

def fingerprint(frame):
    digest=hashlib.sha256()
    for row in frame.itertuples():digest.update((str(row.row_id)+'\0'+str(row.url)+'\0'+str(row.label_binary)+'\n').encode())
    return digest.hexdigest()

def parse(frame,extractor):
    frame=frame.copy();frame['host']=frame.url.map(host_of)
    unique=frame.host.dropna().unique();mapping={h:domain(h,extractor) for h in unique}
    frame['registered_domain']=frame.host.map(mapping).fillna('')
    return frame

def counts(frame):
    return {'rows':len(frame),'phishing_n':int(frame.label_binary.sum()),'benign_n':int((frame.label_binary==0).sum()),
      'unparseable_hosts':int(frame.host.isna().sum()),'registered_domains':int(frame.loc[frame.host.notna(),'registered_domain'].nunique()),
      'arabic_n':int(frame.lang.astype(str).str.lower().isin(['ar','ara','arabic']).sum()),
      'egyptian_registry_target_n':int(frame.target.map(brand_match).notna().sum()),
      'url_over_runtime_2048_chars_n':int(frame.url.str.len().gt(2048).sum())}

def prepare():
    lock=json.loads(LOCK.read_text());assert lock['complete'] and lock['revision']==REVISION and lock['columns']==COLUMNS
    protocol=json.loads((OUT/'protocol.json').read_text());assert protocol['frozen_before_training_and_test_predictions']
    extractor=ext();pieces=[]
    for record in lock['files']:
        path=DATA/Path(record['upstream_file']).name
        if sha(path)!=record['projected_sha256']:raise ValueError('Dataset projection SHA-256 mismatch')
        if pq.read_schema(path).names!=COLUMNS:raise ValueError('Disallowed projected columns')
        part=pq.read_table(path,columns=COLUMNS).to_pandas()
        part['official_split']='train' if path.name.startswith('train-') else 'test'
        part['row_id']=[f'{path.name}:{i}' for i in range(len(part))];part['source']='phreshphish'
        pieces.append(part)
    pp=pd.concat(pieces,ignore_index=True);pp['url']=pp.url.fillna('').astype(str);pp['lang']=pp.lang.fillna('').astype(str);pp['target']=pp.target.fillna('').astype(str)
    assert set(pp.label)=={'phish','benign'};pp['label_binary']=pp.label.map({'phish':1,'benign':0}).astype(int)
    pp=parse(pp,extractor)
    manifest=json.loads((ROOT/'evaluation/reports/2026-10-v3/review-2026-10-13/url_split_manifest.json').read_text())
    ids={r['row_id'] for r in manifest['rows']};et=read_dev();et=et[et.id.isin(ids)].copy();assert len(et)==len(ids)
    et=et.rename(columns={'text':'url'});et['row_id']='etis:'+et.id;et['label_binary']=(et.label=='phishing').astype(int)
    et['lang']='';et['target']='';et['official_split']=et.split;et=parse(et,extractor)
    etval=et[et.split=='val'].copy();test=pp[pp.official_split=='test'].copy()
    # Evaluation row membership stays fixed. Domain exclusion uses input metadata, not labels.
    held_domains=set(test.registered_domain)|set(etval.registered_domain);held_domains.discard('')
    phtrain=pp[pp.official_split=='train'].copy();ettrain=et[et.split=='train'].copy()
    sources={'etis':ettrain,'phreshphish':phtrain,'combined':pd.concat([ettrain[ettrain.label_binary==1],phtrain],ignore_index=True)}
    pools={};audit={'data_sha256':lock['data_sha256'],'protocol_sha256':sha(OUT/'protocol.json'),'dataset_revision':REVISION,
      'psl_sha256':sha(PSL),'etis_split_manifest_sha256':sha(ROOT/'evaluation/reports/2026-10-v3/review-2026-10-13/url_split_manifest.json'),
      'official_train':counts(phtrain),'official_test':counts(test),'etis_evaluation':counts(etval),'settings':{},
      'card_test_counts':{'stated_total':168060,'stated_benign':91260,'stated_phish':76876,'sum':168136,'discrepancy':76},
      'benign_url_source':'not stated on dataset card',
      'subgroup_target_matching':'Strict predeclared registry names/domains and aliases; generic international brand family targets counted as ambiguous.'}
    for name,pool in sources.items():
        valid=pool[pool.host.notna()].copy();overlap=valid.registered_domain.isin(held_domains)
        kept=valid[~overlap].copy();ambiguous=kept.groupby('registered_domain').label_binary.nunique();bad=set(ambiguous[ambiguous>1].index)
        mixed=kept.registered_domain.isin(bad);kept=kept[~mixed].copy();before=len(kept)
        kept=kept.drop_duplicates(['url','label_binary']).copy();kept['bucket']=kept.registered_domain.map(group_bucket)
        fit=kept[kept.bucket<80].reset_index(drop=True);cal=kept[kept.bucket>=80].reset_index(drop=True)
        assert set(fit.registered_domain).isdisjoint(cal.registered_domain)
        assert (set(fit.registered_domain)|set(cal.registered_domain)).isdisjoint(held_domains)
        assert set(fit.label_binary)=={0,1} and set(cal.label_binary)=={0,1}
        assert not fit.official_split.eq('test').any() and not cal.official_split.eq('test').any()
        pools[name]=(fit,cal)
        audit['settings'][name]={'input_pool':counts(pool),'evaluation_domain_overlap_rows_excluded':int(overlap.sum()),
          'evaluation_domain_overlap_domains_excluded':int(valid[overlap].registered_domain.nunique()),
          'mixed_label_domains_excluded':len(bad),'mixed_label_domain_rows_excluded':int(mixed.sum()),
          'same_label_exact_duplicate_rows_removed':before-len(kept),'fit':counts(fit),'calibration':counts(cal),
          'fit_sha256':fingerprint(fit),'calibration_sha256':fingerprint(cal),
          'fit_source_counts':fit.source.value_counts().to_dict(),'calibration_source_counts':cal.source.value_counts().to_dict()}
    for split,frame in [('train',phtrain),('test',test)]:
        arabic=frame[frame.lang.str.lower().isin(['ar','ara','arabic'])];brands=frame[frame.target.map(brand_match).notna()]
        families=frame[frame.target.map(target_key).isin(AMBIGUOUS_FAMILIES)]
        audit[f'{split}_arabic']=counts(arabic);audit[f'{split}_egyptian_registry_targets']=counts(brands)
        audit[f'{split}_egyptian_target_labels']=brands.target.value_counts().to_dict()
        audit[f'{split}_ambiguous_global_target_labels']=families.target.value_counts().to_dict()
    from urllib.parse import urlsplit
    def has_path(u):
        try:p=urlsplit(u if '://' in u else 'http://'+u);return p.path not in ('','/') or bool(p.query)
        except ValueError:return False
    audit['genuine_benign_nonroot_path_or_query_counts']={s:int(f[(f.label_binary==0)].url.map(has_path).sum()) for s,f in [('official_train',phtrain),('official_test',test)]}
    write('data_audit.json',audit);LOCAL.mkdir(parents=True,exist_ok=True)
    cache={'pools':pools,'tests':{'phreshphish_test':test.reset_index(drop=True),'etis_grouped_validation':etval.reset_index(drop=True)},'data_sha256':lock['data_sha256'],'protocol_sha256':sha(OUT/'protocol.json')}
    joblib.dump(cache,LOCAL/'prepared.joblib',compress=3)
    print('DATA AUDIT',json.dumps({k:audit[k] for k in ['official_train','official_test','test_arabic','test_egyptian_registry_targets','genuine_benign_nonroot_path_or_query_counts']}),flush=True)
    return cache

def predict_chunks(vec,clf,values,batch=4096):
    return np.concatenate([clf.predict_proba(vec.transform(values[i:i+batch]))[:,1] for i in range(0,len(values),batch)]) if len(values) else np.array([])

def main():
    start=time.perf_counter();protocol_sha=sha(OUT/'protocol.json');lock=json.loads(LOCK.read_text())
    cachepath=LOCAL/'prepared.joblib'
    if cachepath.exists():
        cache=joblib.load(cachepath)
        if cache['protocol_sha256']!=protocol_sha or cache['data_sha256']!=lock['data_sha256']:raise ValueError('Prepared data does not match protocol/download lock')
    else:cache=prepare()
    models=OUT/'models';models.mkdir(exist_ok=True);extractor=ext();results_path=OUT/'model_comparison.json'
    result=json.loads(results_path.read_text()) if results_path.exists() else {'data_sha256':cache['data_sha256'],'protocol_sha256':protocol_sha,'models':{},'status':'IN_PROGRESS','model_promotion':False}
    assert result['protocol_sha256']==protocol_sha
    for setting,(fit,cal) in cache['pools'].items():
        for representation in ['host_only','full_url']:
            full=representation=='full_url';column='url' if full else 'host';fitvalues=fit[column].tolist();calvalues=cal[column].tolist()
            for name in ['char_logistic','char_calibrated_svm','lightgbm']:
                key=f'{setting}/{representation}/{name}';path=models/f'{setting}_{representation}_{name}.joblib'
                if key in result['models']:
                    assert sha(path)==result['models'][key]['model_sha256'];continue
                print('FITTING',key,len(fit),'calibration',len(cal),flush=True);begin=time.perf_counter()
                if name=='lightgbm':
                    def values(frame):return [hand_features(r.url,r.host,extractor,full) for r in frame.itertuples()]
                    vec=DictVectorizer(dtype=np.float32);x=vec.fit_transform(values(fit));cx=vec.transform(values(cal))
                    clf=LGBMClassifier(n_estimators=250,learning_rate=.05,num_leaves=31,class_weight='balanced',random_state=42,n_jobs=2,verbosity=-1)
                else:
                    vec=TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=2,max_features=50000,sublinear_tf=True,dtype=np.float32)
                    x=vec.fit_transform(fitvalues);cx=vec.transform(calvalues)
                    if name=='char_logistic':clf=LogisticRegression(C=4,max_iter=2000,class_weight='balanced',random_state=42)
                    else:
                        folds=list(GroupKFold(n_splits=2).split(x,fit.label_binary,fit.registered_domain))
                        clf=CalibratedClassifierCV(LinearSVC(class_weight='balanced',random_state=42),method='sigmoid',cv=folds)
                with warnings.catch_warnings(record=True) as captured,threadpool_limits(limits=2):
                    warnings.simplefilter('always',ConvergenceWarning);clf.fit(x,fit.label_binary.to_numpy())
                calp=clf.predict_proba(cx)[:,1];thresholds={k:threshold_at_fpr(cal.label_binary,calp,cap) for k,cap in [('1pct',.01),('0_1pct',.001)]}
                artifact={'vectorizer':vec,'classifier':clf,'representation':representation,'research_feature_version':'phresh-1','thresholds':thresholds,'protocol_sha256':protocol_sha,'data_sha256':cache['data_sha256']}
                joblib.dump(artifact,path,compress=3);del x,cx;gc.collect()
                m={'setting':setting,'representation':representation,'model':name,'model_sha256':sha(path),'model_bytes':path.stat().st_size,
                  'fit_seconds':time.perf_counter()-begin,'fit_rows':len(fit),'calibration_rows':len(cal),'calibration':evaluate_cohort(cal,calp,thresholds),
                  'warnings':sorted({str(w.message) for w in captured if issubclass(w.category,ConvergenceWarning)}),'cohorts':{}}
                for testname,frame in cache['tests'].items():
                    valid=frame.host.notna().to_numpy();scores=np.full(len(frame),np.nan)
                    selected=frame[valid]
                    if name=='lightgbm':
                        for i in range(0,len(selected),4096):
                            z=selected.iloc[i:i+4096];f=values(z);scores[np.flatnonzero(valid)[i:i+4096]]=clf.predict_proba(vec.transform(f))[:,1]
                    else:scores[valid]=predict_chunks(vec,clf,selected[column].tolist())
                    cohort=evaluate_cohort(frame,scores,thresholds)
                    if testname=='phreshphish_test':
                        ar=frame.lang.str.lower().isin(['ar','ara','arabic']).to_numpy();eg=frame.target.map(brand_match).notna().to_numpy()
                        cohort['arabic']=evaluate_cohort(frame[ar],scores[ar],thresholds)
                        cohort['egyptian_registry_target']=evaluate_cohort(frame[eg],scores[eg],thresholds)
                    m['cohorts'][testname]=cohort
                    # Per-row predictions are local-only and excluded from Git/archives.
                    np.savez_compressed(LOCAL/(key.replace('/','_')+'_'+testname+'.npz'),score=scores,row_id=frame.row_id.to_numpy(dtype=str))
                timings=[]
                for row in cal.head(150).itertuples():
                    tick=time.perf_counter()
                    value=hand_features(row.url,row.host,extractor,full) if name=='lightgbm' else getattr(row,column)
                    clf.predict_proba(vec.transform([value]));timings.append((time.perf_counter()-tick)*1000)
                m['cpu_latency']={'batch_size':1,'n':len(timings),'p50_ms':float(np.percentile(timings,50)),'p95_ms':float(np.percentile(timings,95))}
                result['models'][key]=m;write('model_comparison.json',result)
                print('DONE',key,'seconds',round(time.perf_counter()-begin,1),'Phresh test recall',m['cohorts']['phreshphish_test']['fixed_calibration_thresholds']['1pct']['recall'],flush=True)
                del vec,clf,artifact;gc.collect()
    result['status']='COMPLETE';result['total_models']=len(result['models']);result['last_run_seconds']=time.perf_counter()-start
    assert len(result['models'])==18
    write('model_comparison.json',result);print('COMPLETE',len(result['models']),'models',flush=True)

if __name__=='__main__':main()
