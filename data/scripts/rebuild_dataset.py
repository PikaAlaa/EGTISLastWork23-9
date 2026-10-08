"""Deterministic text-template and registered-domain splits. Original data is unchanged.

Synthetic text is training-only. The ambiguous GitHub spam source is excluded.
Real anonymized SMS can be supplied separately; none are invented to meet targets.
"""
import argparse, hashlib, json, sys, re
from pathlib import Path
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'backend'))
from app.core.url_utils import parse_url, registered_domain
from app.core.text_utils import normalize_arabic_text
from app.core.dataset_identity import dataset_identity

def identity(text):
    text=normalize_arabic_text(str(text)).lower()
    text=re.sub(r'\d+', '<number>', text)
    return ' '.join(text.split())
def assignment(group):
    bucket=int(hashlib.sha256(('etis-v2-42:'+group).encode()).hexdigest()[:8],16)%100
    return 'train' if bucket<70 else 'val' if bucket<85 else 'test'

def rebuild(input_path,output,private_sms=None,augment_synthetic=False):
    data=pd.read_csv(input_path).fillna('')
    source_identity=dataset_identity(input_path)
    excluded=data[data.source=='github_arabic_text_spam_detection']
    data=data[data.source!='github_arabic_text_spam_detection'].copy()
    # Only reviewed binary labels are admitted. Spam/scam require explicit adjudication.
    data=data[data.label.isin(['phishing','legitimate'])].copy()
    data['sealed']=False
    synthetic_added=0
    if augment_synthetic:
        from synthetic_notifications import generate
        additions=generate();synthetic_added=len(additions)
        data=pd.concat([data,additions],ignore_index=True).fillna('')
    if private_sms:
        private=pd.read_csv(private_sms).fillna('')
        if not {'text','label','consent','anonymized'}<=set(private.columns):
            raise ValueError('SMS import requires text,label,consent,anonymized columns')
        if not private.consent.astype(str).str.lower().eq('yes').all() or not private.anonymized.astype(str).str.lower().eq('yes').all():
            raise ValueError('All imported SMS need consent and anonymization confirmation')
        if not private.label.isin(['phishing','legitimate']).all() or private.text.astype(str).str.strip().eq('').any():
            raise ValueError('SMS need reviewed binary labels and nonempty text')
        private=private.assign(content_type='text',source='consented_sms',language='ar',sealed=False)
        data=pd.concat([data,private],ignore_index=True).fillna('')
    texts=data[data.content_type.isin(['text','email'])].copy().reset_index(drop=True)
    keys=texts.text.map(identity).tolist()
    parents=list(range(len(keys)))
    def find(i):
        while parents[i]!=i:
            parents[i]=parents[parents[i]];i=parents[i]
        return i
    def union(i,j):
        a,b=find(i),find(j)
        if a!=b:parents[max(a,b)]=min(a,b)
    if keys:
        features=TfidfVectorizer(analyzer='char_wb',ngram_range=(3,5)).fit_transform(keys)
        # Batch similarities bound memory; connected components keep transitive copies together.
        for start in range(0,len(keys),128):
            similarity=cosine_similarity(features[start:start+128],features)
            for i,row in enumerate(similarity):
                for j in (row>=0.95).nonzero()[0]:
                    union(start+i,int(j))
    groups={}
    for i in range(len(keys)):groups.setdefault(find(i),[]).append(i)
    rows=[];quarantined=0;sealed_count=0;sealed_groups=0
    # Deduplicate and resolve split membership at group level, before sealing any data.
    for members in groups.values():
        group=texts.iloc[members]
        if group.label.nunique()!=1:
            quarantined+=len(group);continue
        group_id=hashlib.sha256(min(keys[i] for i in members).encode()).hexdigest()[:20]
        synthetic=group.source.str.startswith('synthetic').any()
        real=group.source.eq('consented_sms').any()
        split='train' if synthetic else assignment(group_id)
        # Whole legitimate import groups are reserved; never use them for model selection.
        if real and not synthetic and group.label.iloc[0]=='legitimate' and sealed_groups<200:
            split='sealed';sealed_groups+=1
            sealed_count+=len(group[group.source=='consented_sms'].drop_duplicates('text'))
        for _,r in group.drop_duplicates('text').iterrows():
            item=r.to_dict();item.update(group_id=group_id,split=split,sealed=split=='sealed')
            rows.append(item)
    urls=data[data.content_type=='url'].copy()
    canonical_rows={};invalid=0
    for _,r in urls.iterrows():
        try:p=parse_url(r.text)
        except Exception:invalid+=1;continue
        if p.canonical in canonical_rows:
            if canonical_rows[p.canonical]['label']!=r.label:
                canonical_rows[p.canonical]['conflict']=True
            continue
        item=r.to_dict();item.update(text=p.canonical,group_id=registered_domain(p.host),split=assignment(registered_domain(p.host)))
        canonical_rows[p.canonical]=item
    rows.extend(x for x in canonical_rows.values() if not x.get('conflict'))
    result=pd.DataFrame(rows)
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    # Sealed/private data must never appear in ordinary training files or Git.
    result[result.split!='sealed'].to_csv(output/'dataset.csv',index=False,lineterminator='\n')
    if sealed_count:result[(result.split=='sealed')&(result.source=='consented_sms')].to_csv(output/'sealed_sms.csv',index=False,lineterminator='\n')
    manifest={'version':'dataset-v2',**dataset_identity(output/'dataset.csv'),'source_identity':source_identity,'seed':42,'near_duplicate_cosine':0.95,
              'removed_spam_rows':len(excluded),'conflicting_text_rows_quarantined':quarantined,
              'invalid_url_rows_removed':invalid,'splits':result.split.value_counts().to_dict(),
              'text_splits':result[result.content_type!='url'].split.value_counts().to_dict(),
              'real_sms_sealed':sealed_count,'real_sms_sealed_groups':sealed_groups,'real_sms_target_met':sealed_groups>=200,
              'synthetic_notifications_added':synthetic_added,'synthetic_role':'training only; never real-data evidence',
              'labels':{'phishing':'deceptive request to disclose credentials, transfer funds, or open a fraudulent destination',
                        'legitimate':'reviewed non-deceptive communication','spam':'excluded unsolicited advertising','scam':'requires adjudication before binary use'}}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',default=str(ROOT/'data/processed/dataset.csv'))
    p.add_argument('--output',default=str(ROOT/'data/processed/v2'));p.add_argument('--private-sms');p.add_argument('--augment-synthetic',action='store_true')
    args=p.parse_args();print(json.dumps(rebuild(args.input,args.output,args.private_sms,args.augment_synthetic),indent=2))
