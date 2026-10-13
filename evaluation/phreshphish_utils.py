"""Offline URL-only helpers; no network, webpage parsing, or content-column access."""
import hashlib,ipaddress,json,re,sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
import idna,numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'backend')]
from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS
from evaluation.run_text_v3 import versions
OUT=ROOT/'evaluation/reports/2026-10-v3/phreshphish'
LOCAL=ROOT/'evaluation/local-results/phreshphish'

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def libraries():
    import pyarrow,requests
    return {**versions(),'pyarrow':pyarrow.__version__,'requests':requests.__version__}
def write(name,obj):
    OUT.mkdir(parents=True,exist_ok=True);obj.setdefault('model_sha256',None);obj.setdefault('libraries',libraries())
    obj.setdefault('etis_sealed_test_evaluated',False)
    (OUT/name).write_text(json.dumps(obj,ensure_ascii=False,indent=2,allow_nan=False,default=lambda x:x.item())+'\n',encoding='utf-8')
def host_of(value):
    """Parse long research URL strings offline; runtime's 2048-char cap is not applied."""
    value=str(value).strip()
    if not value or re.search(r'[\x00-\x20\x7f\\]',value):return None
    try:
        p=urlsplit(value if '://' in value else 'http://'+value)
        if p.scheme.lower() not in {'http','https'} or not p.hostname:return None
        host=p.hostname.rstrip('.')
        try:return ipaddress.ip_address(host).compressed
        except ValueError:return idna.encode(host,uts46=True).decode('ascii').lower() if '.' in host else None
    except (ValueError,idna.IDNAError):return None
def group_bucket(group):return int(hashlib.sha256(('etis-phresh-42:'+str(group)).encode()).hexdigest()[:8],16)%100
def target_key(value):return re.sub(r'[^a-z0-9\u0600-\u06ff]+','',str(value).lower())
STRICT_ALIASES={target_key(n):n for n,d in EGYPTIAN_BRAND_DOMAINS}
STRICT_ALIASES.update({target_key(d):n for n,d in EGYPTIAN_BRAND_DOMAINS})
# Explicit aliases anchored to the registry; global families remain a separate ambiguity audit.
for alias,brand in {'nbe':'National Bank of Egypt (NBE)','nationalbankofegypt':'National Bank of Egypt (NBE)',
  'cibegypt':'Commercial International Bank (CIB)','cibeg':'Commercial International Bank (CIB)',
  'bankmisr':'Banque Misr','aaib':'Arab African International Bank','etisalatmisr':'Etisalat Misr (e&)',
  'telecomegypt':'Telecom Egypt (WE)'}.items():STRICT_ALIASES[alias]=brand
AMBIGUOUS_FAMILIES={'amazon','vodafone','orange','qnb','noon','jumia','talabat','etisalat','cib'}
def brand_match(target):return STRICT_ALIASES.get(target_key(target))

def hand_features(value,host,extractor,full):
    # Full representation uses original URL characters, including schemes and paths.
    feature=str(value) if full else host
    p=urlsplit(str(value) if '://' in str(value) else 'http://'+str(value))
    t=extractor(host);chars=Counter(feature.lower());counts=np.asarray(list(chars.values()),float);prob=counts/counts.sum()
    try:ipaddress.ip_address(host);ip=1
    except ValueError:ip=0
    return {'url_len':len(feature),'host_len':len(host),'digits':sum(c.isdigit() for c in feature),
      'digit_ratio':sum(c.isdigit() for c in feature)/max(len(feature),1),'hyphens':feature.count('-'),
      'dots':host.count('.'),'subdomain_depth':len(t.subdomain.split('.')) if t.subdomain else 0,
      'tld':t.suffix.lower(),'is_ip':ip,'has_at':int('@' in feature),'punycode':int('xn--' in host),
      'entropy':float(-(prob*np.log2(prob)).sum()),'path_len':len(p.path) if full else 0,
      'query_len':len(p.query) if full else 0,'token_count':len(re.findall(r'[a-z0-9]+',feature.lower()))}

def wilson(success,n):
    if n==0:return [None,None]
    z=1.959963984540054;p=success/n;d=1+z*z/n
    mid=(p+z*z/(2*n))/d;half=z*np.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [float(max(0,mid-half)),float(min(1,mid+half))]
def adjusted_precision(tpr,fpr,prior):
    if tpr is None or fpr is None:return None
    den=prior*tpr+(1-prior)*fpr
    return prior*tpr/den if den else None
def threshold_at_fpr(y,scores,cap):
    negatives=np.asarray(scores)[np.asarray(y)==0];valid=negatives[np.isfinite(negatives)]
    if not len(valid):raise ValueError('Calibration needs scorable negatives')
    # Invalid inputs abstain, so allowed false positives uses all calibration negatives.
    allowed=int(np.floor(cap*len(negatives)));ordered=np.sort(valid)
    return float(np.nextafter(ordered[len(ordered)-allowed-1],np.inf)) if allowed<len(ordered) else 0.0
def at_threshold(y,scores,threshold):
    y=np.asarray(y,int);scores=np.asarray(scores,float);pred=np.isfinite(scores)&(scores>=threshold);pos=y==1
    tp=int((pred&pos).sum());fp=int((pred&~pos).sum());fn=int((~pred&pos).sum());tn=int((~pred&~pos).sum())
    tpr=tp/(tp+fn) if tp+fn else None;fpr=fp/(fp+tn) if fp+tn else None
    tci=wilson(tp,tp+fn);fci=wilson(fp,fp+tn)
    return {'n':len(y),'phishing_n':int(pos.sum()),'benign_n':int((~pos).sum()),'abstentions':int((~np.isfinite(scores)).sum()),
      'threshold':threshold,'tp':tp,'fp':fp,'fn':fn,'tn':tn,'recall':tpr,'false_positive_rate':fpr,
      'recall_wilson_95':tci,'fpr_wilson_95':fci,
      'precision_at_phishing_base_rate_1pct':adjusted_precision(tpr,fpr,.01),
      'precision_at_phishing_base_rate_0_1pct':adjusted_precision(tpr,fpr,.001),
      'precision_conservative_bound_1pct':adjusted_precision(tci[0],fci[1],.01),
      'precision_conservative_bound_0_1pct':adjusted_precision(tci[0],fci[1],.001),
      'precision_bound_note':'Combines marginal Wilson bounds; descriptive conservative bound, not joint or domain-cluster confidence interval.'}

def evaluate_cohort(frame,scores,thresholds):
    y=frame.label_binary.to_numpy();scorable=np.isfinite(scores)
    result={'n':len(frame),'phishing_n':int(y.sum()),'benign_n':int((y==0).sum()),'scorable_n':int(scorable.sum()),
      'fixed_calibration_thresholds':{cap:at_threshold(y,scores,t) for cap,t in thresholds.items()},
      'retrospective_roc_operating_points':{},'retrospective_note':'Evaluation-score-derived thresholds describe ROC performance only; never used for training, selection or deployment.'}
    if (y==0).any() and (y==1).any() and ((y==0)&scorable).any():
        for key,cap in [('1pct',.01),('0_1pct',.001)]:
            result['retrospective_roc_operating_points'][key]=at_threshold(y,scores,threshold_at_fpr(y,scores,cap))
    else:result['retrospective_unavailable_reason']='Both classes, including scorable benign rows, are required to estimate an FPR-constrained ROC point.'
    return result
