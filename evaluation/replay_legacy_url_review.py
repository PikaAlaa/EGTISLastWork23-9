"""Re-run the supplied baseline engine in a separate process on reconstructed development rows.
Pass the pristine ZIP extraction as --baseline; never overwrite its reports.
"""
import argparse,csv,hashlib,json,sys
from pathlib import Path
from urllib.parse import urlsplit,urlunsplit

def main():
    p=argparse.ArgumentParser();p.add_argument('--baseline',type=Path,required=True);a=p.parse_args()
    root=Path(__file__).resolve().parents[1];sys.path[:0]=[str(a.baseline/'backend'),str(a.baseline/'evaluation')]
    import pandas as pd
    from run_url_benchmark import benchmark
    kept=[]
    with (root/'evaluation/local-results/v3-data/dataset.csv').open(encoding='utf-8-sig',newline='') as stream:
        for row in csv.DictReader(stream):
            if row['split'] in {'train','val'} and row['content_type']=='url':kept.append(row)
    d=pd.DataFrame(kept);v=d[d.split=='val'].copy();known=d[(d.split=='train')&(d.label=='phishing')].text.tolist()
    full=benchmark(known,v)
    pathless=v.copy();pathless['text']=pathless.text.map(lambda u:urlunsplit((urlsplit(u).scheme,urlsplit(u).netloc,'/','','')))
    no_paths=benchmark(known,pathless)
    # A host-only policy probe preserves authority but fixes scheme to https and removes path/query.
    # Existing blacklist remains frozen. This is a diagnostic input transform, not a genuine-data addition.
    bare=v.copy();bare['text']=bare.text.map(lambda u:'https://'+urlsplit(u).netloc+'/')
    stripped=benchmark(known,bare)
    baseline=json.loads((a.baseline/'evaluation/reports/reviewed-2026-10-08/url-development.json').read_text())['new_registered_domains']
    import importlib.metadata as md
    out={'stage':'development_reconstructed_baseline','final_test_run':False,'full_url_legacy':full,'pathless_preserving_scheme_legacy':no_paths,'host_only_input_legacy':stripped,
      'original_report':baseline,'matches_original_aggregate_confusion':full['medium_or_high']['confusion']==baseline['medium_or_high']['confusion'],
      'identity_limitation':'Original baseline lacks row-level IDs. Matching aggregate counts, if observed, does not prove identical membership.',
      'transform':'https scheme, original authority, / root; no path/query/fragment; original frozen blacklist and rules.',
      'data_sha256':hashlib.sha256(json.dumps([{'id':r.id,'sha256':hashlib.sha256(r.text.encode()).hexdigest(),'split':r.split} for r in d.itertuples()],sort_keys=True).encode()).hexdigest(),
      'model_sha256':None,'baseline_risk_scoring_sha256':hashlib.sha256((a.baseline/'backend/app/engines/risk_scoring.py').read_bytes()).hexdigest(),
      'libraries':{n:md.version(n) for n in ['pandas','scikit-learn','SQLAlchemy','tldextract']}}
    output=root/'evaluation/reports/2026-10-v3/review-2026-10-13/legacy_url_replay.json'
    output.write_text(json.dumps(out,indent=2),encoding='utf-8');print(json.dumps(out,indent=2))

if __name__=='__main__':main()
