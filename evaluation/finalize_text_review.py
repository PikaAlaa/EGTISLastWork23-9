"""Replay candidate probes with the final shared URL artifact; preserve completed LOSO fits."""
import importlib.util,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'backend')]
import joblib
import numpy as np
from evaluation.review_common import OUT,PREVIOUS,write,sha,PROVENANCE
from evaluation.run_text_review import load_bilstm,probe_results

def main():
    result=json.loads((OUT/'text_review_metrics.json').read_text(encoding='utf-8'))
    assert result['status']=='COMPLETE'
    rule=json.loads((OUT/'model_selection_rule.json').read_text())
    assert result['rule_sha256']==sha(OUT/'model_selection_rule.json')
    spec=importlib.util.spec_from_file_location('cases',ROOT/'evaluation/review-evidence/cases.py')
    cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)
    for name,m in result['models'].items():
        path=PREVIOUS/'models'/('bilstm_candidate.keras' if name=='bilstm' else name+'.joblib')
        assert sha(path)==m['model_sha256']
        model=load_bilstm(path) if name=='bilstm' else joblib.load(path)['pipeline']
        m['everyday']=probe_results(model,m['validation']['metrics']['threshold_at_recall_95'],cases.EVERYDAY_SMS)
        components={'source_mean_fnr':float(np.mean([1-r['held_source']['phishing_recall'] for r in m['loso'].values()])),
          'source_mean_fpr':float(np.mean([r['held_source']['legitimate_fpr'] for r in m['loso'].values()])),
          'everyday_alert_rate':m['everyday']['medium_or_high_rate']}
        m['primary_loss_components']=components;m['primary_loss']=sum(components.values())/3
    eligible=[n for n,m in result['models'].items() if m['latency']['p95_ms']<=300 and m['everyday']['incomplete_n']==0]
    best=min(result['models'][n]['primary_loss'] for n in eligible)
    tied=[n for n in eligible if result['models'][n]['primary_loss']<=best+rule['tie_tolerance']]
    result['provisional_winner']=min(tied,key=lambda n:(-result['models'][n]['validation']['metrics']['macro_f1_at_recall_95'],rule['simplicity_order'].index(n)))
    result['probe_url_model_sha256']=sha(ROOT/'ml/models/url_host_v3.joblib')
    result['provenance']=PROVENANCE
    write('text_review_metrics.json',result)
    write('local_model_selection.json',{'winner':result['provisional_winner'],'rule_sha256':result['rule_sha256'],'final_choice':False,
      'model_sha256':result['models'][result['provisional_winner']]['model_sha256'],
      'provenance':PROVENANCE,'final_choice_requires':'Transformer source-held-out and everyday results under the same rule, not validation predictions alone.'})
    print('PROVISIONAL_WINNER',result['provisional_winner'])

if __name__=='__main__':main()
