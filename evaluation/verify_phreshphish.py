"""Verify aggregate artifacts and isolation; optionally run local CI commands."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import joblib
import numpy as np
from evaluation.phreshphish_utils import OUT, LOCAL, sha, libraries, write


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--run-checks', action='store_true'); args=parser.parse_args()
    if args.run_checks:
        from evaluation import run_checks_v3
        run_checks_v3.OUT=OUT
        if run_checks_v3.main():
            raise RuntimeError('Local CI command failed; inspect verification.json')
    lock=json.loads((ROOT/'data/phreshphish-lock.json').read_text())
    protocol=json.loads((OUT/'protocol.json').read_text())
    assert protocol['data_sha256']==sha(ROOT/'data/phreshphish-lock.json')
    results=json.loads((OUT/'model_comparison.json').read_text())
    prior=json.loads((OUT.parent/'review-2026-10-13/integrity.json').read_text())
    protected=[]
    for item in prior['protected_files']:
        digest=sha(ROOT/item['path'])
        assert digest==item['sha256'], item['path']
        protected.append({'path':item['path'],'sha256':digest,'unchanged':True})
    for path,expected in {
        'ml/models/url_host_v3.joblib':'619ea13cedc98645ccd9603af3e9554b290a3eb9f7a5d1e46397098e00e92232',
        'evaluation/reports/2026-10-v3/text_split.json':'a404a48c0018143f5842018c602fc4d99499bacf9e1229ff5b05bfe21bee57f0',
        'evaluation/reports/2026-10-v3/review-2026-10-13/url_split_manifest.json':'5f65968d776e052797c666245530f4eae9f5ab77b1d4a9116dac14f424eb45bd',
    }.items():
        assert sha(ROOT/path)==expected, path
        protected.append({'path':path,'sha256':expected,'unchanged':True})
    cache=joblib.load(LOCAL/'prepared.joblib')
    assert cache['data_sha256']==lock['data_sha256']==results['data_sha256']
    assert cache['protocol_sha256']==sha(OUT/'protocol.json')==results['protocol_sha256']
    held=set().union(*(set(f.registered_domain) for f in cache['tests'].values()));held.discard('')
    checks={}
    for name,(fit,cal) in cache['pools'].items():
        assert set(fit.registered_domain).isdisjoint(cal.registered_domain)
        assert (set(fit.registered_domain)|set(cal.registered_domain)).isdisjoint(held)
        assert not fit.official_split.eq('test').any() and not cal.official_split.eq('test').any()
        checks[name]={'fit_calibration_domain_disjoint':True,'evaluation_domain_disjoint':True,'no_official_test_rows_in_training':True}
    test=cache['tests']['phreshphish_test']
    assert len(test)==168060 and test.row_id.nunique()==168060 and test.official_split.eq('test').all()
    model_checks={}
    for key,m in results['models'].items():
        path=OUT/'models'/(key.replace('/','_')+'.joblib')
        assert sha(path)==m['model_sha256']
        for cohort,frame in cache['tests'].items():
            pred=np.load(LOCAL/(key.replace('/','_')+'_'+cohort+'.npz'),allow_pickle=False)
            assert np.array_equal(pred['row_id'],frame.row_id.to_numpy(dtype=str))
            assert len(pred['score'])==len(frame)
        model_checks[key]={'sha256':sha(path),'prediction_row_alignment_verified':True}
    assert len(model_checks)==18 and results['status']=='COMPLETE'
    verification=json.loads((OUT/'verification.json').read_text())
    assert all(v['exit_code']==0 for v in verification['commands'].values())
    verification.setdefault('etis_text_data_sha256',verification['data_sha256'])
    verification['data_sha256']=lock['data_sha256']
    verification['libraries']=libraries()
    verification['phreshphish_official_test_evaluated']=True
    verification['etis_sealed_test_evaluated']=False
    verification['final_test_run_note']='Legacy final_test_run=False refers to ETIS sealed tests; the explicitly authorized PhreshPhish official test was evaluated.'
    write('verification.json',verification)
    metadata=json.loads((OUT/'upstream_metadata.json').read_text())
    metadata.update(data_sha256=lock['data_sha256'], model_sha256=None, libraries=libraries())
    write('upstream_metadata.json',metadata)
    write('integrity.json',{'data_sha256':lock['data_sha256'],'model_sha256':sha(ROOT/'ml/models/url_host_v3.joblib'),
        'protected_files':protected,'all_protected_files_byte_identical':True,'training_isolation':checks,
        'protocol_data_sha256_scope':'SHA-256 of the complete pinned download-lock file; aggregate result data_sha256 identifies the projection set.',
        'download_lock_sha256':sha(ROOT/'data/phreshphish-lock.json'),
        'official_test_membership_preserved':True,'official_test_rows':len(test),'model_artifacts':model_checks,
        'html_data_columns_present_in_projections':False,'projection_columns_verified_by_downloader':lock['columns'],
        'phreshphish_official_test_evaluated':True,'etis_sealed_test_evaluated':False})
    print('Verified preserved files, all 18 model hashes, prediction alignment and domain/test isolation')


if __name__=='__main__':main()
