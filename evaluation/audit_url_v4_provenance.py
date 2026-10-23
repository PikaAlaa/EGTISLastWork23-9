"""Aggregate coverage/schema provenance for the fixed v4 inventory; no rescoring."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
import joblib
import pandas as pd
from evaluation.run_url_selection_v4 import frozen, load_inputs, components, coverage, sha, OUT, FROZEN
from evaluation.run_phreshphish import fingerprint


def describe(frame):
    assert 'html' not in {str(c).lower() for c in frame.columns}
    return dict(fingerprint=fingerprint(frame), coverage=coverage(frame, components(frame)),
                registered_domains=int(frame.loc[frame.registered_domain.ne(''), 'registered_domain'].nunique()))


def main():
    inventory = frozen()
    data, _, pools = load_inputs()
    result = dict(rule_sha256=inventory['rule_sha256'], frozen_thresholds_sha256=sha(FROZEN),
                  frozen_git_bytes={}, pools={}, schemas=[], html_loaded=False, destination_requests=0,
                  sealed_test_run=False, genuine_egyptian_sms_test_count=0)
    for relative in ['evaluation/reports/2026-10-v4/url_selection_rule_v4.md',
                     'evaluation/reports/2026-10-v4/url_v2_frozen_thresholds.json',
                     'evaluation/reports/2026-10-v4/query-shortcut/query-fragment-counts.json',
                     'evaluation/probe_query_shortcut.py', 'evaluation/probe_legit_hosts.py',
                     'evaluation/targets.json']:
        prior = subprocess.check_output(['git', 'show', 'a80e790:' + relative], cwd=ROOT)
        current = (ROOT / relative).read_bytes()
        # Git may check out ordinary text with CRLF. Preserve the working-tree
        # bytes; record both hashes and require exact content after EOL handling.
        assert prior.replace(b'\r\n', b'\n') == current.replace(b'\r\n', b'\n'), relative
        result['frozen_git_bytes'][relative] = sha(ROOT / relative)
        result.setdefault('git_blob_sha256', {})[relative] = hashlib.sha256(prior).hexdigest()
    for setting, (fit, cal) in data['pools'].items():
        all_rows = pd.concat([fit, cal], ignore_index=True)
        result['pools'][setting] = dict(fit=describe(fit), calibration=describe(cal), union=describe(all_rows),
            phreshphish_only={name: describe(frame[frame.source.eq('phreshphish')])
                             for name, frame in [('fit', fit), ('calibration', cal), ('union', all_rows)]})
    result['historical_excluded_calibration'] = describe(pools['historical'])
    for record in inventory['models']:
        artifact = joblib.load(ROOT / record['path'])
        vec = artifact.get('vectorizer')
        if vec is None:
            vec = artifact['pipeline'].steps[0][1]
        names = list(map(str, vec.get_feature_names_out()))
        result['schemas'].append(dict(artifact_sha256=record['sha256'], input_mode=record['input_mode'],
            representation=record['representation'], phresh_schema=record['phresh_schema'],
            vectorizer_class=type(vec).__name__, fitted_feature_count=len(names),
            fitted_feature_schema_sha256=hashlib.sha256(json.dumps(names, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest(),
            preprocessing_sha256=record['preprocessing_sha256'], weights_unchanged=True))
    result['test'] = {name: describe(frame) for name, frame in data['tests'].items()}
    frozen()
    (OUT / 'url_v4_provenance.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
