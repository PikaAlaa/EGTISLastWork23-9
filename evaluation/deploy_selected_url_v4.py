"""Package the recorded v4 winner; never evaluate, fit, rank or retune candidates."""
import hashlib
import json
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v4'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    decision = json.loads((OUT / 'url_v4_decision.json').read_text())
    selected = decision['selected_candidate']
    assert selected['id'] == decision['numerical_selection']['selected_id'] == 'ee0ba9f0077c1fd140aa'
    assert selected['input_mode'] == 'host_path'
    assert selected['threshold'] == 0.9870690448552604
    assert selected['passes_v3'] and selected['passes_query_invariance'] and selected['primary_eligible']
    rule = OUT / 'url_selection_rule_v4.md'
    frozen_path = OUT / 'url_v4_frozen_thresholds.json'
    assert sha(rule) == decision['rule_sha256']
    assert sha(frozen_path) == decision['frozen_thresholds_sha256']
    assert sha(frozen_path) == (OUT / 'url_v4_frozen_thresholds.sha256').read_text().strip()
    inventory = json.loads(frozen_path.read_text())
    record = next(r for r in inventory['models'] if r['sha256'] == selected['artifact_sha256']
                  and r['input_mode'] == selected['input_mode'])
    assert record['path'] == selected['artifact_path']
    assert record['preprocessing_sha256'] == selected['preprocessing_sha256']
    assert any(p['threshold'] == selected['threshold'] for p in record['thresholds'])
    source = ROOT / selected['artifact_path']
    assert sha(source) == selected['artifact_sha256']
    parity = json.loads((OUT / 'url_v4_runtime_parity.json').read_text())
    assert parity['complete']
    assert next(c for c in parity['candidates'] if c['artifact_sha256'] == selected['artifact_sha256']
                and c['input_mode'] == selected['input_mode'] and c['threshold'] == selected['threshold'])['passes']
    artifact = joblib.load(source)
    artifact['deployment_schema'] = {key: selected[key] for key in ('representation', 'phresh_schema', 'input_mode')}
    artifact['thresholds'] = {**artifact.get('thresholds', {}), 'medium': selected['threshold']}
    target = ROOT / 'ml/models/url_host_v3.joblib'
    joblib.dump(artifact, target)
    previous = json.loads((ROOT / 'ml/models/url_host_deployment.json').read_text())
    metadata = dict(selected=selected['artifact_path'], candidate_id=selected['id'],
                    artifact_sha256=sha(target), source_artifact_sha256=sha(source),
                    threshold=selected['threshold'], representation=selected['representation'],
                    input_mode=selected['input_mode'], phresh_schema=selected['phresh_schema'],
                    preprocessing_sha256=selected['preprocessing_sha256'], policy='ordinary',
                    pattern_policy=inventory['pattern_policy'],
                    selection_rule_path=rule.relative_to(ROOT).as_posix(), selection_rule_sha256=sha(rule),
                    frozen_thresholds_path=frozen_path.relative_to(ROOT).as_posix(),
                    frozen_thresholds_sha256=sha(frozen_path),
                    pattern_acceptance_rule_sha256=previous['pattern_acceptance_rule_sha256'],
                    pattern_training_proposal_sha256=previous['pattern_training_proposal_sha256'],
                    protocol_sha256=inventory['protocol_sha256'], data_sha256=inventory['data_sha256'],
                    report='evaluation/reports/2026-10-v4/REPORT.md',
                    numerical_decision='evaluation/reports/2026-10-v4/url_v4_decision.json',
                    owner_authorized_test_rewrite=True, historical_engineering_failures=29,
                    model_weights_fitted=False, thresholds_retuned=False, sealed_test_run=False,
                    limitations='Exposed development selection; sparse natural benign queries, no benign fragment coverage or genuine Egyptian SMS final test.')
    for path in [ROOT / 'ml/models/url_host_deployment.json', OUT / 'deployment.json']:
        path.write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8', newline='\n')
    assert sha(source) == selected['artifact_sha256']
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    main()
