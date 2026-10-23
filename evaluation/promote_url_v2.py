"""Package the recorded v2 policy without fitting or choosing new thresholds."""
import hashlib
import json
from pathlib import Path
import sys
import joblib

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
OUT = ROOT / 'evaluation/reports/2026-10-v4'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    report = json.loads((OUT / 'url_v2_comparison.json').read_text())
    assert sha(OUT / 'url_selection_rule_v2.md') == report['rule_sha256']
    selected = report['selection']['deployed_candidate']
    policy = report['selection']['deployed_policy']
    assert policy == 'corroboration_only' or (selected['passes_model_v2'] and selected['passes_integrated_v2'])
    source = ROOT / selected['artifact_path']
    assert sha(source) == selected['artifact_sha256']
    artifact = joblib.load(source)
    frozen = json.loads((OUT / 'url_v2_frozen_thresholds.json').read_text())
    record = next(r for r in frozen['models'] if r['sha256'] == selected['artifact_sha256'])
    assert any(t['threshold'] == selected['threshold'] for t in record['thresholds'])
    artifact['thresholds'] = {**artifact.get('thresholds', {}), 'medium': selected['threshold']}
    artifact['deployment_schema'] = {'representation': record['representation'], 'phresh_schema': record['phresh_schema']}
    target = ROOT / 'ml/models/url_host_v3.joblib'
    joblib.dump(artifact, target, compress=3)
    runtime = ROOT / 'backend/app/engines/risk_scoring.py'
    text = runtime.read_text(encoding='utf-8')
    import re
    text, replaced = re.subn(r"URL_MODEL_POLICY = '[a-z_]+'", f"URL_MODEL_POLICY = '{policy}'", text)
    assert replaced == 1
    runtime.write_text(text, encoding='utf-8', newline='\n')
    metadata = {'selected': selected['artifact_path'], 'artifact_sha256': sha(target),
                'source_artifact_sha256': selected['artifact_sha256'], 'threshold': selected['threshold'],
                'representation': record['representation'], 'policy': policy,
                'protocol_sha256': report['protocol_sha256'], 'data_sha256': report['data_sha256'],
                'selection_rule_path': 'evaluation/reports/2026-10-v4/url_selection_rule_v2.md',
                'selection_rule_sha256': report['rule_sha256'],
                'frozen_thresholds_sha256': report['frozen_thresholds_sha256'],
                'report': 'evaluation/reports/2026-10-v4/url_v2_comparison.json',
                'passes_model_v2': selected['passes_model_v2'],
                'passes_integrated_v2': selected['passes_integrated_v2'] if policy == 'ordinary' else selected['passes_corroboration_v2'],
                'fallback': policy == 'corroboration_only', 'sealed_test_run': False,
                'limitations': 'Exposed selection evidence; URL-only cohorts, healthy empty blacklist; no Egyptian SMS validation.'}
    for path in [ROOT / 'ml/models/url_host_deployment.json', OUT / 'deployment.json']:
        path.write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(metadata))


if __name__ == '__main__':
    main()
