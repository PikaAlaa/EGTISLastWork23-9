"""Promote only the v4 rule's recorded winner, without fitting or retuning."""
import hashlib
import json
import shutil
from pathlib import Path
import joblib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v4'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    results = json.loads((OUT / 'url_comparison.json').read_text())
    assert sha(OUT / 'url_selection_rule.md') == results['selection_rule_sha256']
    winner = results['selection']['winner']
    if not results['selection']['promote_new_model']:
        raise ValueError('No new winner authorized by the frozen rule')
    selected = results['models'][winner]
    assert selected['passes_subdomain_gate']
    source = ROOT / selected['artifact_path']
    assert sha(source) == selected['model_sha256']
    artifact = joblib.load(source)
    if (artifact.get('research_feature_version'), artifact.get('representation'), artifact.get('model')) != (
            'phresh-1', 'host_only', 'char_calibrated_svm'):
        raise ValueError('Winner needs runtime feature-schema integration before promotion')
    assert artifact['thresholds']['medium'] == selected['thresholds'][selected['deployment_point']]
    target = ROOT / 'ml/models/url_host_v3.joblib'
    prior = ROOT / 'release-artifacts/prior-deployment/url_host_v3.joblib'
    prior.parent.mkdir(parents=True, exist_ok=True)
    expected_prior = json.loads((OUT / 'probe_before.json').read_text())['artifact_sha256']
    if not prior.exists():
        assert sha(target) == expected_prior
        shutil.copy2(target, prior)
    assert sha(prior) == expected_prior
    shutil.copy2(source, target)
    assert sha(target) == selected['model_sha256']
    metadata = {'selected': winner, 'artifact_sha256': sha(target), 'prior_artifact_sha256': sha(prior),
                'threshold': selected['thresholds'][selected['deployment_point']],
                'protocol_sha256': results['protocol_sha256'], 'data_sha256': results['data_sha256'],
                'selection_rule_sha256': results['selection_rule_sha256'],
                'report': 'evaluation/reports/2026-10-v4/url_comparison.json',
                'operating_point': selected['deployment_point'], 'sealed_test_run': False,
                'policy': 'Existing URL supporting policy and official/shared-host suppression; fallback not required.',
                'limitations': 'Exposed external-test model selection; not independent final or Egyptian-traffic validation.'}
    (ROOT / 'ml/models/url_host_deployment.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    (OUT / 'deployment.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(metadata))


if __name__ == '__main__':
    main()
