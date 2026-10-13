"""Package the validation threshold without memorizing held-out legitimate domains."""
import hashlib
import json
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'evaluation/reports/2026-10-v3'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    report_path = REPORT / 'url_model_metrics.json'
    report = json.loads(report_path.read_text(encoding='utf-8'))
    selected = report['variants']['host_only']['models']['lightgbm_hand_features']
    threshold = selected['metrics']['threshold_at_fpr_le_0_1pct']
    source = ROOT / selected['path']
    if sha(source) != selected['metrics']['model_sha256']:
        raise ValueError('Candidate model hash does not match the validation report')
    artifact = joblib.load(source)
    artifact['thresholds'] = {'medium': float(threshold)}
    artifact_path = ROOT / 'ml/models/url_host_v3.joblib'
    joblib.dump(artifact, artifact_path)
    model_hash = sha(artifact_path)
    report['deployment'] = {
        'variant': 'host_only', 'model': 'lightgbm_hand_features',
        'selection_reason': 'Highest host-only validation recall at FPR <= 0.1%, with CPU p95 below 300 ms',
        'threshold': float(threshold),
        'threshold_source': 'validation recall-maximizing at FPR <= 0.1%',
        'artifact_sha256': model_hash,
        'psl_sha256': sha(REPORT / 'public_suffix_list.dat'),
        'tranco_allowlist_used': False,
        'model_only_corroboration_exclusions': [
            'Hosts in the existing verified official-brand registry, uniformly for all brands',
            'Hosts in the existing shared-hosting registry (host-only features cannot distinguish hosted paths)'
        ]
    }
    report['model_sha256'] = model_hash
    report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    prediction_path = REPORT / 'url_validation_predictions.json'
    pred = json.loads(prediction_path.read_text(encoding='utf-8'))
    pred['model_sha256'] = model_hash
    prediction_path.write_text(json.dumps(pred, separators=(',', ':')), encoding='utf-8')
    print(json.dumps({'threshold': threshold, 'model_sha256': model_hash,
                      'data_sha256': report['data_sha256']}, indent=2))


if __name__ == '__main__':
    main()
