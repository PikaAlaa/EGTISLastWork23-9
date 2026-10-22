"""Aggregate-only offline query audit of existing development data and predictions.

No fitting, threshold selection, row exports, final-test access or destination requests.
"""
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]

import joblib
import numpy as np
from app.engines.url_features import phresh_features
from app.engines.url_model import ARTIFACT, _extractor, _load

OUT = ROOT / 'evaluation/reports/2026-10-v4/query-shortcut'


def query_group(value):
    value = str(value)
    try:
        return 'query' if urlsplit(value if '://' in value else 'http://' + value).query else 'no_query'
    except ValueError:
        return 'unparseable'


def aggregate(frame, probabilities=None, components=None, threshold=None):
    groups = np.array([query_group(value) for value in frame.url])
    rows = []
    for source in sorted(frame.source.unique()):
        for label in [0, 1]:
            base = frame.source.eq(source).to_numpy() & frame.label_binary.eq(label).to_numpy()
            if not base.any():
                continue
            for group in ['query', 'no_query', 'unparseable']:
                mask = base & (groups == group)
                row = {'source': source, 'label': 'phishing' if label else 'benign',
                       'query_group': group, 'rows': int(mask.sum()),
                       'source_label_rows': int(base.sum()), 'fraction': float(mask.sum() / base.sum())}
                if probabilities is not None:
                    raw = np.isfinite(probabilities) & (probabilities >= threshold)
                    row.update(model_alerts=int((mask & raw).sum()),
                               model_alert_rate=float(raw[mask].mean()) if mask.any() else None,
                               model_abstentions=int((mask & ~np.isfinite(probabilities)).sum()))
                    if components is not None:
                        # Same accepted four structural flags as the deployment.
                        structural_bits = 1 | 2 | 4 | 8
                        baseline = components['valid'] & (components['brand'] | ((components['bits'] & structural_bits) != 0))
                        ordinary = baseline | (components['eligible'] & raw)
                        row.update(non_model_alerts=int((mask & baseline).sum()),
                                   ordinary_scanner_alerts=int((mask & ordinary).sum()),
                                   model_added_alerts=int((mask & ordinary & ~baseline).sum()))
                rows.append(row)
    assert sum(row['rows'] for row in rows) == len(frame)
    return rows


def main():
    metadata = json.loads((ROOT / 'ml/models/url_host_deployment.json').read_text())
    cache_path = ROOT / 'evaluation/local-results/v4/prepared.joblib'
    data = joblib.load(cache_path)
    artifact = _load()
    assert data['data_sha256'] == artifact['data_sha256'] == metadata['data_sha256']
    assert data['protocol_sha256'] == artifact['protocol_sha256'] == metadata['protocol_sha256']
    assert hashlib.sha256(ARTIFACT.read_bytes()).hexdigest() == metadata['artifact_sha256']
    assert metadata['pattern_policy'] == 'four_structural_only'
    threshold = artifact['thresholds']['medium']
    assert threshold == metadata['threshold']
    report = {'kind': 'aggregate audit of exposed development data; not independent final validation',
              'artifact_sha256': metadata['artifact_sha256'], 'source_artifact_sha256': metadata['source_artifact_sha256'],
              'data_sha256': data['data_sha256'], 'protocol_sha256': data['protocol_sha256'],
              'threshold': threshold, 'query_definition': 'nonempty urllib.parse.urlsplit query; same as frozen query_len feature',
              'thresholds_changed': False, 'models_fitted': 0, 'destination_requests': 0,
              'sealed_test_run': False, 'combined_pool': {}, 'cohorts': {}}
    fit, cal = data['pools']['combined']
    report['combined_pool']['fit'] = aggregate(fit)
    extractor = _extractor()
    scores = []
    for start in range(0, len(cal), 4096):
        batch = cal.iloc[start:start + 4096]
        features = [phresh_features(row.url, row.host, extractor, True) for row in batch.itertuples()]
        scores.extend(artifact['classifier'].predict_proba(artifact['vectorizer'].transform(features))[:, 1])
    report['combined_pool']['calibration'] = aggregate(cal, np.array(scores), threshold=threshold)
    for name, frame in data['tests'].items():
        path = ROOT / 'evaluation/local-results/v4-v2' / (metadata['source_artifact_sha256'] + '_' + name + '.npz')
        with np.load(path) as predictions, np.load(ROOT / 'evaluation/local-results/v4-v3' / (name + '_components.npz')) as components:
            assert np.array_equal(predictions['row_id'], frame.row_id.to_numpy(dtype=str))
            assert np.array_equal(components['row_id'], frame.row_id.to_numpy(dtype=str))
            report['cohorts'][name] = aggregate(frame, predictions['score'], components, threshold)
            if name == 'phreshphish_test':
                assert sum(row['model_alerts'] for row in report['cohorts'][name] if row['label'] == 'benign') == 48
    path = OUT / 'distribution.json'
    path.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'combined_pool': report['combined_pool'], 'cohorts': report['cohorts']}, indent=2))


if __name__ == '__main__':
    main()
