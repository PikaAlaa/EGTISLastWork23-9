"""Verify only the deployed winner against frozen scores; no cohort reevaluation."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]

import joblib
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from threadpoolctl import threadpool_limits
from app.core.database import Base
from app.core.exceptions import InvalidScanInputError
from app.engines import risk_scoring, url_model
from app.services.registry import populate_registry

OUT = ROOT / 'evaluation/reports/2026-10-v4'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(output):
    metadata = json.loads((ROOT / 'ml/models/url_host_deployment.json').read_text())
    decision = json.loads((OUT / 'url_v4_decision.json').read_text())
    selected = decision['selected_candidate']
    assert metadata['candidate_id'] == selected['id']
    assert metadata['source_artifact_sha256'] == selected['artifact_sha256']
    assert metadata['threshold'] == selected['threshold']
    assert metadata['input_mode'] == selected['input_mode'] == 'host_path'
    assert metadata['policy'] == risk_scoring.URL_MODEL_POLICY == 'ordinary'
    assert sha(url_model.ARTIFACT) == metadata['artifact_sha256']
    inventory = json.loads((ROOT / metadata['frozen_thresholds_path']).read_text())
    assert sha(ROOT / metadata['frozen_thresholds_path']) == decision['frozen_thresholds_sha256']
    prepared = ROOT / 'evaluation/local-results/v4/prepared.joblib'
    assert sha(prepared) == inventory['prepared_cache_sha256']
    # This existing prepared cache contains URL/label projections, never HTML.
    data = joblib.load(prepared)
    source = joblib.load(ROOT / metadata['selected'])
    packaged = url_model._load()
    assert sha(ROOT / metadata['selected']) == metadata['source_artifact_sha256']
    assert source['classifier'].booster_.model_to_string() == packaged['classifier'].booster_.model_to_string()
    assert joblib.hash(source['vectorizer']) == joblib.hash(packaged['vectorizer'])
    report = dict(candidate_id=selected['id'], artifact_sha256=metadata['artifact_sha256'],
                  policy=metadata['policy'], input_mode=metadata['input_mode'],
                  threshold=metadata['threshold'], weights_and_vectorizer_unchanged=True,
                  method='Boundary/random samples of recorded winner only; existing frozen predictions, no evaluation rerun',
                  destination_requests=0, sealed_test_run=False, cohorts={})
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db, patch.object(risk_scoring, 'blacklist_health',
                return_value={'available': True, 'reason': None}):
            populate_registry(db)
            for name, frame in data['tests'].items():
                assert 'html' not in frame.columns
                saved = np.load(ROOT / 'evaluation/local-results/v4-selection' /
                                (selected['artifact_sha256'] + '_host_path_' + name + '.npz'))
                b = np.load(ROOT / 'evaluation/local-results/v4-v3' / (name + '_components.npz'))
                assert np.array_equal(saved['row_id'], frame.row_id.to_numpy(dtype=str))
                assert np.array_equal(b['row_id'], saved['row_id'])
                p, threshold = saved['score'], selected['threshold']
                # Cached non-model components use the accepted four structural flags.
                baseline = b['valid'] & (b['brand'] | ((b['bits'] & 15) != 0))
                raw = np.isfinite(p) & (p >= threshold)
                expected = baseline | (b['eligible'] & raw)
                indices = np.unique(np.concatenate([
                    np.argsort(np.abs(p - threshold))[:75],
                    np.random.default_rng(42).choice(len(frame), min(50, len(frame)), replace=False),
                    np.flatnonzero(raw & ~baseline & frame.label_binary.eq(0).to_numpy())[:30],
                    np.flatnonzero((b['bits'] != 0) & ((b['bits'] & 15) == 0))[:15],
                    np.flatnonzero(b['official'])[:15], np.flatnonzero(~b['valid'])[:10]]))
                matched, abstentions, max_delta = 0, 0, 0.
                for idx in indices:
                    value = frame.iloc[idx].url.strip()
                    try:
                        actual = url_model.score_url(value)
                        assert actual is not None and np.isfinite(p[idx])
                        delta = abs(actual['probability'] - float(p[idx]))
                        assert delta < 1e-6 and actual['threshold'] == threshold
                        assert (actual['probability'] >= threshold) == bool(raw[idx])
                        max_delta = max(max_delta, delta)
                        scan = risk_scoring.calculate_final_risk_score(url=value, db=db)
                        assert (scan['verdict'] in {'MEDIUM', 'HIGH'}) == bool(expected[idx])
                        matched += 1
                    except InvalidScanInputError:
                        assert not b['valid'][idx] and not expected[idx]
                        abstentions += 1
                report['cohorts'][name] = dict(full_scanner_matches=matched, runtime_input_abstentions=abstentions,
                    mismatches=0, packaged_probability_max_difference=max_delta)
    finally:
        engine.dispose()
    report['passes'] = True
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUT / 'url_v4_release_scanner_verification.json')
    with threadpool_limits(limits=1):
        main(parser.parse_args().output)
