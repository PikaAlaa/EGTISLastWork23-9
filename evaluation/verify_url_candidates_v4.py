"""Check unchanged source-model/schema, frozen scores, and real runtime parity."""
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
import joblib
import numpy as np
from threadpoolctl import threadpool_limits
from app.core.exceptions import InvalidScanInputError
from app.engines import url_model, risk_scoring
from app.core.database import Base
from app.services.registry import populate_registry
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from evaluation import run_url_followup_v3 as v3
from evaluation.run_url_selection_v4 import frozen, load_inputs, predict, sha, FROZEN, OUT, LOCAL


def verify_scanner(frame, p, t, name):
    b = dict(np.load(v3.LOCAL / (name + '_components.npz')))
    assert np.array_equal(b['row_id'], frame.row_id.to_numpy(dtype=str))
    baseline = b['valid'] & (b['brand'] | v3.pattern_alerts(b['bits'], 'four_structural_only'))
    raw = np.isfinite(p) & (p >= t)
    ids = np.unique(np.concatenate([np.argsort(np.abs(p - t))[:10],
        np.random.default_rng(42).choice(len(frame), min(5, len(frame)), replace=False),
        np.flatnonzero(raw & ~baseline & frame.label_binary.eq(0).to_numpy())[:5],
        np.flatnonzero((b['bits'] != 0) & ~v3.pattern_alerts(b['bits'], 'four_structural_only'))[:5],
        np.flatnonzero(~b['valid'])[:5]]))
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    results = {}
    try:
        with Session(engine) as db, v3.accelerated_brands(), patch.object(risk_scoring, 'blacklist_health',
                return_value={'available': True, 'reason': None}):
            populate_registry(db)
            for policy in ['ordinary', 'corroboration_only', 'no_model']:
                expected = baseline | (b['eligible'] & raw) if policy == 'ordinary' else baseline
                mismatches = 0
                with patch.object(risk_scoring, 'URL_MODEL_POLICY', 'ordinary' if policy == 'ordinary' else 'corroboration_only'):
                    for idx in ids:
                        finding = {'probability': float(p[idx]), 'threshold': t} if np.isfinite(p[idx]) and policy != 'no_model' else None
                        with patch.object(risk_scoring, 'score_url', return_value=finding):
                            try:
                                scan = risk_scoring.calculate_final_risk_score(url=frame.iloc[idx].url, db=db)
                                actual = scan['verdict'] in {'MEDIUM', 'HIGH'}
                            except InvalidScanInputError:
                                actual = False
                        mismatches += actual != bool(expected[idx])
                results[policy] = dict(checks=len(ids), mismatches=int(mismatches))
    finally:
        engine.dispose()
    return results


def main():
    inventory = frozen()
    data, extractor, pools = load_inputs()
    report = dict(rule_sha256=inventory['rule_sha256'], frozen_thresholds_sha256=sha(FROZEN),
                  source_weights_unchanged=True, runtime_preprocessor_sha256=sha(ROOT / 'backend/app/engines/url_model.py'),
                  method='Boundary/random probability samples per calibration/evaluation cohort and threshold; sampled full-scanner factoring checks under all three policies',
                  destination_requests=0, candidates=[])
    for record in inventory['models']:
        # Verification may trail the evaluator without rescoring or changing a
        # decision. A model entry appears only after all its score files close.
        while True:
            try:
                comparison = json.loads((OUT / 'url_v4_comparison.json').read_text())
                ready = any(c['artifact_sha256'] == record['sha256'] and c['input_mode'] == record['input_mode']
                            for c in comparison['candidates'])
            except (FileNotFoundError, json.JSONDecodeError):
                ready = False
            if ready:
                break
            time.sleep(2)
        artifact = joblib.load(ROOT / record['path'])
        assert sha(ROOT / record['path']) == record['sha256']
        artifact['deployment_schema'] = {k: record[k] for k in ['representation', 'phresh_schema', 'input_mode']}
        artifact['artifact_sha256'] = record['sha256']
        frames = {**data['tests'], 'calibration': pools[record['setting']]}
        predictions = {}
        for name, frame in frames.items():
            if name == 'calibration':
                if record['input_mode'] == 'host_path':
                    saved = np.load(LOCAL / (record['sha256'] + '_host_path_cal.npz'))
                    assert np.array_equal(saved['row_id'], frame.row_id.to_numpy(dtype=str))
                    p = saved['score']
                else:
                    # Only parity samples, never any threshold selection.
                    p = predict(artifact, record, frame, extractor)
            else:
                saved = np.load(LOCAL / (record['sha256'] + '_' + record['input_mode'] + '_' + name + '.npz'))
                assert np.array_equal(saved['row_id'], frame.row_id.to_numpy(dtype=str))
                p = saved['score']
            predictions[name] = p
        for point in record['thresholds']:
            t = point['threshold']
            artifact['thresholds'] = {**artifact.get('thresholds', {}), 'medium': t}
            cohorts = {}
            for name, frame in frames.items():
                p = predictions[name]
                ids = np.unique(np.concatenate([np.argsort(np.abs(p - t))[:15],
                    np.random.default_rng(42).choice(len(frame), min(15, len(frame)), replace=False)]))
                matched, runtime_abstentions, mismatches, max_delta = 0, 0, 0, 0.
                with patch.object(url_model, '_load', return_value=artifact):
                    for idx in ids:
                        try:
                            actual = url_model.score_url(frame.iloc[idx].url.strip())
                        except InvalidScanInputError:
                            runtime_abstentions += 1
                            continue
                        expected = p[idx]
                        if actual is None or not np.isfinite(expected):
                            mismatches += int(actual is not None or np.isfinite(expected))
                            continue
                        delta = abs(actual['probability'] - float(expected))
                        max_delta = max(delta, max_delta)
                        mismatches += int(delta >= 1e-6 or (actual['probability'] >= t) != (expected >= t))
                        matched += 1
                cohorts[name] = dict(matched=matched, runtime_input_abstentions=runtime_abstentions,
                    mismatches=mismatches, max_probability_delta=max_delta)
                if name != 'calibration':
                    cohorts[name]['full_scanner'] = verify_scanner(frame, p, t, name)
            report['candidates'].append(dict(artifact_sha256=record['sha256'], input_mode=record['input_mode'],
                threshold=t, cohorts=cohorts, passes=not any(c['mismatches'] or
                    any(s['mismatches'] for s in c.get('full_scanner', {}).values()) for c in cohorts.values())))
        print('PARITY', record['input_mode'], record['path'], flush=True)
        report['complete'] = False
        (OUT / 'url_v4_runtime_parity.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    frozen()
    report['complete'] = True
    report['passes'] = all(c['passes'] for c in report['candidates'])
    (OUT / 'url_v4_runtime_parity.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return int(not report['passes'])


if __name__ == '__main__':
    with threadpool_limits(limits=1):
        raise SystemExit(main())
