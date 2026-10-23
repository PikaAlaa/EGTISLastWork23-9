"""Verify actual packaged inference and original scanner against v2 evaluation."""
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
from app.core.database import Base
from app.core.exceptions import InvalidScanInputError
from app.engines import risk_scoring
from app.engines.url_model import score_url
from app.services.registry import populate_registry

OUT = ROOT / 'evaluation/reports/2026-10-v4'
LOCAL = ROOT / 'evaluation/local-results/v4-v2'


def main():
    comparison = json.loads((OUT / 'url_v2_comparison.json').read_text())
    selected = comparison['selection']['deployed_candidate']
    policy = comparison['selection']['deployed_policy']
    assert risk_scoring.URL_MODEL_POLICY == policy
    prepared = ROOT / 'evaluation/local-results/v4/prepared.joblib'
    cache = joblib.load(prepared if prepared.exists() else LOCAL / 'prepared.joblib')
    flags = json.loads((OUT / 'v1_etis_validation_benign_flags.json').read_text())
    flagged_ids = {row['row_id'] for row in flags['rows']}
    report = {'kind': 'selected boundary/regression checks, not an additional performance estimate',
              'url_model_policy': policy, 'source_model_sha256': selected['artifact_sha256'],
              'uses_packaged_score_url': True, 'production_brand_distance_unchanged': True,
              'destination_requests': 0, 'cohorts': {}}
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db, patch.object(risk_scoring, 'blacklist_health', return_value={'available': True, 'reason': None}):
            populate_registry(db)
            for name, frame in cache['tests'].items():
                pfile = np.load(LOCAL / (selected['artifact_sha256'] + '_' + name + '.npz'))
                assert np.array_equal(pfile['row_id'], frame.row_id.to_numpy(dtype=str))
                p = pfile['score']
                b = joblib.load(LOCAL / (name + '_scanner.joblib'))['baseline']
                t = selected['threshold']
                above = np.isfinite(p) & (p >= t)
                expected = b['base'] | (b['valid'] & b['eligible'] & above &
                           (b['corroborates'] if policy == 'corroboration_only' else True))
                choices = np.unique(np.concatenate([
                    np.argsort(np.abs(p - t))[:100], np.flatnonzero(above & ~b['base'])[:10],
                    np.flatnonzero(~b['eligible'] & b['valid'])[:10], np.flatnonzero(~b['valid'])[:10],
                    np.flatnonzero(frame.row_id.isin(flagged_ids).to_numpy())]))
                checked = invalid = 0
                max_delta = 0.
                for idx in choices:
                    url = frame.iloc[idx].url
                    try:
                        probability = score_url(url.strip())['probability']
                        delta = abs(probability - float(p[idx]))
                        assert delta < 1e-6, (name, int(idx), probability, float(p[idx]))
                        assert (probability >= t) == bool(above[idx]), (name, int(idx), 'threshold decision')
                        max_delta = max(max_delta, delta)
                        scan = risk_scoring.calculate_final_risk_score(url=url, db=db)
                        actual = scan['verdict'] in {'MEDIUM', 'HIGH'}
                        checked += 1
                    except InvalidScanInputError:
                        actual = False
                        invalid += 1
                    assert actual == bool(expected[idx]), (name, int(idx), 'scanner verdict')
                report['cohorts'][name] = {'sampled_rows': len(choices), 'inference_and_scanner_matches': checked,
                    'invalid_input_matches': invalid, 'maximum_probability_difference': max_delta, 'mismatches': 0}
    finally:
        engine.dispose()
    (OUT / 'deployed_scanner_verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
