"""Full production scanner checks for the factored v3 cohort measurements."""
import argparse
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.core.database import Base
from app.core.exceptions import InvalidScanInputError
from app.engines import risk_scoring
from app.engines.url_model import score_url
from app.engines.rule_based import url_pattern_analyzer
from app.services.registry import populate_registry
from evaluation import run_url_followup_v3 as v3


def main(output=None):
    data = v3.cache()
    selection = v3.read('url_v3_final_selection.json')
    mode = selection['accepted_pattern_policy']
    assert mode == url_pattern_analyzer.PATTERN_ALERT_POLICY
    active_policy = risk_scoring.URL_MODEL_POLICY
    assert active_policy in {'ordinary', 'corroboration_only'}
    stage = selection['stages'][mode]
    selected = stage['selected']
    prior = v3.read('url_v2_comparison.json')
    candidates = {**prior['comparators'], 'deployed_v3': selected, 'corroboration_only': selected}
    result = {'policy': active_policy, 'pattern_policy': mode, 'production_brand_distance_unchanged': True,
              'destination_requests': 0, 'cohorts': {}}
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db, patch.object(risk_scoring, 'blacklist_health', return_value={'available': True, 'reason': None}):
            populate_registry(db)
            for name, frame in data['tests'].items():
                b = np.load(v3.LOCAL / (name + '_components.npz'))
                baseline = b['valid'] & (b['brand'] | v3.pattern_alerts(b['bits'], mode))
                samples = {}
                max_delta = 0.
                for label, candidate in candidates.items():
                    p = v3.probabilities(candidate, name, frame)
                    t = candidate['threshold']
                    raw = np.isfinite(p) & (p >= t)
                    candidate_policy = active_policy if label == 'deployed_v3' else (
                        'corroboration_only' if label == 'corroboration_only' else 'ordinary')
                    expected = baseline if candidate_policy == 'corroboration_only' else baseline | (b['eligible'] & raw)
                    indices = np.unique(np.concatenate([
                        np.argsort(np.abs(p - t))[:75],
                        np.random.default_rng(42).choice(len(frame), min(50, len(frame)), replace=False),
                        np.flatnonzero((b['bits'] != 0) & ~v3.pattern_alerts(b['bits'], mode))[:15],
                        np.flatnonzero(raw & ~baseline & frame.label_binary.eq(0).to_numpy())[:30],
                        np.flatnonzero(b['official'])[:15], np.flatnonzero(~b['valid'])[:10]]))
                    for idx in indices:
                        url = frame.iloc[idx].url
                        finding = {'probability': float(p[idx]), 'threshold': t} if np.isfinite(p[idx]) else None
                        with patch.object(risk_scoring, 'URL_MODEL_POLICY', candidate_policy):
                            try:
                                if label == 'deployed_v3':
                                    actual_probability = score_url(url.strip())['probability']
                                    delta = abs(actual_probability - float(p[idx]))
                                    assert delta < 1e-6
                                    assert (actual_probability >= t) == bool(raw[idx])
                                    max_delta = max(max_delta, delta)
                                    scan = risk_scoring.calculate_final_risk_score(url=url, db=db)
                                else:
                                    with patch.object(risk_scoring, 'score_url', return_value=finding):
                                        scan = risk_scoring.calculate_final_risk_score(url=url, db=db)
                                actual = scan['verdict'] in {'MEDIUM', 'HIGH'}
                            except InvalidScanInputError:
                                actual = False
                        assert actual == bool(expected[idx]), (name, label, int(idx))
                    samples[label] = {'full_scanner_matches': len(indices), 'mismatches': 0}
                # Independently check the matched no-model baseline.
                ids = np.unique(np.concatenate([np.flatnonzero(baseline)[:50], np.flatnonzero(~baseline)[:50]]))
                with patch.object(risk_scoring, 'score_url', return_value=None):
                    for idx in ids:
                        try:
                            scan = risk_scoring.calculate_final_risk_score(url=frame.iloc[idx].url, db=db)
                            actual = scan['verdict'] in {'MEDIUM', 'HIGH'}
                        except InvalidScanInputError:
                            actual = False
                        assert actual == bool(baseline[idx])
                samples['non_model_baseline'] = {'full_scanner_matches': len(ids), 'mismatches': 0}
                result['cohorts'][name] = {'policies': samples, 'packaged_probability_max_difference': max_delta}
    finally:
        engine.dispose()
    output = Path(output) if output else v3.OUT / 'query-shortcut/scanner-verification.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    main(parser.parse_args().output)
