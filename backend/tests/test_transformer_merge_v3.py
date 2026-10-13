"""Temporary merge-contract fixtures; these are never reported as transformer results."""
import json
from pathlib import Path

import pytest

from evaluation import merge_transformer_predictions as merge

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / 'evaluation/reports/2026-10-v3'


def prepare(tmp_path, monkeypatch):
    for name in ('text_split.json', 'text_local_metrics.json', 'model_selection_rule.json'):
        (tmp_path / name).write_bytes((REPORT / name).read_bytes())
    pred = tmp_path / 'predictions'
    pred.mkdir()
    base = json.loads((REPORT / 'predictions/char_tfidf_logistic_seed42.json').read_text())
    measured = json.loads((REPORT / 'text_local_metrics.json').read_text())['models']['char_tfidf_logistic']
    for model in ('marbertv2', 'camelbert_da'):
        for seed in (42, 43, 44):
            obj = dict(base, model=model, seed=seed, runtime='local',
                       model_size_bytes=measured['model_size_bytes'], cpu_latency=measured['latency'])
            (pred / f'{model}_seed{seed}.json').write_text(json.dumps(obj))
    monkeypatch.setattr(merge, 'REPORT', tmp_path)
    monkeypatch.setattr(merge, 'PRED', pred)
    return pred


def test_merge_accepts_matching_rows_and_retains_seed_results(tmp_path, monkeypatch):
    prepare(tmp_path, monkeypatch)
    merge.main()
    result = json.loads((tmp_path / 'combined_model_comparison.json').read_text())
    assert result['final_test_run'] is False
    assert len(result['transformer_models']['marbertv2']['seeds']) == 3
    assert len(result['local_models']) == 5


def test_merge_rejects_duplicate_validation_rows(tmp_path, monkeypatch):
    pred = prepare(tmp_path, monkeypatch)
    path = pred / 'marbertv2_seed42.json'
    obj = json.loads(path.read_text())
    obj['rows'].append(obj['rows'][0])
    path.write_text(json.dumps(obj))
    with pytest.raises(ValueError, match='duplicates'):
        merge.main()
