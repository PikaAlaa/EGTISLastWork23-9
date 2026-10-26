"""Contract-only invented fixtures; never retained or reported as model evidence."""
import copy
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from evaluation import merge_transformer_predictions as merge
from evaluation.build_transformer_colab_bundle import allowlisted_records, existing_probes
from evaluation.transformer_contract import (DIALECT, MODELS, SCHEMA, SEEDS, load_bundle, partitions,
                                            row_identity, sha, threshold95, validate_run, write_json)

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ['kaggle_arabic_phishing_fully_dataset', 'salloum_gaber_bilingual_corpus']


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    """A tiny temporary split, unrelated to the real frozen data or predictions."""
    bundle = tmp_path / 'bundle'; bundle.mkdir()
    report = tmp_path / 'report'; (report / 'review-2026-10-13').mkdir(parents=True)
    returned = tmp_path / 'returned'; returned.mkdir()
    frozen, rows = [], []
    for source in [*SOURCES, DIALECT]:
        for split in ['train', 'val']:
            for label in [0, 1]:
                ident = f'fixture-{len(frozen)}'
                text = 'Invented contract fixture ' + ident
                group = ident
                if source in SOURCES and split == 'train' and label == 0:
                    group = 'shared-source-training-group'
                item = dict(row_id=ident, content_sha256=hashlib.sha256(text.encode()).hexdigest(),
                            group_id=group, split=split, label='phishing' if label else 'legitimate',
                            source=source, language='en', content_type='text')
                frozen.append(item)
                if split == 'train' or source != DIALECT:
                    rows.append(dict(item, text=text, label=label))
    identity = hashlib.sha256(json.dumps(frozen, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    split = dict(rows=frozen, data_sha256=identity, text_split_sha256=identity, test_rows_included=False)
    rule = dict(data_sha256=identity, primary_sources=SOURCES, max_p95_cpu_ms=300,
                provenance={s: 'Invented contract-only fixture; not real SMS' for s in SOURCES})
    write_json(bundle / 'text_split.json', split); write_json(bundle / 'rows.json', rows)
    write_json(bundle / 'rule.json', rule)
    (bundle / 'rule.md').write_text('Temporary test-only rule fixture')
    probes = [dict(probe_index=i, text=t, content_sha256=hashlib.sha256(t.encode()).hexdigest())
              for i, t in enumerate(existing_probes(), 1)]
    write_json(bundle / 'probes.json', probes)
    for name in ['transformer_contract.py', 'transformer_colab.py']:
        shutil.copyfile(ROOT / 'evaluation' / name, bundle / name)
    shutil.copyfile(ROOT / 'backend/app/core/text_utils.py', bundle / 'text_utils.py')
    shutil.copyfile(ROOT / 'notebooks/transformer_compare.ipynb', bundle / 'transformer_compare.ipynb')
    shutil.copyfile(ROOT / 'docs/transformer-colab.md', bundle / 'README.md')
    write_json(bundle / 'manifest.json', dict(schema=SCHEMA, data_sha256=identity, sealed_test_included=False,
               local_replay_sha256={'evaluation/run_text_review.py': sha(ROOT / 'evaluation/run_text_review.py')},
               files={p.name: sha(p) for p in bundle.iterdir()}))
    for name in ['text_split.json', 'rule.json', 'rule.md']:
        dst = report / ('text_split.json' if name == 'text_split.json' else 'review-2026-10-13/model_selection_' + name)
        shutil.copyfile(bundle / name, dst)
    monkeypatch.setattr(merge, 'REPORT', report)
    for name in MODELS:
        for seed in SEEDS:
            obj = dict(schema=SCHEMA, model=name, model_id=MODELS[name], seed=seed,
                       runtime='colab', final_test_run=False, bundle_manifest_sha256=sha(bundle / 'manifest.json'),
                       input_policy='normalized-150-word-windows-stride75-maxprob-256tokens',
                       training=dict(epochs=3, learning_rate=2e-5, effective_batch_size=16, max_length=256, early_stopping=False),
                       libraries={'fixture': 'not transformer evidence'}, folds={})
            for key in ['full', *SOURCES]:
                train, valid, held = partitions(rows, None if key == 'full' else key)
                def scores(records):
                    return [dict(row_identity(r), score=.9 if r['label'] else .1) for r in records]
                obj['folds'][key] = dict(training_row_ids=[r['row_id'] for r in train],
                       training_group_ids=sorted({r['group_id'] for r in train}),
                       validation=scores(valid), held=scores(held), threshold_95=.9, model_sha256='a' * 64)
            _, valid, _ = partitions(rows)
            obj['probes'] = [dict(probe_index=p['probe_index'], content_sha256=p['content_sha256'], score=.05) for p in probes]
            obj['cpu_latency'] = dict(cpu_only=True, batch_size=1, warmup_n=3,
                       includes_tokenization_and_windows=True, separate_from_gpu_inference=True,
                       row_ids=[r['row_id'] for r in valid], durations_ms=[10.] * len(valid), p50_ms=10., p95_ms=10.,
                       cpu_description='TEST FIXTURE', torch_threads=2)
            write_json(returned / f'{name}_seed{seed}.json', obj)
    refresh_receipt(bundle, returned)
    return bundle, returned


def refresh_receipt(bundle, returned):
    write_json(returned / 'results_manifest.json', dict(schema=SCHEMA, final_test_run=False,
               bundle_manifest_sha256=sha(bundle / 'manifest.json'), complete=True,
               files={p.name: sha(p) for p in returned.glob('*_seed*.json')}))


def test_complete_import_replays_policy_without_selection(prepared):
    bundle, returned = prepared
    result = merge.import_results(bundle, returned)
    assert result['final_test_run'] is result['selection_performed'] is result['final_choice'] is False
    assert result['deployed_text_model_changed'] is False
    for model in result['models'].values():
        assert len(model['seeds']) == 3
        for run in model['seeds']:
            assert run['everyday']['n'] == 12 and run['everyday']['incomplete_n'] == 0
            assert 'cpu_p95_ms' not in run['everyday']
            assert set(run['loso']) == set(SOURCES)
            assert run['validation']['n'] == 4


def test_returned_hash_mismatch_rejected_before_policy_replay(prepared, monkeypatch):
    bundle, returned = prepared
    with (returned / 'marbertv2_seed42.json').open('a') as f: f.write(' ')
    monkeypatch.setattr(merge, 'replay_probes', lambda *args: pytest.fail('Replay must follow all validation'))
    with pytest.raises(ValueError, match='SHA-256 mismatch'): merge.import_results(bundle, returned)


@pytest.mark.parametrize('mutation,match', [
    ('duplicate', 'duplicates'), ('extra_id', 'row IDs'), ('content_hash', 'content hash'),
    ('label', 'label'), ('group', 'group'), ('split', 'split'), ('source', 'source'),
    ('training', 'training IDs'), ('missing_loso', 'LOSO'), ('threshold', 'threshold'),
    ('probe', 'probe content hash'), ('latency', 'CPU batch-one'), ('nan', 'invalid score'),
    ('seed', 'seed'), ('model', 'Model'), ('input_hash', 'manifest hash'),
    ('cpu_percentile', 'percentile'), ('cpu_nan', 'timing samples'),
])
def test_structural_mismatches_rejected_even_with_updated_file_hash(prepared, mutation, match):
    bundle, returned = prepared
    path = returned / 'marbertv2_seed42.json'
    obj = json.loads(path.read_text())
    rows = obj['folds']['full']['validation']
    if mutation == 'duplicate': rows.append(copy.deepcopy(rows[0]))
    elif mutation == 'extra_id': rows[0]['row_id'] = 'SEALED-OR-UNKNOWN-ID'
    elif mutation == 'content_hash': rows[0]['content_sha256'] = 'b' * 64
    elif mutation == 'label': rows[0]['label'] = 1 - rows[0]['label']
    elif mutation == 'group': rows[0]['group_id'] = 'changed'
    elif mutation == 'split': rows[0]['split'] = 'test'
    elif mutation == 'source': rows[0]['source'] = 'changed'
    elif mutation == 'training': obj['folds'][SOURCES[0]]['training_row_ids'].append('held-source-row')
    elif mutation == 'missing_loso': del obj['folds'][SOURCES[0]]
    elif mutation == 'threshold': obj['folds'][SOURCES[0]]['threshold_95'] = .99
    elif mutation == 'probe': obj['probes'][0]['content_sha256'] = 'b' * 64
    elif mutation == 'latency': obj['cpu_latency']['cpu_only'] = False
    elif mutation == 'nan': rows[0]['score'] = float('nan')
    elif mutation == 'seed': obj['seed'] = 99
    elif mutation == 'model': obj['model_id'] = 'wrong/model'
    elif mutation == 'input_hash': obj['bundle_manifest_sha256'] = 'b' * 64
    elif mutation == 'cpu_percentile': obj['cpu_latency']['p95_ms'] = 900
    elif mutation == 'cpu_nan': obj['cpu_latency']['durations_ms'][0] = float('nan')
    write_json(path, obj); refresh_receipt(bundle, returned)
    with pytest.raises(ValueError, match=match): merge.import_results(bundle, returned)


def test_stale_input_bundle_rejected(prepared):
    bundle, returned = prepared
    with (bundle / 'rows.json').open('a') as f: f.write(' ')
    with pytest.raises(ValueError, match='Bundle SHA-256'): merge.import_results(bundle, returned)


def test_validation_only_returns_rejected(prepared):
    bundle, returned = prepared
    (returned / 'camelbert_da_seed44.json').unlink()
    refresh_receipt(bundle, returned)
    with pytest.raises(ValueError, match='Six complete'): merge.import_results(bundle, returned)


def test_source_group_exclusion_and_training_only_validation(prepared):
    bundle, _ = prepared
    _, rows, _, _ = load_bundle(bundle)
    train, valid, held = partitions(rows, SOURCES[0])
    assert all(r['source'] != SOURCES[0] for r in train + valid)
    assert {r['group_id'] for r in train + valid}.isdisjoint({r['group_id'] for r in held})
    assert any(r['source'] == DIALECT for r in train)
    assert all(r['source'] != DIALECT for r in valid)


def test_csv_skips_unlisted_undecodable_text_and_handles_multiline(tmp_path):
    path = tmp_path / 'local.csv'
    path.write_bytes(b'id,text,split\r\nSEALED,"\xff\nnot text to decode",test\r\n'
                     b'ALLOW,"existing\r\ntext with ""quotes""",train\r\n')
    rows = list(allowlisted_records(path, {'ALLOW'}))
    assert rows == [dict(id='ALLOW', text='existing\r\ntext with "quotes"', split='train')]


def test_threshold_is_highest_feasible_recall_point():
    rows = [dict(label=1, score=i / 100) for i in range(1, 21)]
    assert threshold95(rows) == .02


def test_import_cannot_write_reviewed_reports():
    with pytest.raises(ValueError, match='reviewed reports are read-only'):
        merge.main(['--output', str(ROOT / 'evaluation/reports/2026-10-v3/transformer_comparison.json')])
