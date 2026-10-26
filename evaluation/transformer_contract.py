"""Offline input/output contract shared by the Colab runner and local importer."""
import hashlib
import json
import math
from pathlib import Path

MODELS = {
    'marbertv2': 'UBC-NLP/MARBERTv2',
    'camelbert_da': 'CAMeL-Lab/bert-base-arabic-camelbert-da',
}
SEEDS = (42, 43, 44)
DIALECT = 'kaggle_dialectal_arabic_sms'
SCHEMA = 'etis-text-transformers-phase1-v1'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write_json(path, obj):
    Path(path).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def threshold95(rows):
    positives = [r['score'] for r in rows if r['label'] == 1]
    require(bool(positives), 'Threshold validation has no phishing rows')
    return max(t for t in set(positives)
               if sum(p >= t for p in positives) / len(positives) >= .95)


def partitions(rows, held=None):
    held_rows = [r for r in rows if r['source'] == held] if held else []
    excluded_groups = {r['group_id'] for r in held_rows}
    available = [r for r in rows if r['source'] != held and r['group_id'] not in excluded_groups]
    train = [r for r in available if r['split'] == 'train']
    valid = [r for r in available if r['split'] == 'val' and r['source'] != DIALECT]
    return train, valid, held_rows


def row_identity(row):
    return {k: row[k] for k in ('row_id', 'content_sha256', 'group_id', 'split', 'source', 'label')}


def validate_scores(actual, expected, kind='rows'):
    require(isinstance(actual, list), f'{kind}: expected a list')
    by_id = {r['row_id']: r for r in expected}
    require(len(actual) == len(by_id) and {r['row_id'] for r in actual} == set(by_id),
            f'{kind}: row IDs differ or contain duplicates')
    for row in actual:
        old = by_id[row['row_id']]
        require(all(row.get(k) == v for k, v in row_identity(old).items()),
                f'{kind}: content hash, label, group, source or split mismatch: {row["row_id"]}')
        p = row.get('score')
        require(type(p) in (int, float) and math.isfinite(p) and 0 <= p <= 1,
                f'{kind}: invalid score')


def load_bundle(folder):
    folder = Path(folder)
    manifest = read_json(folder / 'manifest.json')
    require(manifest.get('schema') == SCHEMA, 'Bundle schema mismatch')
    require(manifest.get('sealed_test_included') is False, 'Sealed test inclusion flag')
    required = {'rows.json', 'text_split.json', 'rule.json', 'rule.md', 'probes.json',
                'transformer_contract.py', 'transformer_colab.py', 'text_utils.py',
                'transformer_compare.ipynb', 'README.md'}
    require(set(manifest['files']) == required, 'Bundle file set differs')
    for name, digest in manifest['files'].items():
        require(sha(folder / name) == digest, f'Bundle SHA-256 mismatch: {name}')
    split, rows = read_json(folder / 'text_split.json'), read_json(folder / 'rows.json')
    rule, probes = read_json(folder / 'rule.json'), read_json(folder / 'probes.json')
    require(rule['data_sha256'] == split['data_sha256'] == manifest['data_sha256'], 'Data identity mismatch')
    canonical = json.dumps(split['rows'], ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    require(hashlib.sha256(canonical).hexdigest() == split['data_sha256'] == split['text_split_sha256'],
            'Frozen split canonical hash mismatch')
    require(split.get('test_rows_included') is False, 'Frozen split includes tests')
    expected = {r['row_id']: r for r in split['rows']
                if r['split'] == 'train' or (r['split'] == 'val' and r['source'] != DIALECT)}
    require(len(expected) == len(rows) and {r['row_id'] for r in rows} == set(expected),
            'Input row IDs differ or contain duplicates')
    groups = {}
    for row in rows:
        old = expected[row['row_id']]
        require(row['split'] in {'train', 'val'}, 'Non-development row')
        require(hashlib.sha256(row['text'].encode()).hexdigest() == old['content_sha256'], 'Text content hash mismatch')
        require(all(row[k] == old[k] for k in old if k != 'row_id' and k != 'label'), 'Frozen metadata mismatch')
        require(row['label'] == int(old['label'] == 'phishing'), 'Label mismatch')
        groups.setdefault(row['group_id'], set()).add(row['split'])
    require(all(len(s) == 1 for s in groups.values()), 'Group crosses frozen splits')
    require(len(probes) == 12 and [p['probe_index'] for p in probes] == list(range(1, 13)), 'Probe set differs')
    for p in probes:
        require(hashlib.sha256(p['text'].encode()).hexdigest() == p['content_sha256'], 'Probe hash mismatch')
    return manifest, rows, rule, probes


def validate_run(obj, folder, name, seed):
    manifest, rows, rule, probes = load_bundle(folder)
    require(obj.get('schema') == SCHEMA and obj.get('model') == name and obj.get('model_id') == MODELS[name]
            and obj.get('seed') == seed, 'Model/seed/schema mismatch')
    require(obj.get('bundle_manifest_sha256') == sha(Path(folder) / 'manifest.json'), 'Input manifest hash mismatch')
    require(obj.get('final_test_run') is False and obj.get('runtime') in {'colab', 'local'}, 'Runtime/test provenance mismatch')
    require(obj.get('input_policy') == 'normalized-150-word-windows-stride75-maxprob-256tokens', 'Input policy mismatch')
    require(obj.get('training') == dict(epochs=3, learning_rate=2e-5, effective_batch_size=16,
                                      max_length=256, early_stopping=False), 'Training recipe mismatch')
    require(set(obj['folds']) == {'full', *rule['primary_sources']}, 'Missing or unexpected LOSO folds')
    for key, fold in obj['folds'].items():
        train, valid, held = partitions(rows, None if key == 'full' else key)
        require(fold['training_row_ids'] == [r['row_id'] for r in train], f'{key}: training IDs differ')
        require(fold['training_group_ids'] == sorted({r['group_id'] for r in train}), f'{key}: training groups differ')
        validate_scores(fold['validation'], valid, key + ' threshold validation')
        validate_scores(fold['held'], held, key + ' held-source')
        require(fold['threshold_95'] == threshold95(fold['validation']), f'{key}: 95%-recall threshold mismatch')
        digest = fold['model_sha256']
        require(isinstance(digest, str) and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest),
                'Invalid model weight hash')
    got = obj['probes']
    require(len(got) == 12 and {p['probe_index'] for p in got} == set(range(1, 13)), 'Probe IDs differ or contain duplicates')
    by_id = {p['probe_index']: p for p in probes}
    for p in got:
        require(p['content_sha256'] == by_id[p['probe_index']]['content_sha256'], 'Returned probe content hash mismatch')
        require(type(p['score']) in (int, float) and math.isfinite(p['score']) and 0 <= p['score'] <= 1, 'Invalid probe score')
    latency = obj['cpu_latency']
    require(latency.get('cpu_only') is True and latency.get('batch_size') == 1
            and latency.get('includes_tokenization_and_windows') is True
            and latency.get('separate_from_gpu_inference') is True, 'Separate CPU batch-one latency required')
    _, valid, _ = partitions(rows)
    require(latency.get('row_ids') == [r['row_id'] for r in valid] and latency.get('warmup_n', 0) >= 3,
            'CPU latency row IDs or warmup mismatch')
    durations = latency['durations_ms']
    require(len(durations) == len(valid) and all(type(t) in (float, int) and math.isfinite(t) and t > 0 for t in durations),
            'Invalid CPU timing samples')
    # NumPy's default linear percentile, without a NumPy dependency in the contract.
    ordered = sorted(durations)
    for q, key in ((.5, 'p50_ms'), (.95, 'p95_ms')):
        idx = (len(ordered) - 1) * q; low = int(idx); high = min(low + 1, len(ordered) - 1)
        value = ordered[low] + (ordered[high] - ordered[low]) * (idx - low)
        require(math.isclose(latency[key], value, rel_tol=1e-9), 'CPU percentile mismatch')
    require(bool(latency.get('cpu_description')) and latency.get('torch_threads', 0) > 0, 'CPU hardware metadata missing')
    return obj
