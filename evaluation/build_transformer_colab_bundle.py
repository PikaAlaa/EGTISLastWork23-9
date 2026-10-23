"""Build a private, allowlisted Colab input ZIP. Never decode non-development records."""
import ast
import csv
import hashlib
import io
from pathlib import Path
import shutil
import zipfile

from evaluation.transformer_contract import DIALECT, SCHEMA, load_bundle, read_json, require, sha, write_json

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'evaluation/reports/2026-10-v3'
REVIEW = REPORT / 'review-2026-10-13'


def allowlisted_records(path, allowed):
    """Skip unlisted CSV records as bytes; deserialize only frozen development IDs.

    CSV quotes have even parity at record boundaries (including escaped quotes).
    This handles embedded newlines without decoding or retaining test text.
    IDs are the first CSV field in these pinned local exports.
    """
    with Path(path).open('rb') as stream:
        header = next(stream).decode('utf-8-sig').strip()
        require(header.split(',')[0] == 'id', 'Expected first field id')
        quoted = False
        for line in stream:
            if not quoted:
                key = line.partition(b',')[0].strip(b'"').decode('ascii')
                keep = key in allowed
                chunks = []
            if keep:
                chunks.append(line)
            quoted ^= bool(line.count(b'"') % 2)
            if not quoted and keep:
                yield next(csv.DictReader(io.StringIO(header + '\n' + b''.join(chunks).decode('utf-8'))))
        require(not quoted, 'Unterminated CSV record')


def existing_probes():
    module = ast.parse((ROOT / 'evaluation/review-evidence/cases.py').read_text(encoding='utf-8'))
    return next(ast.literal_eval(n.value) for n in module.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'EVERYDAY_SMS' for t in n.targets))


def build(destination=None):
    destination = Path(destination or ROOT / 'colab-bundle')
    dataset = ROOT / 'data/processed/dataset.csv'
    v3 = ROOT / 'evaluation/local-results/v3-data/dataset.csv'
    for path in (dataset, v3, REPORT / 'text_split.json', REVIEW / 'model_selection_rule.json'):
        if not path.is_file():
            raise FileNotFoundError(f'Required local data missing: {path}; stopping, no download/rebuild of splits')
    split = read_json(REPORT / 'text_split.json')
    expected = {r['row_id']: r for r in split['rows']}
    require(len(expected) == len(split['rows']) and all(r['split'] in {'train', 'val'} for r in expected.values()),
            'Frozen development manifest invalid')
    recovered = {}
    newline_restored = 0
    for row in allowlisted_records(v3, expected):
        old = expected[row['id']]
        require(row['id'] not in recovered, 'Duplicate input ID')
        require(row['sealed'].lower() not in {'true', '1'}, 'Allowlisted row is sealed')
        require(all(row[k] == old[k] for k in ('split', 'group_id', 'label', 'source', 'language', 'content_type')),
                'Frozen metadata mismatch')
        text = row['text']
        if hashlib.sha256(text.encode()).hexdigest() != old['content_sha256']:
            text = text.replace('\r\n', '\n')
            newline_restored += 1
        require(hashlib.sha256(text.encode()).hexdigest() == old['content_sha256'], 'Frozen text unavailable; stopping')
        recovered[row['id']] = dict(old, text=text, label=int(old['label'] == 'phishing'))
    require(set(recovered) == set(expected), 'Frozen development rows missing; stopping')
    rows = [recovered[r['row_id']] for r in split['rows']
            if r['split'] == 'train' or r['source'] != DIALECT]
    payload = destination / 'payload'
    payload.mkdir(parents=True, exist_ok=True)
    write_json(payload / 'rows.json', rows)
    write_json(payload / 'probes.json', [dict(probe_index=i, text=t, content_sha256=hashlib.sha256(t.encode()).hexdigest())
                                      for i, t in enumerate(existing_probes(), 1)])
    copies = {
        'text_split.json': REPORT / 'text_split.json',
        'rule.json': REVIEW / 'model_selection_rule.json',
        'rule.md': REVIEW / 'model_selection_rule.md',
        'transformer_contract.py': ROOT / 'evaluation/transformer_contract.py',
        'transformer_colab.py': ROOT / 'evaluation/transformer_colab.py',
        'text_utils.py': ROOT / 'backend/app/core/text_utils.py',
        'transformer_compare.ipynb': ROOT / 'notebooks/transformer_compare.ipynb',
        'README.md': ROOT / 'docs/transformer-colab.md',
    }
    for name, source in copies.items():
        shutil.copyfile(source, payload / name)
    manifest = dict(schema=SCHEMA, data_sha256=split['data_sha256'], sealed_test_included=False,
                    row_counts={s: sum(r['split'] == s for r in rows) for s in ('train', 'val')},
                    excluded_dialectal_validation_n=sum(r['split'] == 'val' and r['source'] == DIALECT for r in expected.values()),
                    hash_verified_LF_restorations=newline_restored,
                    local_replay_sha256={str(p.relative_to(ROOT)).replace('\\', '/'): sha(p) for p in
                                         [ROOT / 'evaluation/run_text_review.py',
                                          ROOT / 'evaluation/review-evidence/cases.py',
                                          *sorted((ROOT / 'backend/app').rglob('*.py'))]},
                    provenance=read_json(REVIEW / 'model_selection_rule.json')['provenance'],
                    files={name: sha(payload / name) for name in sorted([*copies, 'rows.json', 'probes.json'])})
    write_json(payload / 'manifest.json', manifest)
    load_bundle(payload)
    archive = destination / 'etis-text-input.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in sorted([*manifest['files'], 'manifest.json']):
            z.write(payload / name, name)
    shutil.copyfile(payload / 'README.md', destination / 'README.md')
    write_json(destination / 'checksums.json', {'etis-text-input.zip': sha(archive), 'manifest.json': sha(payload / 'manifest.json')})
    print(f'Built {archive}: {manifest["row_counts"]}; sealed tests: 0')
    return archive


if __name__ == '__main__':
    build()
