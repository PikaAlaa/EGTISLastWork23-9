"""Untrack restricted data without deleting it; relocate research weights locally.

Run only for the explicitly authorized v4 repository hygiene. This never rewrites
history, removes local raw data, or changes deployed/September artifact bytes.
"""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v4'
RELEASE = ROOT / 'release-artifacts'
DEPLOYED = {'ml/models/deployed_char.joblib', 'ml/models/url_host_v3.joblib',
            'ml/models/lstm_phishing_classifier.keras'}  # Preserve original September evidence.
SUFFIXES = {'.joblib', '.keras', '.pkl'}
DERIVED = ['data/processed/dataset.csv', 'evaluation/reports/2026-10-v3/text_trainval.csv',
           'evaluation/reports/2026-10-v3/tranco-PY35J-top-20000.csv']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    raw = [p for p in tracked if p.startswith('data/raw/')]
    data = raw + [p for p in DERIVED if p in tracked]
    models = [p for p in tracked if Path(p).suffix in SUFFIXES and (
        p.startswith('evaluation/reports/2026-10-v3/') or p.startswith('ml/models/') and p not in DEPLOYED)]
    manifest_path = RELEASE / 'MANIFEST.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {'files': []}
    records = {r['original_path']: r for r in manifest['files']}
    removed = []
    for relative in data:
        path = ROOT / relative
        removed.append({'path': relative, 'sha256': sha(path), 'bytes': path.stat().st_size,
                        'local_file_retained': True, 'reason': 'PhiUSIIL size/no benign nonroot URLs' if 'PhiUSIIL' in relative else 'Redistribution not cleared; see docs/data-licences.md'})
    for relative in models:
        source = ROOT / relative
        target = RELEASE / relative
        before = sha(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if sha(target) != before:
                raise ValueError('Refusing to replace differing release artifact: ' + relative)
        else:
            shutil.copy2(source, target)
        assert sha(target) == before
        records[relative] = {'original_path': relative, 'local_path': str(target.relative_to(ROOT)).replace('\\', '/'),
                             'sha256': before, 'bytes': source.stat().st_size}
    if data + models:
        subprocess.run(['git', 'rm', '--cached', '--', *data, *models], cwd=ROOT, check=True, capture_output=True)
    # Complete the requested move only after a verified copy and successful untracking.
    for relative in models:
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT.resolve()):
            raise ValueError('Artifact path escaped repository')
        path.unlink()
    for path in (RELEASE / 'v4').glob('*.joblib'):
        relative = 'v4/' + path.name
        records[relative] = {'original_path': relative, 'local_path': str(path.relative_to(ROOT)).replace('\\', '/'),
                             'sha256': sha(path), 'bytes': path.stat().st_size}
    manifest = {'purpose': 'Local candidates for optional GitHub Release; no upload performed',
                'files': sorted(records.values(), key=lambda r: r['original_path'])}
    manifest['file_count'] = len(manifest['files'])
    manifest['total_bytes'] = sum(r['bytes'] for r in manifest['files'])
    RELEASE.mkdir(exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'release_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    existing = OUT / 'data_hygiene.json'
    old = json.loads(existing.read_text())['untracked_data'] if existing.exists() else []
    by_path = {row['path']: row for row in old + removed}
    report = {'untracked_data': list(by_path.values()), 'untracked_data_count': len(by_path),
              'candidate_binaries': manifest['files'], 'candidate_count': manifest['file_count'],
              'history_rewritten': False, 'pushed': False,
              'history_warning': 'Files remain in Git history and on GitHub. Making the repository private limits public access; purging historical copies requires a separate authorized history rewrite. No rewrite was performed.'}
    (OUT / 'data_hygiene.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'untracked_data': len(by_path), 'release_candidates': manifest['file_count']}))


if __name__ == '__main__':
    main()
