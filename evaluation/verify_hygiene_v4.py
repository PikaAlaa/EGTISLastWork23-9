"""Check local retention, protected files and an optional data-free tracked-tree export."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v4'
PROTECTED = ['evaluation/reports/reviewed-2026-10-08', 'evaluation/targets.json',
             'evaluation/reports/2026-10-v3/text_split.json',
             'evaluation/reports/2026-10-v3/review-2026-10-13/url_split_manifest.json',
             'evaluation/reports/2026-10-v3/url_time_split.json',
             'evaluation/reports/2026-10-v3/phreshphish/protocol.json', 'data/phreshphish-lock.json']
PRESERVED = ['ml/models/lstm_phishing_classifier.keras', 'ml/data/tokenizer.pkl',
             'ml/models/deployed_char.joblib']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clean-tree', action='store_true')
    args = parser.parse_args()
    inventory = json.loads((OUT / 'data_hygiene.json').read_text())
    manifest = json.loads((ROOT / 'release-artifacts/MANIFEST.json').read_text())
    tracked = git('ls-files', '-z').decode().split('\0')
    retained = [{'path': row['path'], 'unchanged_local_bytes': (ROOT / row['path']).is_file() and
                 sha(ROOT / row['path']) == row['sha256']} for row in inventory['untracked_data']]
    artifacts = [{'path': row['local_path'], 'sha256_matches': sha(ROOT / row['local_path']) == row['sha256']}
                 for row in manifest['files']]
    preserved = {path: sha(ROOT / path) == hashlib.sha256(git('show', 'main:' + path)).hexdigest()
                 for path in PRESERVED}
    changes = git('diff', '--name-status', 'main', '--', *PROTECTED).decode()
    candidates = [path for path in tracked if path.startswith('evaluation/reports/2026-10-v3/')
                  and Path(path).suffix in {'.joblib', '.keras', '.pkl'}]
    forbidden = [path for path in tracked if path.startswith(('data/raw/', 'data/external/phreshphish/',
                                                            'evaluation/local-results/', 'release-artifacts/'))]
    metadata = json.loads((ROOT / 'ml/models/url_host_deployment.json').read_text())
    report = {'protected_git_changes': changes, 'preserved_models_and_tokenizer': preserved,
              'retained_local_data': retained, 'local_data_count': len(retained),
              'release_artifacts': artifacts, 'release_artifact_count': len(artifacts),
              'tracked_restricted_data_or_predictions': forbidden, 'tracked_v3_candidate_binaries': candidates,
              'rule_hash_matches': sha(OUT / 'url_selection_rule.md') == metadata['selection_rule_sha256'],
              'deployed_hash_matches': sha(ROOT / 'ml/models/url_host_v3.joblib') == metadata['artifact_sha256'],
              'history_rewritten': False, 'push_performed': False, 'sealed_test_run': False,
              'genuine_egyptian_sms_test_count': 0}
    assert not changes and all(preserved.values())
    assert all(row['unchanged_local_bytes'] for row in retained)
    assert all(row['sha256_matches'] for row in artifacts)
    assert not candidates and not forbidden and report['rule_hash_matches'] and report['deployed_hash_matches']
    (OUT / 'integrity.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    if args.clean_tree:
        # Export only tracked HEAD; no raw snapshots, projected data, .env or venv.
        destination = Path(tempfile.mkdtemp(prefix='v4-clean-', dir=ROOT / '.local')).resolve()
        assert destination.is_relative_to((ROOT / '.local').resolve())
        with zipfile.ZipFile(io.BytesIO(git('archive', '--format=zip', 'HEAD'))) as archive:
            archive.extractall(destination)
        assert not (destination / 'data/raw').exists()
        assert not (destination / 'data/processed/dataset.csv').exists()
        env = dict(os.environ)
        env.pop('DATABASE_URL', None)
        env['PYTHONIOENCODING'] = 'utf-8'
        clean = {'head': git('rev-parse', 'HEAD').decode().strip(), 'kind': 'tracked git archive with no research data; existing venv dependencies',
                 'commands': {}, 'sealed_test_run': False}
        for name, command in [('pytest', [sys.executable, '-m', 'pytest', '-q']),
                              ('initialize', [sys.executable, 'scripts/initialize.py'])]:
            completed = subprocess.run(command, cwd=destination, env=env, capture_output=True,
                                       text=True, encoding='utf-8', errors='replace')
            output = completed.stdout + completed.stderr
            entry = {'exit_code': completed.returncode, 'output': output}
            if name == 'pytest':
                match = re.search(r'(\d+) passed', output)
                entry['passed'] = int(match[1]) if match else None
            clean['commands'][name] = entry
            (OUT / 'clean_tree_checks.json').write_text(json.dumps(clean, indent=2) + '\n', encoding='utf-8')
            print(name + ': ' + str(completed.returncode), flush=True)
        assert not any(entry['exit_code'] for entry in clean['commands'].values()), 'Clean-tree check failed; see JSON'
    print(json.dumps({'retained_data_verified': len(retained), 'release_hashes_verified': len(artifacts), 'protected_files_changed': bool(changes)}))


if __name__ == '__main__':
    main()
