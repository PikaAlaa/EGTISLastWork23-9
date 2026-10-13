"""Run the repository CI commands locally and save their actual outputs."""
import ast
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v3/review-2026-10-13'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    npm = shutil.which('npm.cmd' if os.name == 'nt' else 'npm')
    if not npm:
        raise RuntimeError('npm is unavailable')
    commands = [
        ('backend_tests', [sys.executable, '-m', 'pytest', '-q'], ROOT),
        ('initialize', [sys.executable, 'scripts/initialize.py'], ROOT),
        ('frontend_install', [npm, 'ci'], ROOT / 'etis-frontend'),
        ('frontend_build', [npm, 'run', 'build'], ROOT / 'etis-frontend'),
        ('frontend_lint', [npm, 'run', 'lint'], ROOT / 'etis-frontend'),
    ]
    results = {}
    for name, command, cwd in commands:
        print(f'Running {name}', flush=True)
        start = time.perf_counter()
        env = dict(os.environ)
        env.pop('DATABASE_URL', None)
        completed = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True,
                                   encoding='utf-8', errors='replace')
        output = completed.stdout + completed.stderr
        (OUT / f'check-{name}.txt').write_text(output, encoding='utf-8')
        results[name] = {'command': command, 'cwd': str(cwd.relative_to(ROOT)),
                         'exit_code': completed.returncode,
                         'elapsed_seconds': round(time.perf_counter() - start, 3),
                         'output_file': f'check-{name}.txt'}
        if name == 'backend_tests':
            match = re.search(r'(\d+) passed', output)
            results[name]['passed'] = int(match.group(1)) if match else None
        print(f'{name}: exit {completed.returncode}', flush=True)
    notebook = json.loads((ROOT / 'notebooks/transformer_compare.ipynb').read_text(encoding='utf-8'))
    for cell in notebook['cells']:
        if cell['cell_type'] == 'code':
            ast.parse(''.join(line for line in cell['source'] if not line.startswith('%')))
    data = json.loads((OUT.parent / 'text_split.json').read_text(encoding='utf-8'))['data_sha256']
    report = {'stage': 'local_ci_commands', 'completed_at_utc': datetime.now(timezone.utc).isoformat(),
              'data_sha256': data, 'model_sha256': sha(ROOT / 'ml/models/url_host_v3.joblib'),
              'libraries': {name: importlib.metadata.version(name) for name in
                            ['numpy', 'pandas', 'scikit-learn', 'lightgbm', 'joblib', 'pytest']},
              'python': platform.python_version(), 'platform': platform.platform(),
              'node': subprocess.check_output(['node', '--version'], text=True).strip(),
              'commands': results, 'notebook_syntax_valid': True,
              'notebook_training_run': False, 'final_test_run': False,
              'limitations': ['Local Windows commands; the GitHub Linux/Python 3.12/Node 24 job itself was not run.']}
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return int(any(item['exit_code'] for item in results.values()))


if __name__ == '__main__':
    raise SystemExit(main())
