"""Run local engineering checks and retain their actual output as v4 JSON."""
import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v4'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['baseline', 'final'], default='final', nargs='?')
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding='utf-8')
    npm = shutil.which('npm.cmd' if os.name == 'nt' else 'npm')
    if not npm:
        raise RuntimeError('npm is unavailable')
    pytest_tmp = ROOT / '.local' / ('pytest-v2-' + datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f'))
    assert pytest_tmp.resolve().is_relative_to((ROOT / '.local').resolve())
    commands = [('pytest', [sys.executable, '-m', 'pytest', '-q', '-o', 'cache_dir=.local/pytest-cache-v2', '--basetemp', str(pytest_tmp)], ROOT),
                ('initialize', [sys.executable, 'scripts/initialize.py'], ROOT)]
    if args.stage == 'baseline':
        commands.append(('npm_ci', [npm, 'ci'], ROOT / 'etis-frontend'))
    commands.extend([(name, [npm, 'run', task], ROOT / 'etis-frontend')
                     for name, task in [('frontend_build', 'build'), ('frontend_lint', 'lint')]])
    environment = dict(os.environ)
    environment.pop('DATABASE_URL', None)
    environment['PYTHONIOENCODING'] = 'utf-8'
    report = {'stage': args.stage, 'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'branch': subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip(),
              'python': platform.python_version(), 'date': datetime.now(timezone.utc).isoformat(),
              'libraries': {name: importlib.metadata.version(name) for name in ['numpy', 'pandas', 'scikit-learn', 'lightgbm', 'pytest']},
              'sealed_test_run': False, 'genuine_egyptian_sms_test_count': 0, 'commands': {}}
    OUT.mkdir(parents=True, exist_ok=True)
    for name, command, cwd in commands:
        print('Running ' + name, flush=True)
        begin = time.perf_counter()
        completed = subprocess.run(command, cwd=cwd, env=environment, capture_output=True,
                                   text=True, encoding='utf-8', errors='replace')
        output = completed.stdout + completed.stderr
        entry = {'command': command, 'exit_code': completed.returncode,
                 'seconds': time.perf_counter() - begin, 'output': output}
        if name == 'pytest':
            for key in ['passed', 'skipped']:
                match = re.search(r'(\d+) ' + key, output)
                entry[key] = int(match[1]) if match else 0
        report['commands'][name] = entry
        (OUT / (args.stage + '_checks.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(name + ': ' + str(completed.returncode) + '\n' + output[-3000:], flush=True)
    return int(any(entry['exit_code'] for entry in report['commands'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
