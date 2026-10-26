"""Capture the requested release checks without using a runtime database."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.transformer_contract import write_json, sha


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('check', choices=['pytest', 'initialize', 'build', 'lint'])
    args = parser.parse_args()
    out = ROOT / 'evaluation/reports/2026-10-v5'
    env = {**os.environ, 'NO_COLOR': '1', 'FORCE_COLOR': '0'}
    cwd = ROOT
    if args.check == 'pytest':
        cmd = [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '--tb=short',
               '--basetemp', str(ROOT / '.local/pytest-text-v5-release-20261026')]
    elif args.check == 'initialize':
        env['DATABASE_URL'] = 'sqlite:///' + (ROOT / 'evaluation/local-results/text-transformers/v5-initialize.db').as_posix()
        cmd = [sys.executable, 'scripts/initialize.py']
    else:
        cwd = ROOT / 'etis-frontend'
        cmd = [shutil.which('npm.cmd') or 'npm', 'run', args.check]
    result = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = out / f'check-{args.check}.txt'
    log.write_bytes(result.stdout)
    write_json(out / f'check-{args.check}.json', dict(command=cmd, exit_code=result.returncode,
                                                    log=log.name, log_sha256=sha(log)))
    print(result.stdout.decode('utf-8', errors='replace'), end='')
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
