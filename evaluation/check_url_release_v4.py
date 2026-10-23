"""Retain actual release-check output using an isolated initialization database."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v4'


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')
    npm = shutil.which('npm.cmd' if os.name == 'nt' else 'npm')
    env = dict(os.environ, PYTHONIOENCODING='utf-8', ETIS_REQUIRED_FEEDS='', ETIS_API_KEY='isolated-v4-check-key', OMP_NUM_THREADS='1')
    env['DATABASE_URL'] = 'sqlite:///' + (ROOT / '.local' / ('initialize-v4-' + stamp + '.db')).as_posix()
    commands = [
        ('pytest', [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '--basetemp', '.local/pytest-v4-final-' + stamp], ROOT),
        ('query_invariance_40', [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'backend/tests/test_url_query_invariance.py', '--basetemp', '.local/pytest-v4-query-' + stamp], ROOT),
        ('replays', [sys.executable, 'evaluation/run_followup.py', '--output', str(OUT / 'url_v4_release_replays.json')], ROOT),
        ('host_probes', [sys.executable, 'evaluation/probe_legit_hosts.py', '--output', str(OUT / 'url_v4_release_host_probes.json')], ROOT),
        ('query_path_88', [sys.executable, 'evaluation/probe_query_shortcut.py', '--output', str(OUT / 'url_v4_release_query_probes.json')], ROOT),
        ('scanner_parity', [sys.executable, 'evaluation/verify_deployed_url_v4.py', '--output', str(OUT / 'url_v4_release_scanner_verification.json')], ROOT),
        ('initialize', [sys.executable, 'scripts/initialize.py'], ROOT),
        ('frontend_build', [npm, 'run', 'build'], ROOT / 'etis-frontend'),
        ('frontend_lint', [npm, 'run', 'lint'], ROOT / 'etis-frontend')]
    result = dict(created_at=datetime.now(timezone.utc).isoformat(), isolated_initialization=True,
                  deployment=json.loads((ROOT / 'ml/models/url_host_deployment.json').read_text()),
                  sealed_test_run=False, destination_requests=0, commands={})
    for name, command, cwd in commands:
        print('CHECK', name, flush=True)
        start = time.perf_counter()
        done = subprocess.run(command, cwd=cwd, env=env, capture_output=True, encoding='utf-8', errors='replace')
        result['commands'][name] = dict(command=command, exit_code=done.returncode, seconds=time.perf_counter() - start,
                                        output=done.stdout + done.stderr)
        (OUT / 'url_v4_release_checks.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(name, done.returncode, (done.stdout + done.stderr)[-1000:], flush=True)
    return int(any(r['exit_code'] for r in result['commands'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
