"""Engineering checks for every frozen candidate, in disposable local copies.

No candidate is written to the real deployment. Test files are copied byte for
byte and never skipped, weakened, or rewritten. Failures remain release blockers.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
import joblib
from evaluation.run_url_selection_v4 import frozen, sha, OUT, FROZEN

LOCAL = ROOT / 'evaluation/local-results/v4-engineering'


def worker(index, tasks):
    checkout = LOCAL / ('checkout-' + str(index))
    checkout.mkdir(parents=True, exist_ok=True)
    tracked = subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
    extra = ['evaluation/check_url_candidate_v4.py', 'evaluation/run_url_selection_v4.py',
             'evaluation/reports/2026-10-v4/url_v4_frozen_thresholds.json',
             'evaluation/reports/2026-10-v4/url_v4_frozen_thresholds.sha256']
    for relative in tracked + extra:
        source, target = ROOT / relative, checkout / relative
        if source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    (checkout / '.local').mkdir(exist_ok=True)
    risk = checkout / 'backend/app/engines/risk_scoring.py'
    text = risk.read_text(encoding='utf-8')
    assert "URL_MODEL_POLICY = 'corroboration_only'" in text
    risk.write_text(text.replace("URL_MODEL_POLICY = 'corroboration_only'", "URL_MODEL_POLICY = 'ordinary'"), encoding='utf-8')
    for record, point in tasks:
        identity = record['sha256'] + '_' + record['input_mode'] + ':' + repr(point['threshold'])
        cid = hashlib.sha256(identity.encode()).hexdigest()[:20]
        result_path = OUT / 'url-v4-engineering' / (cid + '.json')
        if result_path.exists():
            continue
        artifact = joblib.load(ROOT / record['path'])
        artifact['thresholds'] = {**artifact.get('thresholds', {}), 'medium': point['threshold']}
        artifact['deployment_schema'] = {k: record[k] for k in ['representation', 'phresh_schema', 'input_mode']}
        target = checkout / 'ml/models/url_host_v3.joblib'
        joblib.dump(artifact, target, compress=3)
        metadata = json.loads((ROOT / 'ml/models/url_host_deployment.json').read_text())
        metadata.update(selected=record['path'], artifact_sha256=sha(target), source_artifact_sha256=record['sha256'],
                        threshold=point['threshold'], representation=record['representation'], input_mode=record['input_mode'],
                        policy='ordinary', selection_rule_path='evaluation/reports/2026-10-v4/url_selection_rule_v4.md',
                        selection_rule_sha256=sha(OUT / 'url_selection_rule_v4.md'), v4_frozen_thresholds_sha256=sha(FROZEN),
                        candidate_check_only=True)
        (checkout / 'ml/models/url_host_deployment.json').write_text(json.dumps(metadata), encoding='utf-8')
        command = [sys.executable, 'evaluation/check_url_candidate_v4.py', str(checkout / '.local' / ('pytest-' + cid))]
        env = dict(os.environ, PYTHONIOENCODING='utf-8', OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1')
        begin = time.perf_counter()
        completed = subprocess.run(command, cwd=checkout, env=env, text=True, capture_output=True, encoding='utf-8', errors='replace')
        output = checkout / '.local/candidate-result.json'
        result = json.loads(output.read_text()) if completed.returncode == 0 else {'passes': False, 'runner_failed': True}
        result.update(id=cid, artifact_path=record['path'], artifact_sha256=record['sha256'], input_mode=record['input_mode'],
                      threshold=point['threshold'], rule_sha256=metadata['selection_rule_sha256'], frozen_thresholds_sha256=sha(FROZEN),
                      seconds=time.perf_counter() - begin, command=['python', *command[1:]], runner_exit_code=completed.returncode,
                      output=completed.stdout + completed.stderr,
                      test_source_sha256={p: sha(ROOT / p) for p in tracked if p.startswith('backend/tests/') and p.endswith('.py')})
        result_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(cid, record['input_mode'], result.get('pytest_passed'), len(result.get('pytest_failed', [])), result['passes'], flush=True)


def main():
    inventory = frozen()
    tasks = [(r, p) for r in inventory['models'] for p in r['thresholds']]
    LOCAL.mkdir(parents=True, exist_ok=True)
    (OUT / 'url-v4-engineering').mkdir(exist_ok=True)
    workers = 4
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(worker, i, tasks[i::workers]) for i in range(workers)]
        for future in futures:
            future.result()
    frozen()
    results = [json.loads(p.read_text()) for p in sorted((OUT / 'url-v4-engineering').glob('*.json'))]
    assert len(results) == len(tasks)
    (OUT / 'url_v4_engineering.json').write_text(json.dumps(dict(rule_sha256=inventory['rule_sha256'],
        frozen_thresholds_sha256=sha(FROZEN), candidate_count=len(results), passing=sum(r['passes'] for r in results),
        candidates=[{k: v for k, v in r.items() if k not in {'output', 'test_source_sha256', 'command'}} for r in results]), indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
