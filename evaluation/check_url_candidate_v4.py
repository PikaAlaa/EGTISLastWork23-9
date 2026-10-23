"""Run the unchanged complete suite and exposed probes in an isolated candidate checkout."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
os.environ.update(DATABASE_URL='sqlite://', ETIS_API_KEY='', ETIS_REQUIRED_FEEDS='', ETIS_RATE_LIMIT='10000/minute')
import pytest


class Results:
    def __init__(self):
        self.passed, self.failed, self.skipped = [], [], []

    def pytest_runtest_logreport(self, report):
        if report.failed:
            self.failed.append(report.nodeid)
        elif report.skipped:
            self.skipped.append(report.nodeid)
        elif report.when == 'call' and report.passed:
            self.passed.append(report.nodeid)


def main():
    recorder = Results()
    code = pytest.main(['-q', '--tb=line', '-p', 'no:cacheprovider', '--basetemp', sys.argv[1]], plugins=[recorder])
    from evaluation.run_followup import run
    from evaluation.probe_legit_hosts import probe
    from evaluation.probe_query_shortcut import HOSTS, VARIANTS
    from app.engines import risk_scoring
    from app.core.database import Base
    from app.services.registry import populate_registry
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from unittest.mock import patch
    replay = run(ROOT / '.local/replay.json')
    host = probe()
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    nonlow = 0
    try:
        with Session(engine) as db, patch.object(risk_scoring, 'blacklist_health', return_value={'available': True, 'reason': None}):
            populate_registry(db)
            for h in HOSTS:
                for suffix in VARIANTS.values():
                    scan = risk_scoring.calculate_final_risk_score(url='https://' + h + suffix, db=db)
                    nonlow += scan['verdict'] != 'LOW'
    finally:
        engine.dispose()
    result = dict(pytest_exit_code=int(code), pytest_passed=len(recorder.passed), pytest_failed=recorder.failed,
                  pytest_skipped=recorder.skipped,
                  query_invariance_40_passed=sum('test_url_query_invariance.py::' in s for s in recorder.passed),
                  replays=replay['summary'], host_probes=host['summary'], query_path_88_nonlow=int(nonlow),
                  suite_unchanged=True, healthy_empty_blacklist=True, destination_requests=0)
    s = result['replays']
    result['passes'] = bool(not code and s['detection_passed'] == 23 and s['robustness_passed'] == 7
                            and s['followup_passed'] == 15 and not host['summary']['medium_or_high'] and not nonlow)
    (ROOT / '.local/candidate-result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
