"""Offline exposed query-string regressions; never fetch or resolve destinations."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.core.database import Base
from app.engines import risk_scoring
from app.engines.url_features import phresh_features
from app.engines.url_model import ARTIFACT, _extractor, _load, score_url
from app.services.registry import populate_registry

HOSTS = ['youm7.com', 'masrawy.com', 'vezeeta.com', 'noon.com',
         'wuzzuf.net', 'breadfast.com', 'bosta.co', 'aramex.com']
VARIANTS = {
    'path_control': '/track/12345',
    'order_query': '/track?order=12345',
    'sms_tracking': '/?utm_source=sms',
    'login_control': '/login',
    'login_query': '/login?next=/home',
    'root_query': '/?q=weather',
    'search_query': '/search?q=cairo%20weather',
    'pagination': '/products?page=2&sort=price',
    'tracking': '/article?utm_source=newsletter&utm_medium=email',
    'fragment': '/track?order=12345#status',
    'multiple_parameters': '/track?order=12345&lang=ar',
}
OUT = ROOT / 'evaluation/reports/2026-10-v4/query-shortcut'


def scan_summary(result):
    link = result['checked_links'][0]
    return {'verdict': result['verdict'], 'signals': result['supporting_signals'],
            'model_support': link['url_model_above_threshold'],
            'raw_above_threshold': link['url_model_raw_above_threshold'],
            'official_host': link['verified_official_host'],
            'shared_host': link['shared_hosting_domain']}


def probe():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    rows = []
    artifact = _load()
    try:
        with Session(engine) as db, patch.object(risk_scoring, 'blacklist_health',
                return_value={'available': True, 'reason': None, 'mode': 'empty_isolated_probe'}):
            populate_registry(db)
            for host in HOSTS:
                for variant, suffix in VARIANTS.items():
                    url = 'https://' + host + suffix
                    model = score_url(url)
                    scans = {'active': scan_summary(risk_scoring.calculate_final_risk_score(url=url, db=db))}
                    for policy in ['ordinary', 'corroboration_only']:
                        with patch.object(risk_scoring, 'URL_MODEL_POLICY', policy):
                            scans[policy] = scan_summary(risk_scoring.calculate_final_risk_score(url=url, db=db))
                    with patch.object(risk_scoring, 'score_url', return_value=None):
                        scans['non_model'] = scan_summary(risk_scoring.calculate_final_risk_score(url=url, db=db))
                    row = {'host': host, 'variant': variant, 'url': url, 'model': model, 'scans': scans}
                    if variant == 'order_query':
                        # One-feature counterfactual for diagnosis only. Production
                        # uses the original full URL and frozen feature schema.
                        features = phresh_features(url, host, _extractor(), True)
                        features['query_len'] = 0
                        row['query_len_zero_probability'] = float(artifact['classifier'].predict_proba(
                            artifact['vectorizer'].transform([features]))[0, 1])
                    rows.append(row)
    finally:
        engine.dispose()
    summary = {}
    for variant in VARIANTS:
        subset = [row for row in rows if row['variant'] == variant]
        summary[variant] = {'hosts': len(subset), 'raw_above_threshold': sum(
            row['model']['probability'] >= row['model']['threshold'] for row in subset),
            'verdicts': {policy: dict(Counter(row['scans'][policy]['verdict'] for row in subset))
                         for policy in ['active', 'ordinary', 'corroboration_only', 'non_model']}}
    return {'kind': 'exposed reviewer and authored development regressions; not population accuracy',
            'url_model_policy': risk_scoring.URL_MODEL_POLICY,
            'artifact_sha256': hashlib.sha256(ARTIFACT.read_bytes()).hexdigest(),
            'scanner_sha256': hashlib.sha256((ROOT / 'backend/app/engines/risk_scoring.py').read_bytes()).hexdigest(),
            'blacklist': 'isolated healthy empty in-memory fixture; production registry populated',
            'destination_requests': 0, 'sealed_test_run': False, 'summary': summary, 'rows': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUT / 'probes.json')
    args = parser.parse_args()
    result = probe()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(result['summary'], indent=2))
    return 0 if all(row['scans']['active']['verdict'] == 'LOW' for row in result['rows']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
