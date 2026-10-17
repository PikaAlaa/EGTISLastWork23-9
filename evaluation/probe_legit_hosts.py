"""Offline regression hosts supplied by the reviewer; never resolve destinations."""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.core.database import Base
from app.engines import risk_scoring
from app.engines.url_model import ARTIFACT, score_url
from app.services.registry import populate_registry

SUBDOMAIN_HOSTS = [
    'login.microsoftonline.com', 'outlook.office365.com', 'teams.microsoft.com',
    'secure.paymob.com', 'accept.paymob.com', 'careers.vodafone.com',
    'booking.egyptair.com', 'vendor.talabat.com', 'ebanking.cibeg.com',
    'bm-online.banquemisr.com',
]
MAIN_HOSTS = ['microsoftonline.com', 'paymob.com', 'vodafone.com', 'egyptair.com',
              'talabat.com', 'cibeg.com', 'banquemisr.com']
HOSTS = SUBDOMAIN_HOSTS + MAIN_HOSTS
OUT = ROOT / 'evaluation/reports/2026-10-v4'


def probe():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    rows = []
    try:
        with Session(engine) as db, patch.object(risk_scoring, 'blacklist_health',
                return_value={'available': True, 'reason': None, 'mode': 'empty_isolated_probe'}):
            populate_registry(db)
            for host in HOSTS:
                value = 'https://' + host + '/'
                model = score_url(value)
                scan = risk_scoring.calculate_final_risk_score(url=value, db=db)
                rows.append({'host': host, 'kind': 'subdomain' if host in SUBDOMAIN_HOSTS else 'main',
                             'model': model, 'verdict': scan['verdict'],
                             'reason': scan['decisive_reason'], 'signals': scan['supporting_signals'],
                             'link': scan['checked_links'][0]})
    finally:
        engine.dispose()
    return {'kind': 'exposed regression probes, not population or Egyptian-performance evidence',
            'artifact_sha256': hashlib.sha256(ARTIFACT.read_bytes()).hexdigest(),
            'destination_requests': 0, 'sealed_test_run': False, 'rows': rows,
            'summary': {'hosts': len(rows), 'raw_above_threshold': sum(
                row['model']['probability'] >= row['model']['threshold'] for row in rows),
                'medium_or_high': sum(row['verdict'] in {'MEDIUM', 'HIGH'} for row in rows)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUT / 'probe_before.json')
    args = parser.parse_args()
    result = probe()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result['summary']))


if __name__ == '__main__':
    main()
