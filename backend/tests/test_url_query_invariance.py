"""Exposed benign-query regressions using the real packaged URL model.

URLs are inert strings. An unrelated registry entry keeps the brand engine
active while ensuring none of these cases passes through official-host
suppression. Existing tests cover the full production registry separately.
"""
import math
from datetime import date

import pytest

from app.engines.risk_scoring import calculate_final_risk_score
from app.engines import risk_scoring
from app.models import BlacklistEntry
from app.models.brand import BrandDomain, EgyptianBrand


HOSTS = (
    'youm7.com', 'masrawy.com', 'vezeeta.com', 'noon.com',
    'wuzzuf.net', 'breadfast.com', 'bosta.co', 'aramex.com',
)
PATHS = (
    '/track?order=12345',
    '/?utm_source=sms',
    '/login?next=/home',
    '/offers?id=5',
    '/reset-password?token=abc123',
)


@pytest.fixture
def model_only_db(db, monkeypatch):
    # This is the test suite's in-memory DB, never a runtime database. Keep
    # blacklist, brand and pattern implementations real; only fixture health
    # is fixed so unavailable feeds cannot turn a model warning into INCOMPLETE.
    db.query(BlacklistEntry).delete()
    brand = EgyptianBrand(brand_name='Unrelated fixture bank', category='test-fixture')
    db.add(brand)
    db.flush()
    db.add(BrandDomain(brand_id=brand.id, domain='reference-bank.example',
                       verified_date=date(2026, 10, 18)))
    db.commit()
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {
        'available': True, 'reason': None, 'mode': 'isolated_empty_query_fixture'})
    return db


@pytest.mark.parametrize('host', HOSTS)
@pytest.mark.parametrize('path', PATHS)
def test_benign_query_cannot_warn_from_url_model_alone(model_only_db, host, path):
    result = calculate_final_risk_score(url='https://' + host + path, db=model_only_db)
    assert result['analysis_complete']
    assert len(result['checked_links']) == 1
    link = result['checked_links'][0]

    # These cases must exercise a working real URL model, without hiding its
    # contribution behind a missing model, another signal or a host exemption.
    probability, threshold = link['url_model_probability'], link['url_model_threshold']
    assert probability is not None and math.isfinite(probability)
    assert threshold is not None and math.isfinite(threshold)
    assert 0 <= probability <= 1 and 0 <= threshold <= 1
    assert not link['verified_official_host']
    assert not link['shared_hosting_domain']
    assert link['brand']['score'] == 0 and not link['brand']['decisive']
    assert link['patterns'] == []
    assert link['blacklist']['match_type'] is None

    assert not link['url_model_above_threshold']
    assert 'url_model' not in result['supporting_signals']
    assert result['verdict'] not in {'MEDIUM', 'HIGH'}
    assert result['verdict'] == 'LOW'
