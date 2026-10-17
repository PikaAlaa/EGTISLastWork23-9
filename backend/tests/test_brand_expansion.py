"""Synthetic URL-rule fixtures, never presented as collected phishing samples."""
from datetime import date
import pytest
from app.core.egyptian_brands import OCTOBER_VERIFIED_DOMAINS
from app.engines import risk_scoring
from app.engines.rule_based.domain_typosquatting_detector import calculate_domain_typosquatting_score
from app.models import BrandDomain, EgyptianBrand
from app.services.registry import populate_registry

CASES = [
    ('amazon.com', 'amazon.com.login.example'), ('amazon.de', 'amazon.de.login.example'),
    ('amazon.co.jp', 'amazon.co.jp.login.example'), ('amazon.com.mx', 'amazon.com.mx.login.example'),
    ('amazon.co.za', 'amazon.co.za.login.example'), ('amazon.se', 'amazon.se.login.example'),
    ('orange.pl', 'orange.pl.login.example'),
    ('vodafone.com', 'vodafone.com.verify.example'),
    ('paymob.com', 'paymob-verify.example'), ('paymob.eg', 'paymob.login.example'),
    ('instapay.eg', 'instapay-update.example'),
    ('web.vodafone.com.eg', 'vodafone-cash.verify.example'),
    ('valu.com.eg', 'valu-login.example'), ('valugroup.com', 'valugroup.verify.example'),
    ('fawry.com', 'fawry-wallet.example'), ('bosta.co', 'bosta.update.example'),
    ('aramex.com', 'aramex-payment.example'), ('egyptpost.org', 'egyptpost.verify.example'),
    ('digital.gov.eg', 'digital-login.example'), ('eta.gov.eg', 'eta.update.example'),
]


@pytest.mark.parametrize('official,lookalike', CASES)
def test_sourced_official_domain_is_not_flagged_but_action_lookalike_is_high(db, monkeypatch, official, lookalike):
    populate_registry(db)
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {'available': True, 'reason': None})
    # Force a high model score to ensure only generic official-domain suppression
    # applies; the model cannot turn these official destinations into warnings.
    monkeypatch.setattr(risk_scoring, 'score_url', lambda _: {'probability': 1., 'threshold': .5})
    for host in [official, 'service.' + official]:
        assert calculate_domain_typosquatting_score('https://' + host)['score'] == 0
        result=risk_scoring.calculate_final_risk_score(url='https://' + host, db=db)
        assert 'url_model' not in result['supporting_signals']
        if host==official:
            assert result['verdict']=='LOW'
    assert risk_scoring.calculate_final_risk_score(url='https://' + lookalike, db=db)['verdict'] == 'HIGH'


def test_registry_seed_is_idempotent_and_uses_sourced_verification_dates(db):
    populate_registry(db)
    count=db.query(BrandDomain).count()
    populate_registry(db)
    assert db.query(BrandDomain).count()==count
    assert all(row.verified_date==date(2026,10,17) for row in db.query(BrandDomain).filter(BrandDomain.domain.in_(OCTOBER_VERIFIED_DOMAINS)))
    assert db.query(EgyptianBrand).filter_by(brand_name='Vodafone Cash').one()
    assert db.query(EgyptianBrand).filter_by(brand_name='Fawry').count()==1
    assert db.query(EgyptianBrand).filter_by(brand_name='Instapay').count()==1
