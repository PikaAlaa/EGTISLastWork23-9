import pytest
from app.engines.risk_scoring import calculate_final_risk_score
from app.engines import risk_scoring
from app.core.exceptions import InvalidScanInputError

def model(probability):
    return lambda text:{'probability':probability,'score':probability*100,'model':'test','version':'fixture','windows':1}
def test_added_clean_url_never_dilutes_strong_text(db,monkeypatch):
    monkeypatch.setattr(risk_scoring,'score_text',model(.95))
    a=calculate_final_risk_score(text='test message',db=db)
    b=calculate_final_risk_score(text='test message',url='https://example.com/',db=db)
    assert a['verdict']==b['verdict']=='HIGH'
    assert b['final_score']>=a['final_score']
def test_official_domain_does_not_override_text(db,monkeypatch):
    monkeypatch.setattr(risk_scoring,'score_text',model(.99))
    assert calculate_final_risk_score(text='test',url='https://cibeg.com/',db=db)['verdict']=='HIGH'
def test_clean_text_can_reach_low(db,monkeypatch):
    monkeypatch.setattr(risk_scoring,'score_text',model(.01))
    assert calculate_final_risk_score(text='team meeting tomorrow',db=db)['verdict']=='LOW'
def test_blacklisted_url_in_message_and_multiple_links(db,monkeypatch):
    monkeypatch.setattr(risk_scoring,'score_text',model(.01))
    result=calculate_final_risk_score(text='https://google.com/ https://known-phish.example/login',db=db)
    assert result['verdict']=='HIGH';assert len(result['checked_links'])==2
def test_incomplete_precedes_medium(db,monkeypatch):
    def missing(_):raise FileNotFoundError()
    monkeypatch.setattr(risk_scoring,'score_text',missing)
    r=calculate_final_risk_score(text='text',url='http://example.com/',db=db)
    assert r['verdict']=='INCOMPLETE';assert not r['analysis_complete']
def test_high_survives_missing_model(db,monkeypatch):
    def missing(_):raise FileNotFoundError()
    monkeypatch.setattr(risk_scoring,'score_text',missing)
    assert calculate_final_risk_score(text='text',url='https://known-phish.example/login',db=db)['verdict']=='HIGH'
def test_ten_link_limit_is_explicit(db,monkeypatch):
    monkeypatch.setattr(risk_scoring,'score_text',model(.01))
    r=calculate_final_risk_score(text=' '.join(f'https://d{i}.example/' for i in range(11)),db=db)
    assert len(r['checked_links'])==10;assert r['links_truncated'];assert r['verdict']=='INCOMPLETE'
def test_no_database_does_not_claim_clean_url():
    assert calculate_final_risk_score(url='https://example.com/')['verdict']=='INCOMPLETE'
def test_invalid_empty_input():
    with pytest.raises(InvalidScanInputError):calculate_final_risk_score()

def test_duplicate_destination_does_not_hide_userinfo(db,monkeypatch):
    monkeypatch.setattr(risk_scoring,'score_text',model(.01))
    r=calculate_final_risk_score(text='https://evil.example/login https://cibeg.com@evil.example/login',db=db)
    assert r['verdict']=='HIGH'
    assert r['decisive_reason']=='userinfo_brand'
