"""Invented unit fixtures only; none are authentic or evaluated Egyptian SMS."""
import json
import re
from pathlib import Path
import pytest
from app.core.sender_claims import has_financial_or_telecom_brand_claim
from app.engines import risk_scoring
from app.models import ScanRequest, ScanResult

SIGNAL='brand_claim_from_mobile_number'


@pytest.fixture
def low_text(monkeypatch):
    monkeypatch.setattr(risk_scoring,'score_text',lambda _:dict(probability=.01,score=1,model='fixture',version='unit',windows=1))


@pytest.mark.parametrize('text',[
    'CIB: A notice is available in the app.',
    'This is Vodafone customer service.',
    'A notice from InstaPay is available.',
    'رسالة من البنك الأهلي المصري بخصوص حسابك.',
    'فودافون كاش: تم تنفيذ العملية.',
    'This notice is from your bank.',
    'A service notice - Fawry',
])
def test_brand_claim_from_mobile_is_only_supporting(low_text,text):
    result=risk_scoring.calculate_final_risk_score(text=text,sender_type='mobile_number')
    assert result['verdict']=='MEDIUM'
    assert result['supporting_signals']==[SIGNAL]


@pytest.mark.parametrize('sender_type',[None,'unknown','company_name','short_code'])
def test_sender_field_optional_and_other_displays_do_not_add_signal(low_text,sender_type):
    result=risk_scoring.calculate_final_risk_score(text='CIB: A notice is available.',sender_type=sender_type)
    assert result['verdict']=='LOW'
    assert SIGNAL not in result['supporting_signals']


@pytest.mark.parametrize('text',[
    'An ordinary service notice.', 'Bosta: A delivery notice is available.',
    'Aramex: A parcel notice is available.', 'I paid for groceries with Fawry yesterday.',
    'Someone mentioned CIB in our discussion.', 'WEATHER conditions are pleasant.',
])
def test_mobile_without_financial_sender_claim_is_not_a_signal(low_text,text):
    assert not has_financial_or_telecom_brand_claim(text)
    result=risk_scoring.calculate_final_risk_score(text=text,sender_type='mobile_number')
    assert result['verdict']=='LOW' and SIGNAL not in result['supporting_signals']


def test_sender_signal_does_not_corroborate_text_model_high(monkeypatch):
    monkeypatch.setattr(risk_scoring,'score_text',lambda _:dict(probability=.99,score=99,model='fixture',version='unit',windows=1))
    result=risk_scoring.calculate_final_risk_score(text='CIB: A notice is available.',sender_type='mobile_number')
    assert result['verdict']=='MEDIUM'
    assert SIGNAL in result['supporting_signals']
    assert 'text_high_corroborated' not in result['supporting_signals']


def test_existing_decisive_evidence_keeps_high_with_any_sender_type(db,low_text,monkeypatch):
    monkeypatch.setattr(risk_scoring,'blacklist_health',lambda _:dict(available=True,reason=None))
    for display in ['company_name','short_code','mobile_number','unknown',None]:
        result=risk_scoring.calculate_final_risk_score(text='CIB: A notice.',url='https://known-phish.example/login',sender_type=display,db=db)
        assert result['verdict']=='HIGH'


def test_api_accepts_sender_without_storing_input_field(client,db,low_text,caplog):
    response=client.post('/analyze',json={'text':'CIB: A notice.','sender_type':'mobile_number'})
    assert response.status_code==200 and response.json()['verdict']=='MEDIUM'
    assert SIGNAL in response.json()['supporting_signals']
    assert 'sender_type' not in response.json()
    request=db.query(ScanRequest).one();result=db.query(ScanResult).one()
    assert 'sender_type' not in request.__table__.columns
    assert 'sender_type' not in result.__table__.columns
    assert 'sender_type' not in json.dumps(result.engine_breakdown)
    assert 'sender_type' not in caplog.text
    assert client.post('/analyze',json={'text':'CIB: A notice.','sender_type':None}).status_code==200


@pytest.mark.parametrize('value',['made_up',23,{},['mobile_number']])
def test_api_rejects_invalid_sender_types_without_echo(client,value):
    response=client.post('/analyze',json={'text':'unit fixture','sender_type':value})
    assert response.status_code==400
    assert 'unit fixture' not in response.text
    assert 'made_up' not in response.text


def test_url_only_mobile_field_has_no_sender_claim_effect(db,low_text,monkeypatch):
    monkeypatch.setattr(risk_scoring,'blacklist_health',lambda _:dict(available=True,reason=None))
    result=risk_scoring.calculate_final_risk_score(url='https://cibeg.com/',sender_type='mobile_number',db=db)
    assert result['verdict']=='LOW' and SIGNAL not in result['supporting_signals']


def test_sender_options_and_advice_have_both_translations():
    root=Path(__file__).resolve().parents[2]
    for language in ['ar','en']:
        strings=json.loads((root/f'etis-frontend/src/i18n/locales/{language}.json').read_text(encoding='utf-8'))
        assert set(strings['scan']['senderTypes'])=={'company_name','short_code','mobile_number','unknown'}
        assert strings['reason'][SIGNAL] and strings['advice']['senderType']
        if language=='ar':
            for value in [strings['scan']['senderLabel'],strings['scan']['senderHelp'],
                          strings['reason'][SIGNAL],strings['advice']['senderType'],*strings['scan']['senderTypes'].values()]:
                assert re.search(r'[\u0621-\u064a]',value)
                assert '??' not in value
