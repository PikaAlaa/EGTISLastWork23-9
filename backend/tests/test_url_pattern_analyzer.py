import pytest
from app.engines.rule_based.url_pattern_analyzer import calculate_url_pattern_score
from app.engines.rule_based import url_pattern_analyzer as patterns
from app.engines import risk_scoring
@pytest.mark.parametrize('url,flag',[('http://example.com','no_https'),('http://192.0.2.1/login','ip_address_host'),('https://x@example.com/','userinfo_in_url'),('https://example.com:80','non_standard_port')])
def test_warning_flags(url,flag):
    assert flag in [x[0] for x in calculate_url_pattern_score(url)['flags']]
def test_bare_domain_does_not_invent_http_warning():
    assert calculate_url_pattern_score('cibeg.com')['flags']==[]
def test_https_clean():
    assert calculate_url_pattern_score('https://example.com')['score']==0


@pytest.mark.parametrize('url,observation', [
    ('http://example.test/', 'no_https'),
    ('https://example.test/login', 'suspicious_path_keyword'),
    ('https://example.test/' + 'x' * 160, 'long_url'),
    ('https://a.b.c.d.example.test/', 'many_subdomains'),
])
def test_diagnostic_pattern_does_not_create_medium(db, monkeypatch, url, observation):
    monkeypatch.setattr(patterns, 'PATTERN_ALERT_POLICY', 'four_structural_only')
    monkeypatch.setattr(risk_scoring, 'score_url', lambda _: None)
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {'available': True, 'reason': None})
    finding = calculate_url_pattern_score(url)
    assert observation in [f[0] for f in finding['flags']]
    assert finding['alert_flags'] == []
    scan = risk_scoring.calculate_final_risk_score(url=url, db=db)
    assert scan['verdict'] == 'LOW'
    assert scan['checked_links'][0]['patterns'] == []
    assert observation in [f[0] for f in scan['checked_links'][0]['pattern_observations']]


@pytest.mark.parametrize('url', ['https://person@example.test/', 'https://192.0.2.1/', 'https://example.test:8080/'])
def test_structural_pattern_remains_alerting(db, monkeypatch, url):
    monkeypatch.setattr(patterns, 'PATTERN_ALERT_POLICY', 'four_structural_only')
    monkeypatch.setattr(risk_scoring, 'score_url', lambda _: None)
    monkeypatch.setattr(risk_scoring, 'blacklist_health', lambda _: {'available': True, 'reason': None})
    assert risk_scoring.calculate_final_risk_score(url=url, db=db)['verdict'] == 'MEDIUM'
