import pytest
from app.engines.rule_based.url_pattern_analyzer import calculate_url_pattern_score
@pytest.mark.parametrize('url,flag',[('http://example.com','no_https'),('http://192.0.2.1/login','ip_address_host'),('https://x@example.com/','userinfo_in_url'),('https://example.com:80','non_standard_port')])
def test_warning_flags(url,flag):
    assert flag in [x[0] for x in calculate_url_pattern_score(url)['flags']]
def test_bare_domain_does_not_invent_http_warning():
    assert calculate_url_pattern_score('cibeg.com')['flags']==[]
def test_https_clean():
    assert calculate_url_pattern_score('https://example.com')['score']==0
