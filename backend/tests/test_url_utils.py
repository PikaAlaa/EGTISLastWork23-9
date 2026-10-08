import pytest
from app.core.url_utils import parse_url,url_hash,extract_links,registered_domain
from app.core.exceptions import InvalidScanInputError

@pytest.mark.parametrize('value',['javascript:alert(1)','data:text/plain,x','file:///x','hello','https://example.com:99999','https://example.com:bad','https://example.com:0','https://exa mple.com','https://[invalid]/','https://example.com/'+('a'*2048),'https://example.com..','https://xn--!!invalid.com'])
def test_invalid_url_is_refused(value):
    with pytest.raises(InvalidScanInputError):parse_url(value)
def test_userinfo_real_host():
    assert parse_url('https://cibeg.com:443@evil.example/login').host=='evil.example'
def test_identity_and_ports():
    assert url_hash('https://EXAMPLE.com:443/a#x')==url_hash('https://example.com/a')
    assert parse_url('https://example.com:80/a').port==80
    assert parse_url('http://example.com:443/a').port==443
    assert url_hash('https://example.com/A?q=1')!=url_hash('https://example.com/a?q=1')
    assert url_hash('https://example.com/a?q=1')!=url_hash('https://example.com/a?q=2')
def test_extract_defanged_and_punctuation():
    links,invalid=extract_links('افحص hxxps://evil[.]example/login، ثم https://google.com/.')
    assert links==['https://evil.example/login','https://google.com/'];assert not invalid
def test_registered_domain_groups_subdomains():
    assert registered_domain('a.example.co.uk')==registered_domain('b.example.co.uk')=='example.co.uk'
