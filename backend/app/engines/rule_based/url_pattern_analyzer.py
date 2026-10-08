import ipaddress
import re
from app.core.url_utils import parse_url

def calculate_url_pattern_score(url: str) -> dict:
    parsed = parse_url(url)
    flags = []
    try:
        ipaddress.ip_address(parsed.host)
        flags.append(('ip_address_host', 20, None))
    except ValueError:
        pass
    if parsed.userinfo:
        flags.append(('userinfo_in_url', 20, None))
    if parsed.port is not None:
        flags.append(('non_standard_port', 10, None))
    if parsed.host.startswith('xn--') or '.xn--' in parsed.host:
        flags.append(('punycode_domain', 8, None))
    if not parsed.bare and parsed.scheme == 'http':
        flags.append(('no_https', 8, None))
    if re.search(r'(?i)(?:login|verify|update|confirm|secure|account)', parsed.path):
        flags.append(('suspicious_path_keyword', 8, None))
    if len(parsed.canonical) > 150:
        flags.append(('long_url', 10, None))
    if parsed.host.count('.') >= 4:
        flags.append(('many_subdomains', 10, None))
    return {'score': float(min(100, sum(f[1] for f in flags))), 'flags': flags}
