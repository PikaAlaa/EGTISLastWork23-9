import ipaddress
import re
from app.core.url_utils import parse_url

PATTERN_ALERT_POLICY = 'four_structural_only'
STRUCTURAL_FLAGS = {'ip_address_host', 'userinfo_in_url', 'non_standard_port', 'punycode_domain', 'many_subdomains'}
WEAK_FLAGS = {'no_https', 'suspicious_path_keyword', 'long_url'}


def alerting_flags(flags, policy=None):
    """Keep observations separate from flags allowed to create a warning."""
    policy = policy or PATTERN_ALERT_POLICY
    if policy == 'legacy':
        return flags
    names = {flag[0] for flag in flags}
    if policy == 'structural_or_weak_pair':
        allowed = STRUCTURAL_FLAGS | (WEAK_FLAGS if len(names & WEAK_FLAGS) >= 2 else set())
    elif policy == 'structural_only':
        allowed = STRUCTURAL_FLAGS
    elif policy == 'four_structural_only':
        allowed = STRUCTURAL_FLAGS - {'many_subdomains'}
    elif policy == 'userinfo_or_punycode':
        allowed = {'userinfo_in_url', 'punycode_domain'}
    else:
        raise ValueError('Unknown pattern alert policy')
    return [flag for flag in flags if flag[0] in allowed]

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
    active = alerting_flags(flags)
    return {'score': float(min(100, sum(f[1] for f in flags))), 'flags': flags,
            'alert_flags': active, 'alert_score': float(min(100, sum(f[1] for f in active)))}
