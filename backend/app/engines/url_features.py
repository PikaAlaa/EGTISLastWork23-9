"""Pure string features shared by URL training and local inference."""
import ipaddress
import re
from urllib.parse import urlsplit
import numpy as np
from collections import Counter
from scipy.stats import entropy
from app.core.url_utils import parse_url


def phresh_features(value, host, extractor, full):
    """Frozen phresh-1 dictionary schema, shared with offline evaluation."""
    feature = str(value) if full else host
    p = urlsplit(str(value) if '://' in str(value) else 'http://' + str(value))
    t = extractor(host)
    counts = np.asarray(list(Counter(feature.lower()).values()), float)
    probability = counts / counts.sum()
    try:
        ipaddress.ip_address(host)
        ip = 1
    except ValueError:
        ip = 0
    return {'url_len': len(feature), 'host_len': len(host), 'digits': sum(c.isdigit() for c in feature),
            'digit_ratio': sum(c.isdigit() for c in feature) / max(len(feature), 1), 'hyphens': feature.count('-'),
            'dots': host.count('.'), 'subdomain_depth': len(t.subdomain.split('.')) if t.subdomain else 0,
            'tld': t.suffix.lower(), 'is_ip': ip, 'has_at': int('@' in feature), 'punycode': int('xn--' in host),
            'entropy': float(-(probability * np.log2(probability)).sum()),
            'path_len': len(p.path) if full else 0, 'query_len': len(p.query) if full else 0,
            'token_count': len(re.findall(r'[a-z0-9]+', feature.lower()))}


def shortcut_features(value):
    p = parse_url(value)
    return {'total_length': len(value), 'path_length': len(p.path), 'query_length': len(p.query),
            'has_nonroot_path': int(p.path not in ('', '/')), 'has_query': int(bool(p.query)),
            'https': int(str(value).lower().startswith('https://'))}

def url_features(value, extractor):
 # Host-only training strings can include IPv6 literals; parse as URLs only when a scheme/path is present.
 if '://' in value:
  p=parse_url(value); host=p.host; path=p.path; query=p.query
 else:
  host=str(value).strip().lower().rstrip('.'); path=''; query=''
 parts=host.split('.'); t=extractor(host)
 try: ip=ipaddress.ip_address(host.strip('[]'))
 except ValueError: ip=None
 tokens=re.findall(r'[a-z0-9]+',value.lower())
 chars=Counter(value.lower()); ent=float(entropy(list(chars.values()),base=2)) if chars else 0.0
 return {'url_len':len(value),'host_len':len(host),'digits':sum(c.isdigit() for c in value),
  'digit_ratio':sum(c.isdigit() for c in value)/max(len(value),1),'hyphens':value.count('-'),
  'dots':host.count('.'),'subdomain_depth':max(0,len(parts)-2),'tld':t.suffix.lower(),
  'is_ip':int(ip is not None),'has_at':int('@' in value),'punycode':int('xn--' in host),
  'entropy':ent,'path_len':len(path),'query_len':len(query),'token_count':len(tokens)}
