"""Pure string features shared by URL training and local inference."""
import ipaddress
import re
from collections import Counter
from scipy.stats import entropy
from app.core.url_utils import parse_url

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
