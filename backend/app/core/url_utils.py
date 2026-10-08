"""Shared parsing, validation and canonical identity. Never fetch submitted URLs."""
from dataclasses import dataclass
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit, unquote_plus
import idna
import tldextract
from app.core.exceptions import InvalidScanInputError

MAX_URL_LENGTH = 2048
MAX_TEXT_LENGTH = 5000
MAX_LINKS = 10
_suffixes = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)
_link = re.compile(r'(?i)(?:https?://|hxxps?://|www\.)[^\s<>"\u201c\u201d]+|(?<![\w@])(?:[\w-]+(?:\[\.\]|\.)+)+(?:[a-z]{2,63})(?::\d+)?(?:/[^\s<>"\u201c\u201d]*)?')

@dataclass(frozen=True)
class ParsedURL:
    canonical: str
    host: str
    unicode_host: str
    bare: bool
    userinfo: str
    path: str
    query: str
    scheme: str
    port: int | None

def parse_url(value: str) -> ParsedURL:
    if not isinstance(value, str) or not value.strip():
        raise InvalidScanInputError('invalid_url')
    value = value.strip()
    if len(value) > MAX_URL_LENGTH:
        raise InvalidScanInputError('url_too_long')
    if re.search(r'[\x00-\x20\x7f\\]', value):
        raise InvalidScanInputError('invalid_url')
    # A colon in a bare hostname's numeric port is not a URI scheme.
    explicit = bool(re.match(r'^[a-z][a-z0-9+.-]*:', value, re.I)) and not bool(re.match(r'^[\w.-]+:\d+(?:/|$)', value))
    bare = not explicit
    if value.startswith('//'):
        raise InvalidScanInputError('invalid_url')
    try:
        parts = urlsplit('http://' + value if bare else value)
        if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
            raise ValueError()
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        host = parts.hostname.rstrip('.')
        if parts.hostname.endswith('..'):
            raise ValueError()
        try:
            address = ipaddress.ip_address(host)
            host = address.compressed
            unicode_host = host
        except ValueError:
            host = idna.encode(host, uts46=True).decode('ascii').lower()
            unicode_host = idna.decode(host)
            if '.' not in host or len(host) > 253:
                raise ValueError()
        scheme = parts.scheme.lower()
        if port == (443 if scheme == 'https' else 80):
            port = None
        netloc = f'[{host}]' if ':' in host else host
        if port is not None:
            netloc += f':{port}'
        # Userinfo is preserved separately as evidence; identity uses the true host.
        userinfo = parts.netloc.rsplit('@', 1)[0] if '@' in parts.netloc else ''
        canonical = urlunsplit((scheme, netloc, parts.path or '/', parts.query, ''))
        return ParsedURL(canonical, host, unicode_host, bare, userinfo, parts.path or '/', parts.query, scheme, port)
    except (ValueError, UnicodeError, idna.IDNAError):
        raise InvalidScanInputError('invalid_url') from None

def url_hash(value: str) -> str:
    return hashlib.sha256(parse_url(value).canonical.encode('utf-8')).hexdigest()

def lookup_keys(value: str) -> list[str]:
    parsed = parse_url(value)
    keys = [parsed.canonical, value.strip()]
    # Only an additional reputation key. Never rewrite the URL being analyzed.
    query = '&'.join(p for p in parsed.query.split('&') if not (unquote_plus(p.split('=', 1)[0]).lower().startswith('utm_') or unquote_plus(p.split('=', 1)[0]).lower() == 'fbclid'))
    if query != parsed.query:
        p = urlsplit(parsed.canonical)
        keys.append(urlunsplit((p.scheme, p.netloc, p.path, query, '')))
    return list(dict.fromkeys(keys))

def registered_domain(host: str) -> str:
    result = _suffixes(host)
    return result.top_domain_under_public_suffix or host

def extract_links(text: str) -> tuple[list[str], list[str]]:
    candidates, invalid = [], []
    normalized = re.sub(r'(?i)hxxp(s?)://', r'http\1://', text).replace('[.]', '.')
    for match in _link.finditer(normalized):
        value = match.group().rstrip('.,;!؟،؛)]}')
        # Avoid extracting filenames and email-domain suffixes as arbitrary domains.
        try:
            parsed = parse_url(value)
            if not value.lower().startswith(('http://', 'https://', 'www.')) and not _suffixes(parsed.host).suffix:
                continue
            if value not in candidates:
                candidates.append(value)
        except InvalidScanInputError:
            invalid.append('invalid_embedded_url')
    return candidates, invalid
