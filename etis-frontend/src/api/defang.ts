/**
 * De-fanged display of indicator values, rules `defang-v1` (docs/design/core-v2.md §4.2).
 *
 * Display only: the console shows `hxxps://evil[.]example` instead of a live-looking value.
 * Stored, hashed, looked-up and exported values stay canonical. Pure string functions; nothing
 * here resolves, fetches or opens a value. The cases in docs/design/defang-cases.json are the
 * contract shared with the backend (`app/core/defang.py`) and checked by tests/defang.test.mts.
 */

export const DEFANG_VERSION = 'defang-v1';

export type DefangType = 'url' | 'domain' | 'ip' | 'email' | 'phone' | 'hash' | string;

const SCHEMES: Record<string, string> = { http: 'hxxp', https: 'hxxps', ftp: 'fxp' };
const REFANG_SCHEMES: Record<string, string> = { hxxp: 'http', hxxps: 'https', fxp: 'ftp' };
const SCHEME = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//;
const DEFANGED_SCHEME = /^(hxxps?|fxp):\/\//i;
const UNCHANGED = new Set(['hash', 'phone']);
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** Undo every defang-v1 mark: hxxp/hxxps/fxp schemes, `[.]`, `[@]` and `[:]`. */
export function refang(value: string): string {
  const text = value.trim().replace(DEFANGED_SCHEME, (_, scheme: string) => `${REFANG_SCHEMES[scheme.toLowerCase()]}://`);
  return text.split('[.]').join('.').split('[@]').join('@').split('[:]').join(':');
}

function isIpv6(value: string): boolean {
  if (!value.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(value)) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

/** IDN hosts are shown in IDNA ASCII (`xn--…`), never as Unicode. */
function asciiHost(host: string): string {
  if (Array.from(host).every((ch) => ch.charCodeAt(0) < 128)) return host;
  try {
    return new URL(`http://${host}/`).hostname;
  } catch {
    // Not encodable: show code points escaped rather than lookalike characters.
    return Array.from(host, (ch) => (ch.charCodeAt(0) < 128 ? ch : `\\u${ch.codePointAt(0)!.toString(16)}`)).join('');
  }
}

function dots(text: string): string {
  return text.split('.').join('[.]');
}

function hostPart(host: string): string {
  if (host.startsWith('[') && host.endsWith(']')) return `[${host.slice(1, -1).split(':').join('[:]')}]`;
  return dots(asciiHost(host));
}

function defangUrl(value: string): string {
  const match = SCHEME.exec(value);
  let prefix = '';
  let rest = value;
  if (match) {
    const scheme = match[1].toLowerCase();
    prefix = `${SCHEMES[scheme] ?? scheme}://`;
    rest = value.slice(match[0].length);
  }
  const cuts = ['/', '?', '#'].map((c) => rest.indexOf(c)).filter((i) => i >= 0);
  const cut = cuts.length ? Math.min(...cuts) : rest.length;
  const authority = rest.slice(0, cut);
  const tail = rest.slice(cut);
  const at = authority.lastIndexOf('@');
  const userinfo = at >= 0 ? authority.slice(0, at) : '';
  const hostport = at >= 0 ? authority.slice(at + 1) : authority;
  let host: string;
  let port: string;
  if (hostport.startsWith('[')) {
    const end = hostport.indexOf(']');
    host = end >= 0 ? hostport.slice(0, end + 1) : hostport;
    port = end >= 0 ? hostport.slice(end + 1) : '';
  } else {
    const colon = hostport.indexOf(':');
    host = colon >= 0 ? hostport.slice(0, colon) : hostport;
    port = colon >= 0 ? hostport.slice(colon) : '';
  }
  const shownUser = at >= 0 ? `${dots(userinfo.split('@').join('[@]'))}[@]` : '';
  return prefix + shownUser + hostPart(host) + port + tail;
}

function defangIp(value: string): string {
  const bare = value.replace(/^\[|\]$/g, '');
  if (IPV4.test(bare)) {
    const last = bare.lastIndexOf('.');
    return `${bare.slice(0, last)}[.]${bare.slice(last + 1)}`;
  }
  if (isIpv6(bare)) return bare.split(':').join('[:]');
  return bare.split('.').join('[.]').split(':').join('[:]');
}

function defangEmail(value: string): string {
  const at = value.lastIndexOf('@');
  if (at < 0) return dots(asciiHost(value));
  return `${value.slice(0, at)}[@]${dots(asciiHost(value.slice(at + 1)))}`;
}

/**
 * De-fanged display form of a canonical (or already de-fanged) value. Idempotent: the value
 * is refanged first. Hashes, phone numbers and unknown types are returned unchanged.
 */
export function defang(type: DefangType, value: string): string {
  if (UNCHANGED.has(type)) return value;
  const plain = refang(value);
  switch (type) {
    case 'url':
      return defangUrl(plain);
    case 'domain':
      return dots(asciiHost(plain));
    case 'ip':
      return defangIp(plain);
    case 'email':
      return defangEmail(plain);
    default:
      return value;
  }
}

/**
 * Best guess of the indicator type of a value that has none attached (a community report's raw
 * value, or a checked link's host). Used only to pick the display rule; it never changes data.
 */
export function guessIndicatorType(value: string): DefangType {
  const plain = refang(value);
  if (SCHEME.test(plain)) return 'url';
  const bare = plain.replace(/^\[|\]$/g, '');
  if (IPV4.test(bare) || isIpv6(bare)) return 'ip';
  if (/^[^@\s]+@[^@\s]+$/.test(plain)) return 'email';
  if (/^\+?[\d\s()-]{3,}$/.test(plain)) return 'phone';
  if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(plain)) return 'hash';
  if (plain.includes('/')) return 'url';
  if (plain.includes('.')) return 'domain';
  return 'text';
}
