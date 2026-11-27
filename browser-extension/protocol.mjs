/**
 * Pure protocol, URL validation, local-only storage guard and loopback transport
 * for ETIS browser extension v1 (design docs/design/browser-extension-v1.md §1, §2, §6, §7).
 *
 * Chrome/Edge Manifest V3 runtime behaviors (match-pattern port granularity,
 * service worker module lifetime, activeTab scope and chrome.storage.local
 * context isolation) are marked "to verify" against official Chrome/Edge docs.
 * No eval, no remote code, no page-content bridge, no URL/hash persistence.
 */

export const BACKEND_HOST = '127.0.0.1:8000';
export const BACKEND_ORIGIN = 'http://127.0.0.1:8000';
export const PAIR_PATH = '/extension/v1/pair';
export const CHECK_PATH = '/extension/v1/check';
export const PAIR_ENDPOINT = `${BACKEND_ORIGIN}${PAIR_PATH}`;
export const CHECK_ENDPOINT = `${BACKEND_ORIGIN}${CHECK_PATH}`;

export const PAIR_SCHEMA_VERSION = 'extension-pair-v1';
export const CHECK_SCHEMA_VERSION = 'extension-check-v1';

export const MAX_URL_LENGTH = 2048;
export const MAX_BODY_BYTES = 4096;
export const REQUEST_TIMEOUT_MS = 5000;

export const EXTENSION_ID_PATTERN = /^[a-p]{32}$/;
export const IDENTIFIER_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
export const VALID_VERDICTS = Object.freeze(['LOW', 'MEDIUM', 'HIGH', 'INCOMPLETE']);
export const SUPPORTED_LANGUAGES = Object.freeze(['ar', 'en']);

/**
 * Only pairing/auth metadata and language may ever survive a check or restart (§7).
 * Never store URL, URL hash, query/fragment, tabId, documentId, check time, verdict or dismissals.
 */
export const ALLOWED_STORAGE_KEYS = Object.freeze([
  'pairingToken',
  'serverInstanceId',
  'extensionInstanceId',
  'language',
]);

export const FORBIDDEN_SCHEME_PREFIXES = Object.freeze([
  'data:',
  'blob:',
  'file:',
  'javascript:',
  'vbscript:',
  'about:',
  'chrome:',
  'chrome-extension:',
  'edge:',
  'devtools:',
  'view-source:',
  'ftp:',
  'ws:',
  'wss:',
]);

export function validateExtensionId(rawId) {
  if (typeof rawId !== 'string' || !EXTENSION_ID_PATTERN.test(rawId)) {
    return { ok: false, error: 'pairing_invalid' };
  }
  return { ok: true, extensionId: rawId, origin: `chrome-extension://${rawId}` };
}

export function validateIdentifier(value) {
  return typeof value === 'string' && IDENTIFIER_PATTERN.test(value);
}

/**
 * Validate a browser-supplied top-level tab URL and strip its fragment locally (§1).
 * Never decodes data: URLs or inspects their payloads. Refuses embedded credentials.
 */
export function prepareTabUrlForCheck(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return { ok: false, error: 'input_invalid' };
  }
  if (rawUrl !== rawUrl.trim() || /[\r\n\t\0]/.test(rawUrl)) {
    return { ok: false, error: 'input_invalid' };
  }
  const lowered = rawUrl.toLowerCase();
  for (const prefix of FORBIDDEN_SCHEME_PREFIXES) {
    if (lowered.startsWith(prefix)) {
      return { ok: false, error: 'input_invalid' };
    }
  }
  if (!lowered.startsWith('http://') && !lowered.startsWith('https://')) {
    return { ok: false, error: 'input_invalid' };
  }
  const hashIndex = rawUrl.indexOf('#');
  const withoutFragment = hashIndex >= 0 ? rawUrl.slice(0, hashIndex) : rawUrl;
  if (withoutFragment.length === 0 || withoutFragment.length > MAX_URL_LENGTH) {
    return {
      ok: false,
      error: withoutFragment.length > MAX_URL_LENGTH ? 'limit_exceeded' : 'input_invalid',
    };
  }
  let parsed;
  try {
    parsed = new URL(withoutFragment);
  } catch {
    return { ok: false, error: 'input_invalid' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, error: 'input_invalid' };
  }
  if (!parsed.hostname) {
    return { ok: false, error: 'input_invalid' };
  }
  if (parsed.username !== '' || parsed.password !== '') {
    return { ok: false, error: 'input_invalid' };
  }
  // Check raw authority for empty userinfo like https://@example.com/
  const schemeSep = withoutFragment.indexOf('://');
  const authorityEnd = withoutFragment.slice(schemeSep + 3).search(/[/?#]/);
  const authority = authorityEnd >= 0
    ? withoutFragment.slice(schemeSep + 3, schemeSep + 3 + authorityEnd)
    : withoutFragment.slice(schemeSep + 3);
  if (authority.includes('@')) {
    return { ok: false, error: 'input_invalid' };
  }
  return { ok: true, cleanUrl: withoutFragment };
}

/**
 * Runtime egress allowlist (§2.1, §2.2): only http://127.0.0.1:8000/extension/v1/pair
 * and http://127.0.0.1:8000/extension/v1/check are permitted.
 */
export function assertAllowedEndpoint(endpointUrl) {
  if (typeof endpointUrl !== 'string') {
    throw new Error('egress_blocked');
  }
  if (endpointUrl !== PAIR_ENDPOINT && endpointUrl !== CHECK_ENDPOINT) {
    throw new Error('egress_blocked');
  }
  const parsed = new URL(endpointUrl);
  if (
    parsed.protocol !== 'http:' ||
    parsed.hostname !== '127.0.0.1' ||
    parsed.port !== '8000' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.search !== '' ||
    parsed.hash !== '' ||
    (parsed.pathname !== PAIR_PATH && parsed.pathname !== CHECK_PATH)
  ) {
    throw new Error('egress_blocked');
  }
  return endpointUrl;
}

/**
 * Guard local storage writes so no URL, hash, tab ID, result, timestamp or dismissal
 * can ever be written to chrome.storage.local (§7).
 */
export function sanitizeStorageWrite(patch) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    throw new Error('forbidden_storage_write');
  }
  const keys = Object.keys(patch);
  if (keys.length === 0) {
    throw new Error('forbidden_storage_write');
  }
  const clean = {};
  for (const key of keys) {
    if (!ALLOWED_STORAGE_KEYS.includes(key)) {
      throw new Error('forbidden_storage_key');
    }
    const value = patch[key];
    if (key === 'language') {
      if (!SUPPORTED_LANGUAGES.includes(value)) {
        throw new Error('invalid_storage_value');
      }
      clean.language = value;
    } else if (key === 'pairingToken') {
      if (value !== null && (typeof value !== 'string' || value.length < 16 || value.length > 128 || /\s/.test(value))) {
        throw new Error('invalid_storage_value');
      }
      clean.pairingToken = value;
    } else if (key === 'serverInstanceId' || key === 'extensionInstanceId') {
      if (value !== null && !validateIdentifier(value)) {
        throw new Error('invalid_storage_value');
      }
      clean[key] = value;
    }
  }
  return clean;
}

export class LocalSettingsStore {
  constructor(storageArea) {
    if (!storageArea || typeof storageArea.get !== 'function' || typeof storageArea.set !== 'function') {
      throw new Error('local_storage_unavailable');
    }
    this._area = storageArea;
  }

  async readSettings() {
    const raw = (await this._area.get(null)) || {};
    const unexpectedKeys = Object.keys(raw).filter((k) => !ALLOWED_STORAGE_KEYS.includes(k));
    if (unexpectedKeys.length > 0 && typeof this._area.remove === 'function') {
      await this._area.remove(unexpectedKeys);
    }
    return {
      pairingToken: typeof raw.pairingToken === 'string' ? raw.pairingToken : null,
      serverInstanceId: validateIdentifier(raw.serverInstanceId) ? raw.serverInstanceId : null,
      extensionInstanceId: validateIdentifier(raw.extensionInstanceId) ? raw.extensionInstanceId : null,
      language: SUPPORTED_LANGUAGES.includes(raw.language) ? raw.language : 'ar',
    };
  }

  async writeSettings(patch) {
    const clean = sanitizeStorageWrite(patch);
    await this._area.set(clean);
    return clean;
  }

  async clearPairing() {
    if (typeof this._area.remove === 'function') {
      await this._area.remove(['pairingToken', 'serverInstanceId']);
    } else {
      await this._area.set({ pairingToken: null, serverInstanceId: null });
    }
  }
}

export function validatePairResponse(payload, expectedInstanceId) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, error: 'protocol_mismatch' };
  }
  if (payload.schema_version !== PAIR_SCHEMA_VERSION) {
    return { ok: false, error: 'protocol_mismatch' };
  }
  if (
    typeof payload.extension_token !== 'string' ||
    payload.extension_token.length < 16 ||
    payload.extension_token.length > 128 ||
    !validateIdentifier(payload.server_instance_id) ||
    payload.extension_instance_id !== expectedInstanceId
  ) {
    return { ok: false, error: 'protocol_mismatch' };
  }
  return {
    ok: true,
    extensionToken: payload.extension_token,
    serverInstanceId: payload.server_instance_id,
    extensionInstanceId: payload.extension_instance_id,
  };
}

export function validateCheckResponse(payload, expectedNonce, expectedServerInstanceId) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, error: 'protocol_mismatch' };
  }
  if (payload.schema_version !== CHECK_SCHEMA_VERSION) {
    return { ok: false, error: 'protocol_mismatch' };
  }
  if (!validateIdentifier(payload.request_ref) || payload.request_ref !== expectedNonce) {
    return { ok: false, error: 'nonce_mismatch' };
  }
  if (!validateIdentifier(payload.server_instance_id) || payload.server_instance_id !== expectedServerInstanceId) {
    return { ok: false, error: 'server_instance_mismatch' };
  }
  if (!VALID_VERDICTS.includes(payload.verdict)) {
    return { ok: false, error: 'protocol_mismatch' };
  }
  if (
    typeof payload.decisive_reason !== 'string' ||
    !Array.isArray(payload.supporting_signals) ||
    !Array.isArray(payload.unavailable_components) ||
    typeof payload.policy_version !== 'string'
  ) {
    return { ok: false, error: 'protocol_mismatch' };
  }
  // Never accept a response that echoes URL, host or unknown keys (§2.2).
  const allowedKeys = new Set([
    'schema_version',
    'request_ref',
    'server_instance_id',
    'verdict',
    'decisive_reason',
    'supporting_signals',
    'unavailable_components',
    'policy_version',
    'url_model_version',
  ]);
  for (const key of Object.keys(payload)) {
    if (!allowedKeys.has(key)) {
      return { ok: false, error: 'protocol_mismatch' };
    }
  }
  // §2.2: If all analysis components are unavailable, show unavailable regardless of transport success.
  const unavail = payload.unavailable_components;
  if (unavail.includes('database_unavailable') && unavail.includes('url_model_unavailable')) {
    return { ok: false, error: 'service_unavailable' };
  }
  return {
    ok: true,
    result: {
      verdict: payload.verdict,
      decisiveReason: payload.decisive_reason,
      supportingSignals: payload.supporting_signals.filter((s) => typeof s === 'string'),
      unavailableComponents: unavail.filter((s) => typeof s === 'string'),
      policyVersion: payload.policy_version,
      urlModelVersion: typeof payload.url_model_version === 'string' ? payload.url_model_version : null,
    },
  };
}

/**
 * Send one authenticated POST request to the exact loopback endpoint (§2 item 2, §2.2).
 * Disables redirects and ambient cookies; never retries or falls back to another host/port.
 */
export async function sendLocalRequest(
  endpointUrl,
  bodyObj,
  { token = null, fetchImpl = globalThis.fetch, timeoutMs = REQUEST_TIMEOUT_MS } = {},
) {
  assertAllowedEndpoint(endpointUrl);
  if (typeof fetchImpl !== 'function') {
    return { ok: false, status: 0, error: 'service_unavailable' };
  }
  const serialized = JSON.stringify(bodyObj);
  if (serialized.length > MAX_BODY_BYTES) {
    return { ok: false, status: 413, error: 'limit_exceeded' };
  }
  const headers = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(endpointUrl, {
      method: 'POST',
      headers,
      body: serialized,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      mode: 'cors',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const code = payload && typeof payload.detail === 'string' ? payload.detail : 'service_unavailable';
      return { ok: false, status: response.status, error: code };
    }
    return { ok: true, status: response.status, payload };
  } catch {
    return { ok: false, status: 0, error: 'service_unavailable' };
  } finally {
    clearTimeout(timer);
  }
}
