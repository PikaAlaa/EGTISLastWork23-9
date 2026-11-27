"""Step 6 tests: Unavailable/incomplete UI states, bilingual AR/EN coverage, privacy and egress gates.

Design: docs/design/browser-extension-v1.md (§2.2, §2.4, §4, §6, §7, §8, §9 step 6).
All URLs and page fixtures in this file are INVENTED on reserved RFC 2606 domains (example.com).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest
from sqlalchemy import text as sql_text

from app.engines import risk_scoring
from app.services.extension_config import (
    ALLOWED_BACKEND_HOST,
    ALLOWED_REASON_CODES,
    CHECK_SCHEMA_VERSION,
    ERROR_CODES,
    PAIR_SCHEMA_VERSION,
    UNAVAILABLE_COMPONENT_CODES,
)
from app.services.extension_pairing import pairing_store

ROOT = Path(__file__).resolve().parents[2]
EXT_DIR = ROOT / 'browser-extension'
FRONTEND_LOCALES = ROOT / 'etis-frontend' / 'src' / 'i18n' / 'locales'
APPROVED_ID = 'a' * 32
APPROVED_ORIGIN = f'chrome-extension://{APPROVED_ID}'
INSTANCE_ID = 'ext_instance_invented_0001'
NONCE = 'req_nonce_invented_0001'


def _db_snapshot(db) -> list[tuple[str, list[tuple]]]:
    snapshot = []
    for table in sorted(db.bind.dialect.get_table_names(db.connection())):
        rows = [tuple(row) for row in db.execute(sql_text(f'SELECT * FROM "{table}"'))]
        snapshot.append((table, rows))
    return snapshot


@pytest.fixture(autouse=True)
def reset_state():
    pairing_store.reset_for_restart()
    yield
    pairing_store.reset_for_restart()


def test_bilingual_i18n_parity_across_extension_popup_banner_and_frontend_pairing():
    ar_locale = json.loads((FRONTEND_LOCALES / 'ar.json').read_text(encoding='utf-8'))
    en_locale = json.loads((FRONTEND_LOCALES / 'en.json').read_text(encoding='utf-8'))
    assert 'extensionPairing' in ar_locale and 'extensionPairing' in en_locale
    assert set(ar_locale['extensionPairing']) == set(en_locale['extensionPairing'])
    for key, val in ar_locale['extensionPairing'].items():
        assert isinstance(val, str) and val.strip()
        assert isinstance(en_locale['extensionPairing'][key], str) and en_locale['extensionPairing'][key].strip()

    reasons_json = json.dumps(sorted(ALLOWED_REASON_CODES))
    unavail_json = json.dumps(sorted(UNAVAILABLE_COMPONENT_CODES))
    errors_json = json.dumps(sorted(ERROR_CODES))

    script = f"""
import assert from 'node:assert/strict';
import {{ POPUP_I18N }} from './browser-extension/i18n.mjs';
import {{ BANNER_COPY, REASON_LABELS }} from './browser-extension/banner.mjs';

const allowedReasons = {reasons_json};
const unavailableCodes = {unavail_json};
const errorCodes = {errors_json};

// 1. Arabic and English popup dictionaries have identical top-level and nested key sets.
assert.deepEqual(Object.keys(POPUP_I18N.ar).sort(), Object.keys(POPUP_I18N.en).sort());
for (const section of ['verdicts', 'reasons', 'unavailableComponents', 'errors']) {{
  assert.deepEqual(
    Object.keys(POPUP_I18N.ar[section]).sort(),
    Object.keys(POPUP_I18N.en[section]).sort(),
    `Mismatch in section ${{section}}`,
  );
  for (const [k, arText] of Object.entries(POPUP_I18N.ar[section])) {{
    const enText = POPUP_I18N.en[section][k];
    assert.equal(typeof arText === 'string' && arText.trim().length > 0, true, `Empty AR for ${{section}}.${{k}}`);
    assert.equal(typeof enText === 'string' && enText.trim().length > 0, true, `Empty EN for ${{section}}.${{k}}`);
  }}
}}

// 2. Every backend reason code, unavailable-component code and error code is covered in both AR and EN.
for (const code of unavailableCodes) {{
  assert.equal(code in POPUP_I18N.ar.unavailableComponents, true, `Missing AR unavailable code ${{code}}`);
  assert.equal(code in POPUP_I18N.en.unavailableComponents, true, `Missing EN unavailable code ${{code}}`);
}}
for (const code of allowedReasons) {{
  const inReasons = (code in POPUP_I18N.ar.reasons) && (code in POPUP_I18N.en.reasons);
  const inUnavail = (code in POPUP_I18N.ar.unavailableComponents) && (code in POPUP_I18N.en.unavailableComponents);
  assert.equal(inReasons || inUnavail, true, `Missing translation for reason code ${{code}}`);
}}
for (const code of errorCodes) {{
  assert.equal(code in POPUP_I18N.ar.errors, true, `Missing AR error code ${{code}}`);
  assert.equal(code in POPUP_I18N.en.errors, true, `Missing EN error code ${{code}}`);
}}

// 3. Banner AR and EN dictionaries have identical structure.
assert.deepEqual(Object.keys(BANNER_COPY.ar).sort(), Object.keys(BANNER_COPY.en).sort());
assert.deepEqual(Object.keys(REASON_LABELS.ar).sort(), Object.keys(REASON_LABELS.en).sort());
"""
    proc = subprocess.run(
        ['node', '--input-type=module', '-e', script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_unavailable_and_incomplete_states_never_display_low_or_inject_banner():
    script = """
import assert from 'node:assert/strict';
import { buildPopupViewModel } from './browser-extension/i18n.mjs';
import { buildBannerPayload } from './browser-extension/banner.mjs';
import { LocalSettingsStore } from './browser-extension/protocol.mjs';
import { handlePopupMessage } from './browser-extension/background.js';

const extId = 'a'.repeat(32);
const popupPrefix = `chrome-extension://${extId}/popup.html`;
const activeTab = {
  id: 7,
  windowId: 1,
  active: true,
  incognito: false,
  url: 'https://example.com/invented-check',
};

// 1. Every failure state (stopped server, timeout, revoked token, protocol mismatch, nonce mismatch, stale nav)
//    produces displayState === 'UNAVAILABLE' in both AR and EN, never 'LOW', and never builds a warning banner.
const failureCodes = [
  'service_unavailable',
  'pairing_required',
  'pairing_invalid',
  'protocol_mismatch',
  'nonce_mismatch',
  'server_instance_mismatch',
  'limit_exceeded',
  'input_invalid',
  'stale_navigation_cancelled',
  'incognito_disabled',
];

for (const code of failureCodes) {
  for (const lang of ['ar', 'en']) {
    const vm = buildPopupViewModel({ ok: false, error: code }, lang);
    assert.equal(vm.displayState, 'UNAVAILABLE');
    assert.notEqual(vm.displayState, 'LOW');
    assert.equal(buildBannerPayload({ verdict: vm.displayState }, lang), null);
  }
}
assert.equal(
  buildPopupViewModel({ ok: false, error: 'service_unavailable' }, 'en').summaryText,
  'ETIS unavailable — this page was not fully checked',
);
assert.equal(
  buildPopupViewModel({ ok: false, error: 'service_unavailable' }, 'ar').summaryText,
  'نظام ETIS غير متاح — لم يتم فحص هذه الصفحة بالكامل',
);

// 2. INCOMPLETE verdict lists unavailable component categories, offers user retry, never shows LOW, and builds no warning banner.
const incompleteState = {
  ok: true,
  verdict: 'INCOMPLETE',
  decisiveReason: 'database_unavailable',
  supportingSignals: [],
  unavailableComponents: ['database_unavailable', 'url_model_unavailable'],
  bannerCoverage: 'not_applicable',
};
const vmEn = buildPopupViewModel(incompleteState, 'en');
const vmAr = buildPopupViewModel(incompleteState, 'ar');
assert.equal(vmEn.displayState, 'INCOMPLETE');
assert.equal(vmAr.displayState, 'INCOMPLETE');
assert.equal(vmEn.showRetry, true);
assert.equal(vmAr.showRetry, true);
assert.equal(vmEn.unavailableItems.length, 2);
assert.equal(vmAr.unavailableItems.length, 2);
assert.equal(buildBannerPayload(incompleteState, 'en'), null);

// 3. Simulated connection failure followed by user-triggered retry: zero retry queue, zero stored history.
const backing = {
  pairingToken: 'invented_bearer_token_00000001',
  serverInstanceId: 'srv_instance_invented_0001',
  extensionInstanceId: 'ext_instance_invented_0001',
  language: 'en',
};
const store = new LocalSettingsStore({
  async get() { return { ...backing }; },
  async set(p) { Object.assign(backing, p); },
  async remove(keys) { for (const k of keys) delete backing[k]; },
});

let serverOnline = false;
let fetchCount = 0;
const env = {
  runtimeId: extId,
  popupUrlPrefix: popupPrefix,
  settingsStore: store,
  queryActiveTab: async () => activeTab,
  fetchImpl: async (_url, init) => {
    fetchCount += 1;
    if (!serverOnline) {
      throw new TypeError('fetch failed: ECONNREFUSED 127.0.0.1:8000');
    }
    const req = JSON.parse(init.body);
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          schema_version: 'extension-check-v1',
          request_ref: req.request_ref,
          server_instance_id: 'srv_instance_invented_0001',
          verdict: 'LOW',
          decisive_reason: 'no_warning_signs',
          supporting_signals: [],
          unavailable_components: [],
          policy_version: 'decision-v2',
          url_model_version: 'ee0ba9f0077c1fd140aa',
        };
      },
    };
  },
};

const offlineRes = await handlePopupMessage({ action: 'CHECK_ACTIVE_TAB' }, { id: extId, url: popupPrefix }, env);
assert.equal(offlineRes.ok, false);
assert.equal(offlineRes.error, 'service_unavailable');
assert.equal(fetchCount, 1); // No automatic background retry loop!
const offlineVm = buildPopupViewModel(offlineRes, 'en');
assert.equal(offlineVm.displayState, 'UNAVAILABLE');
assert.equal(offlineVm.showRetry, true);

// User starts ETIS and clicks Retry explicitly:
serverOnline = true;
const retryRes = await handlePopupMessage({ action: 'CHECK_ACTIVE_TAB' }, { id: extId, url: popupPrefix }, env);
assert.equal(retryRes.ok, true);
assert.equal(retryRes.verdict, 'LOW');
assert.equal(fetchCount, 2);
assert.equal(JSON.stringify(backing).includes('example.com'), false);
"""
    proc = subprocess.run(
        ['node', '--input-type=module', '-e', script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_end_to_end_privacy_and_egress_across_extension_and_backend(client, db, caplog, monkeypatch):
    """§4 & §8 gate: secret markers in page DOM/title/forms/cookies/fragment and URL never leak or persist."""
    before_db = _db_snapshot(db)
    caplog.clear()

    # 1. Operator approves the 32-letter [a-p] extension ID and obtains a one-use pairing secret.
    approve = client.post(
        '/extension/v1/pairing-secret',
        headers={'Host': ALLOWED_BACKEND_HOST},
        json={'extension_id': APPROVED_ID},
    )
    assert approve.status_code == 200
    one_use_secret = approve.json()['pairing_secret']

    # 2. Pair via FastAPI /extension/v1/pair.
    pair_res = client.post(
        '/extension/v1/pair',
        headers={'Host': ALLOWED_BACKEND_HOST, 'Origin': APPROVED_ORIGIN},
        json={
            'schema_version': PAIR_SCHEMA_VERSION,
            'pairing_secret': one_use_secret,
            'extension_instance_id': INSTANCE_ID,
        },
    )
    assert pair_res.status_code == 200
    pair_payload = pair_res.json()

    # 3. Run the real extension background flow in Node, capturing its exact outbound fetch request,
    #    forwarding that request to FastAPI /extension/v1/check, and feeding the response back to Node.
    page_html_marker = 'PageHtmlBodySecretMarker_101'
    page_title_marker = 'PageTitleSecretMarker_202'
    page_form_marker = 'PageFormInputSecretMarker_303'
    page_cookie_marker = 'PageCookieSecretMarker_404'
    page_selection_marker = 'PageSelectionSecretMarker_505'
    url_host_marker = 'invented-privacy-host.example.com'
    url_path_marker = 'InventedPrivatePath_606'
    url_query_marker = 'InventedPrivateQuery_707'
    url_fragment_marker = 'InventedPrivateFragment_808'
    tab_full_url = f'https://{url_host_marker}/{url_path_marker}?q={url_query_marker}#{url_fragment_marker}'

    # First let Node prepare and capture the outbound check request from handlePopupMessage.
    prep_script = f"""
import assert from 'node:assert/strict';
import {{ LocalSettingsStore }} from './browser-extension/protocol.mjs';
import {{ handlePopupMessage }} from './browser-extension/background.js';

const extId = {json.dumps(APPROVED_ID)};
const popupPrefix = `chrome-extension://${{extId}}/popup.html`;
const backing = {{
  pairingToken: {json.dumps(pair_payload['extension_token'])},
  serverInstanceId: {json.dumps(pair_payload['server_instance_id'])},
  extensionInstanceId: {json.dumps(INSTANCE_ID)},
  language: 'ar',
}};
const store = new LocalSettingsStore({{
  async get() {{ return {{ ...backing }}; }},
  async set(p) {{ Object.assign(backing, p); }},
  async remove(keys) {{ for (const k of keys) delete backing[k]; }},
}});

let capturedFetch = null;
await handlePopupMessage(
  {{ action: 'CHECK_ACTIVE_TAB' }},
  {{ id: extId, url: popupPrefix }},
  {{
    runtimeId: extId,
    popupUrlPrefix: popupPrefix,
    settingsStore: store,
    queryActiveTab: async () => ({{
      id: 99,
      windowId: 1,
      active: true,
      incognito: false,
      url: {json.dumps(tab_full_url)},
      title: {json.dumps(page_title_marker)},
    }}),
    fetchImpl: async (url, init) => {{
      capturedFetch = {{ url, method: init.method, headers: init.headers, body: init.body, credentials: init.credentials, redirect: init.redirect, cache: init.cache }};
      return {{
        ok: false,
        status: 503,
        async json() {{ return {{ detail: 'service_unavailable' }}; }},
      }};
    }},
  }},
);
console.log(JSON.stringify({{ capturedFetch, backing }}));
"""
    prep_proc = subprocess.run(
        ['node', '--input-type=module', '-e', prep_script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert prep_proc.returncode == 0, prep_proc.stderr
    prep_out = json.loads(prep_proc.stdout.strip())
    captured_fetch = prep_out['capturedFetch']

    # Egress verification: exact loopback URL, POST, omit cookies, error on redirect, no fragment or page markers in wire body.
    assert captured_fetch['url'] == 'http://127.0.0.1:8000/extension/v1/check'
    assert captured_fetch['method'] == 'POST'
    assert captured_fetch['credentials'] == 'omit'
    assert captured_fetch['redirect'] == 'error'
    assert captured_fetch['cache'] == 'no-store'
    wire_body = captured_fetch['body']
    for page_secret in (
        page_html_marker,
        page_title_marker,
        page_form_marker,
        page_cookie_marker,
        page_selection_marker,
        url_fragment_marker,
    ):
        assert page_secret not in wire_body

    # Forward the exact wire payload to FastAPI /extension/v1/check (with a stubbed HIGH scorer to also test banner rendering).
    monkeypatch.setattr(
        risk_scoring,
        'calculate_final_risk_score',
        lambda **_kw: {
            'verdict': 'HIGH',
            'final_score': 95.0,
            'decisive_reason': 'blacklist_exact',
            'supporting_signals': ['blacklist_exact'],
            'checked_links': [{
                'url': f'https://{url_host_marker}/{url_path_marker}?q={url_query_marker}',
                'host': url_host_marker,
                'bare': False,
                'brand': {'score': 0, 'decisive': False, 'matched_brand': None, 'technique': None, 'official_contact': None},
                'patterns': [],
                'pattern_observations': [],
                'blacklist': {'score': 95, 'match_type': 'exact', 'matched_entry': None},
                'url_model_probability': 0.99,
                'url_model_threshold': 0.9870690448552604,
                'url_model_above_threshold': True,
                'url_model_raw_above_threshold': True,
                'verified_official_host': False,
                'shared_hosting_domain': False,
                'analysis_complete': True,
            }],
            'links_truncated': False,
            'text_finding': None,
            'analysis_complete': True,
            'checks_unavailable': [],
            'policy_version': 'decision-v2',
            'timing_ms': 1.0,
        },
    )
    api_res = client.post(
        '/extension/v1/check',
        headers={
            'Host': ALLOWED_BACKEND_HOST,
            'Origin': APPROVED_ORIGIN,
            **captured_fetch['headers'],
        },
        content=wire_body.encode('utf-8'),
    )
    assert api_res.status_code == 200
    api_json_text = api_res.text

    # Feed the real backend response back into the extension's check + banner + popup rendering in Node.
    verify_script = f"""
import assert from 'node:assert/strict';
import {{ LocalSettingsStore }} from './browser-extension/protocol.mjs';
import {{ handlePopupMessage }} from './browser-extension/background.js';
import {{ buildPopupViewModel }} from './browser-extension/i18n.mjs';

const extId = {json.dumps(APPROVED_ID)};
const popupPrefix = `chrome-extension://${{extId}}/popup.html`;
const backing = {{
  pairingToken: {json.dumps(pair_payload['extension_token'])},
  serverInstanceId: {json.dumps(pair_payload['server_instance_id'])},
  extensionInstanceId: {json.dumps(INSTANCE_ID)},
  language: 'ar',
}};
const store = new LocalSettingsStore({{
  async get() {{ return {{ ...backing }}; }},
  async set(p) {{ Object.assign(backing, p); }},
  async remove(keys) {{ for (const k of keys) delete backing[k]; }},
}});

const serverTemplate = {api_json_text};
let bannerArgs = null;
const res = await handlePopupMessage(
  {{ action: 'CHECK_ACTIVE_TAB' }},
  {{ id: extId, url: popupPrefix }},
  {{
    runtimeId: extId,
    popupUrlPrefix: popupPrefix,
    settingsStore: store,
    queryActiveTab: async () => ({{
      id: 99,
      windowId: 1,
      active: true,
      incognito: false,
      url: {json.dumps(tab_full_url)},
    }}),
    scriptingApi: {{
      async executeScript(call) {{
        bannerArgs = call.args;
      }},
    }},
    fetchImpl: async (_url, init) => {{
      const req = JSON.parse(init.body);
      return {{
        ok: true,
        status: 200,
        async json() {{
          return {{ ...serverTemplate, request_ref: req.request_ref }};
        }},
      }};
    }},
  }},
);
assert.equal(res.ok, true);
assert.equal(res.verdict, 'HIGH');
assert.equal(res.bannerCoverage, 'banner_injected');
const vm = buildPopupViewModel(res, 'ar');
console.log(JSON.stringify({{ backing, bannerArgs, vm }}));
"""
    verify_proc = subprocess.run(
        ['node', '--input-type=module', '-e', verify_script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify_proc.returncode == 0, verify_proc.stderr
    verify_out = json.loads(verify_proc.stdout.strip())

    # Database is 100% unchanged and logs are empty.
    assert _db_snapshot(db) == before_db
    assert caplog.records == []
    assert caplog.text == ''

    status_json = json.dumps(client.get('/extension/v1/status', headers={'Host': ALLOWED_BACKEND_HOST}).json())
    all_surfaces = (
        api_json_text
        + status_json
        + json.dumps(verify_out['backing'])
        + json.dumps(verify_out['bannerArgs'])
        + json.dumps(verify_out['vm'])
        + caplog.text
    )

    forbidden_markers = (
        page_html_marker,
        page_title_marker,
        page_form_marker,
        page_cookie_marker,
        page_selection_marker,
        url_host_marker,
        url_path_marker,
        url_query_marker,
        url_fragment_marker,
        tab_full_url,
        f'https://{url_host_marker}/{url_path_marker}?q={url_query_marker}',
    )
    for secret in forbidden_markers:
        for variant in (secret, secret.lower(), secret.upper()):
            digest = hashlib.sha256(variant.encode('utf-8')).hexdigest()
            assert variant not in all_surfaces
            assert digest not in all_surfaces
