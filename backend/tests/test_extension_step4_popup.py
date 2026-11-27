"""Step 4 tests: Action/popup, local-only settings, egress allowlist and no page-content bridge.

Design: docs/design/browser-extension-v1.md (§1, §2, §2.1–2.4, §7, §9 step 4).
Executes Node.js unit checks directly against browser-extension/protocol.mjs and
browser-extension/background.js, plus static checks on popup.html/popup.js/manifest.json.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EXT_DIR = ROOT / 'browser-extension'


def test_static_manifest_popup_and_no_eval_or_page_bridge():
    manifest = json.loads((EXT_DIR / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['manifest_version'] == 3
    assert manifest['action']['default_popup'] == 'popup.html'
    assert manifest['background'] == {'service_worker': 'background.js', 'type': 'module'}
    assert 'content_scripts' not in manifest
    assert 'externally_connectable' not in manifest
    assert 'web_accessible_resources' not in manifest

    for filename in ('protocol.mjs', 'background.js', 'popup.js', 'popup.html', 'popup.css'):
        text = (EXT_DIR / filename).read_text(encoding='utf-8')
        assert 'eval(' not in text
        assert 'new Function' not in text
        assert 'chrome.storage.sync' not in text
        assert 'onMessageExternal' not in text
        assert 'navigator.clipboard' not in text
        assert 'https://fonts.googleapis.com' not in text


def test_node_protocol_storage_and_popup_message_bridge_isolation():
    script = """
import assert from 'node:assert/strict';
import {
  CHECK_ENDPOINT,
  LocalSettingsStore,
  PAIR_ENDPOINT,
  assertAllowedEndpoint,
  prepareTabUrlForCheck,
  sanitizeStorageWrite,
  sendLocalRequest,
  validateCheckResponse,
  validateExtensionId,
} from './browser-extension/protocol.mjs';
import { handlePopupMessage, isTrustedPopupSender } from './browser-extension/background.js';

// 1. Extension ID validation: exact 32 lowercase letters a-p.
assert.equal(validateExtensionId('a'.repeat(32)).ok, true);
assert.equal(validateExtensionId('p'.repeat(32)).ok, true);
assert.equal(validateExtensionId('q'.repeat(32)).ok, false);
assert.equal(validateExtensionId('A'.repeat(32)).ok, false);
assert.equal(validateExtensionId('a'.repeat(31)).ok, false);

// 2. Fragment stripping and forbidden scheme / credential rejection without decoding payloads.
const clean = prepareTabUrlForCheck('https://example.com/path?x=1#PrivateFragmentMarker');
assert.equal(clean.ok, true);
assert.equal(clean.cleanUrl, 'https://example.com/path?x=1');
assert.equal(clean.cleanUrl.includes('PrivateFragmentMarker'), false);

for (const bad of [
  'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
  'blob:https://example.com/123',
  'file:///C:/secret.txt',
  'chrome://extensions',
  'edge://settings',
  'https://user:pass@example.com/login',
  'https://@example.com/login',
]) {
  assert.equal(prepareTabUrlForCheck(bad).ok, false);
}

// 3. Runtime egress allowlist.
assert.equal(assertAllowedEndpoint(PAIR_ENDPOINT), PAIR_ENDPOINT);
assert.equal(assertAllowedEndpoint(CHECK_ENDPOINT), CHECK_ENDPOINT);
for (const forbiddenEndpoint of [
  'http://localhost:8000/extension/v1/check',
  'http://127.0.0.1:5173/extension/v1/check',
  'https://127.0.0.1:8000/extension/v1/check',
  'http://127.0.0.1:8000/analyze',
  'http://127.0.0.1:8000/extension/v1/check?url=https://example.com',
  'https://example.com/extension/v1/check',
]) {
  assert.throws(() => assertAllowedEndpoint(forbiddenEndpoint), /egress_blocked/);
}

// 4. Local-only storage guard rejects any URL, hash, tabId, result, or dismissal list.
for (const forbiddenPatch of [
  { url: 'https://example.com' },
  { urlHash: 'a'.repeat(64) },
  { tabId: 1 },
  { documentId: 'doc1' },
  { verdict: 'LOW' },
  { dismissedSites: ['example.com'] },
  { checkTimestamp: Date.now() },
]) {
  assert.throws(() => sanitizeStorageWrite(forbiddenPatch));
}

// Memory-backed fake chrome.storage.local that also starts with a rogue key to prove auto-scrubbing.
const backing = {
  rogueVisitedUrl: 'https://secret.example.com',
  language: 'ar',
};
const fakeArea = {
  async get() { return { ...backing }; },
  async set(patch) { Object.assign(backing, patch); },
  async remove(keys) {
    for (const k of (Array.isArray(keys) ? keys : [keys])) delete backing[k];
  },
};
const store = new LocalSettingsStore(fakeArea);
const initial = await store.readSettings();
assert.equal('rogueVisitedUrl' in backing, false);
assert.equal(initial.language, 'ar');
assert.equal(initial.pairingToken, null);

// 5. Reject messages from content scripts, web pages or other extensions (no page-content bridge).
const extId = 'a'.repeat(32);
const popupPrefix = `chrome-extension://${extId}/popup.html`;
assert.equal(isTrustedPopupSender({ id: extId, url: popupPrefix }, extId, popupPrefix), true);
assert.equal(isTrustedPopupSender({ id: extId, url: popupPrefix, tab: { id: 1 } }, extId, popupPrefix), false);
assert.equal(isTrustedPopupSender({ id: extId, url: 'https://example.com/' }, extId, popupPrefix), false);
assert.equal(isTrustedPopupSender({ id: 'b'.repeat(32), url: popupPrefix }, extId, popupPrefix), false);

const untrustedResp = await handlePopupMessage(
  { action: 'CHECK_ACTIVE_TAB' },
  { id: extId, url: 'https://example.com/', tab: { id: 1 } },
  { runtimeId: extId, popupUrlPrefix: popupPrefix, settingsStore: store },
);
assert.equal(untrustedResp.ok, false);
assert.equal(untrustedResp.error, 'untrusted_sender');

// 6. Verify sendLocalRequest sets credentials: 'omit', redirect: 'error', cache: 'no-store' and never persists URLs.
let capturedInit = null;
const pairRes = await handlePopupMessage(
  { action: 'PAIR', pairingSecret: 'invented_one_use_secret_000001' },
  { id: extId, url: popupPrefix },
  {
    runtimeId: extId,
    popupUrlPrefix: popupPrefix,
    settingsStore: store,
    fetchImpl: async (url, init) => {
      capturedInit = { url, init };
      const body = JSON.parse(init.body);
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            schema_version: 'extension-pair-v1',
            extension_token: 'invented_bearer_token_00000001',
            server_instance_id: 'srv_instance_invented_0001',
            extension_instance_id: body.extension_instance_id,
          };
        },
      };
    },
  },
);
assert.equal(pairRes.ok, true);
assert.equal(capturedInit.init.credentials, 'omit');
assert.equal(capturedInit.init.redirect, 'error');
assert.equal(capturedInit.init.cache, 'no-store');
assert.equal(capturedInit.init.referrerPolicy, 'no-referrer');

// 7. User-initiated CHECK_ACTIVE_TAB strips fragment, checks nonce, and leaves zero URLs in storage.
let sentCheckBody = null;
const checkRes = await handlePopupMessage(
  { action: 'CHECK_ACTIVE_TAB' },
  { id: extId, url: popupPrefix },
  {
    runtimeId: extId,
    popupUrlPrefix: popupPrefix,
    settingsStore: store,
    queryActiveTab: async () => ({
      id: 42,
      windowId: 1,
      active: true,
      incognito: false,
      url: 'https://example.com/invented-check?param=1#NeverSentFragment',
    }),
    fetchImpl: async (url, init) => {
      sentCheckBody = JSON.parse(init.body);
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            schema_version: 'extension-check-v1',
            request_ref: sentCheckBody.request_ref,
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
  },
);
assert.equal(checkRes.ok, true);
assert.equal(checkRes.verdict, 'LOW');
assert.equal(sentCheckBody.url, 'https://example.com/invented-check?param=1');
assert.equal(JSON.stringify(backing).includes('example.com'), false);
assert.equal(JSON.stringify(backing).includes('NeverSentFragment'), false);
assert.deepEqual(Object.keys(backing).sort(), ['extensionInstanceId', 'language', 'pairingToken', 'serverInstanceId']);
"""
    proc = subprocess.run(
        ['node', '--input-type=module', '-e', script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
