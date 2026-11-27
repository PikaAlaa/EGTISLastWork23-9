"""Step 5 tests: Locally bundled warning banner and tab/document navigation race guards.

Design: docs/design/browser-extension-v1.md (§2 items 1, 4, 5, 6, §4, §6, §7, §8, §9 step 5).
Executes Node.js unit checks directly against browser-extension/navigation_guard.mjs,
browser-extension/banner.mjs and browser-extension/background.js.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EXT_DIR = ROOT / 'browser-extension'


def test_static_banner_and_navigation_guard_isolation():
    for filename in ('navigation_guard.mjs', 'banner.mjs', 'background.js'):
        text = (EXT_DIR / filename).read_text(encoding='utf-8')
        assert 'eval(' not in text
        assert 'new Function' not in text
        assert 'innerHTML' not in text
        assert 'outerHTML' not in text
        assert 'document.cookie' not in text
        assert 'chrome.storage.sync' not in text
        assert 'localStorage' not in text
        assert 'sessionStorage' not in text


def test_node_navigation_race_guards_and_bundled_banner_injection():
    script = """
import assert from 'node:assert/strict';
import {
  PendingCheckTracker,
  captureTabSnapshot,
  verifySameTabAndDocument,
} from './browser-extension/navigation_guard.mjs';
import {
  BANNER_ROOT_ID,
  buildBannerPayload,
  injectWarningBanner,
  renderInjectedWarningBanner,
} from './browser-extension/banner.mjs';
import { LocalSettingsStore } from './browser-extension/protocol.mjs';
import { handlePopupMessage } from './browser-extension/background.js';

const NONCE = 'req_nonce_invented_0001';
const baseTab = {
  id: 10,
  windowId: 1,
  active: true,
  incognito: false,
  url: 'https://example.com/invented-page?x=1#frag',
};
const baseFrame = { frameId: 0, documentId: 'doc_invented_0001' };

// 1. Snapshot capture strips fragment and records tabId, windowId and documentId.
const captured = captureTabSnapshot(baseTab, {
  topFrame: baseFrame,
  requestRef: NONCE,
  nowMs: 1000,
});
assert.equal(captured.ok, true);
assert.equal(captured.snapshot.cleanUrl, 'https://example.com/invented-page?x=1');
assert.equal(captured.snapshot.documentId, 'doc_invented_0001');

// Incognito and non-top-level frames are refused.
assert.equal(captureTabSnapshot({ ...baseTab, incognito: true }, { requestRef: NONCE }).ok, false);
assert.equal(captureTabSnapshot(baseTab, { topFrame: { frameId: 2 }, requestRef: NONCE }).ok, false);

// 2. Race verification passes when tab, window, documentId, URL and timeout match.
assert.equal(
  verifySameTabAndDocument(captured.snapshot, baseTab, {
    currentTopFrame: baseFrame,
    nowMs: 1200,
  }).same,
  true,
);

// Race verification fails on: URL change, documentId change (same-URL reload), tab switch, tab inactive, window switch, timeout.
assert.equal(
  verifySameTabAndDocument(
    captured.snapshot,
    { ...baseTab, url: 'https://example.com/other-page' },
    { currentTopFrame: baseFrame, nowMs: 1200 },
  ).same,
  false,
);
assert.equal(
  verifySameTabAndDocument(
    captured.snapshot,
    baseTab,
    { currentTopFrame: { frameId: 0, documentId: 'doc_reloaded_0002' }, nowMs: 1200 },
  ).same,
  false,
);
assert.equal(
  verifySameTabAndDocument(
    captured.snapshot,
    { ...baseTab, id: 11 },
    { currentTopFrame: baseFrame, nowMs: 1200 },
  ).same,
  false,
);
assert.equal(
  verifySameTabAndDocument(
    captured.snapshot,
    { ...baseTab, active: false },
    { currentTopFrame: baseFrame, nowMs: 1200 },
  ).same,
  false,
);
assert.equal(
  verifySameTabAndDocument(
    captured.snapshot,
    baseTab,
    { currentTopFrame: baseFrame, nowMs: 10000 },
  ).same,
  false,
);

// 3. Banner payload is built ONLY for HIGH and MEDIUM, never for LOW or INCOMPLETE, and contains no token or URL.
assert.equal(buildBannerPayload({ verdict: 'LOW', decisiveReason: 'no_warning_signs' }, 'ar'), null);
assert.equal(buildBannerPayload({ verdict: 'INCOMPLETE', decisiveReason: 'database_unavailable' }, 'en'), null);

const highPayload = buildBannerPayload(
  {
    verdict: 'HIGH',
    decisiveReason: 'blacklist_exact',
    supportingSignals: ['blacklist_exact', 'url_patterns'],
    pairingToken: 'SECRET_TOKEN_MUST_NOT_APPEAR',
    url: 'https://secret-url.example.com/must-not-appear',
  },
  'ar',
);
assert.equal(highPayload.verdict, 'HIGH');
assert.equal(highPayload.dir, 'rtl');
assert.equal(highPayload.reasonLabels.length, 2);
const serializedPayload = JSON.stringify(highPayload);
assert.equal(serializedPayload.includes('SECRET_TOKEN_MUST_NOT_APPEAR'), false);
assert.equal(serializedPayload.includes('secret-url.example.com'), false);

// 4. DOM rendering uses closed Shadow DOM, never reads page content/title/forms/cookies, and removes itself on close.
function createFakeDoc() {
  const makeNode = (tag) => ({
    tagName: tag.toUpperCase(),
    id: '',
    className: '',
    type: '',
    textContent: '',
    attrs: {},
    children: [],
    listeners: {},
    shadowRootClosed: null,
    parent: null,
    setAttribute(k, v) { this.attrs[k] = v; },
    appendChild(child) { child.parent = this; this.children.push(child); return child; },
    addEventListener(evt, fn) { this.listeners[evt] = fn; },
    attachShadow(opts) {
      assert.equal(opts.mode, 'closed');
      this.shadowRootClosed = makeNode('shadow-root');
      return this.shadowRootClosed;
    },
    remove() {
      if (this.parent) {
        this.parent.children = this.parent.children.filter((c) => c !== this);
      }
    },
  });
  const body = makeNode('body');
  const html = makeNode('html');
  html.appendChild(body);
  // Plant traps on page properties that must NEVER be read by the injected banner.
  const doc = {
    documentElement: html,
    body,
    get title() { throw new Error('banner attempted to read document.title'); },
    get cookie() { throw new Error('banner attempted to read document.cookie'); },
    get forms() { throw new Error('banner attempted to read document.forms'); },
    createElement: (tag) => makeNode(tag),
    getElementById: (id) => body.children.find((c) => c.id === id) || null,
  };
  return doc;
}

const fakeDoc = createFakeDoc();
const renderOut = renderInjectedWarningBanner(highPayload, fakeDoc);
assert.equal(renderOut.rendered, true);
assert.equal(fakeDoc.body.children.length, 1);
const hostNode = fakeDoc.body.children[0];
assert.equal(hostNode.id, BANNER_ROOT_ID);
assert.notEqual(hostNode.shadowRootClosed, null);

// Clicking close button removes the host element without any storage write.
const sectionNode = hostNode.shadowRootClosed.children[1];
const headerNode = sectionNode.children[0];
const closeBtn = headerNode.children[1];
closeBtn.listeners.click();
assert.equal(fakeDoc.body.children.length, 0);

// 5. injectWarningBanner cancels on navigation race, skips LOW/INCOMPLETE, and degrades to banner_unavailable on error.
let executedCalls = [];
const fakeScripting = {
  async executeScript(call) {
    executedCalls.push(call);
  },
};

const lowInj = await injectWarningBanner({
  scriptingApi: fakeScripting,
  snapshot: captured.snapshot,
  currentTab: baseTab,
  currentTopFrame: baseFrame,
  result: { verdict: 'LOW', decisiveReason: 'no_warning_signs', supportingSignals: [] },
  nowMs: 1100,
});
assert.equal(lowInj.injected, false);
assert.equal(lowInj.coverage, 'not_applicable');
assert.equal(executedCalls.length, 0);

const raceInj = await injectWarningBanner({
  scriptingApi: fakeScripting,
  snapshot: captured.snapshot,
  currentTab: { ...baseTab, url: 'https://example.com/navigated-away' },
  currentTopFrame: baseFrame,
  result: { verdict: 'HIGH', decisiveReason: 'blacklist_exact', supportingSignals: [] },
  nowMs: 1100,
});
assert.equal(raceInj.injected, false);
assert.equal(raceInj.coverage, 'stale_navigation_cancelled');
assert.equal(executedCalls.length, 0);

const okInj = await injectWarningBanner({
  scriptingApi: fakeScripting,
  snapshot: captured.snapshot,
  currentTab: baseTab,
  currentTopFrame: baseFrame,
  result: { verdict: 'HIGH', decisiveReason: 'blacklist_exact', supportingSignals: [] },
  nowMs: 1100,
});
assert.equal(okInj.injected, true);
assert.equal(okInj.coverage, 'banner_injected');
assert.equal(executedCalls.length, 1);
assert.deepEqual(executedCalls[0].target, {
  tabId: 10,
  frameIds: [0],
  documentIds: ['doc_invented_0001'],
});

const restrictedInj = await injectWarningBanner({
  scriptingApi: {
    async executeScript() { throw new Error('Cannot access contents of page'); },
  },
  snapshot: captured.snapshot,
  currentTab: baseTab,
  currentTopFrame: baseFrame,
  result: { verdict: 'MEDIUM', decisiveReason: 'url_patterns', supportingSignals: [] },
  nowMs: 1100,
});
assert.equal(restrictedInj.injected, false);
assert.equal(restrictedInj.coverage, 'banner_unavailable');

// 6. End-to-end background CHECK_ACTIVE_TAB cancels stale navigation during in-flight fetch and clears tracker.
const extId = 'a'.repeat(32);
const popupPrefix = `chrome-extension://${extId}/popup.html`;
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
const tracker = new PendingCheckTracker();
let tabCalls = 0;
let scriptInjectedOnStale = false;

const staleRes = await handlePopupMessage(
  { action: 'CHECK_ACTIVE_TAB' },
  { id: extId, url: popupPrefix },
  {
    runtimeId: extId,
    popupUrlPrefix: popupPrefix,
    settingsStore: store,
    pendingTracker: tracker,
    nowFn: () => 2000,
    queryActiveTab: async () => {
      tabCalls += 1;
      return tabCalls === 1
        ? baseTab
        : { ...baseTab, url: 'https://example.com/user-navigated-during-fetch' };
    },
    queryTopFrame: async () => baseFrame,
    scriptingApi: {
      async executeScript() { scriptInjectedOnStale = true; },
    },
    fetchImpl: async (_url, init) => {
      const body = JSON.parse(init.body);
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            schema_version: 'extension-check-v1',
            request_ref: body.request_ref,
            server_instance_id: 'srv_instance_invented_0001',
            verdict: 'HIGH',
            decisive_reason: 'blacklist_exact',
            supporting_signals: ['blacklist_exact'],
            unavailable_components: [],
            policy_version: 'decision-v2',
            url_model_version: 'ee0ba9f0077c1fd140aa',
          };
        },
      };
    },
  },
);
assert.equal(staleRes.ok, false);
assert.equal(staleRes.error, 'stale_navigation_cancelled');
assert.equal(scriptInjectedOnStale, false);
assert.equal(tracker.hasPending(), false);
"""
    proc = subprocess.run(
        ['node', '--input-type=module', '-e', script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
