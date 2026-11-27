/**
 * Top-level tab and document navigation race guards for ETIS browser extension v1
 * (design docs/design/browser-extension-v1.md §2 items 1, 4, 6, §4, §8, §9 step 5).
 *
 * Chrome/Edge frameId/documentId behavior across navigations and reloads is marked
 * "to verify" against official Chrome/Edge scripting and webNavigation docs (§10).
 * Holds only ephemeral in-memory state for the single in-flight user check and
 * clears it immediately upon completion, cancellation, navigation or failure.
 */
import {
  REQUEST_TIMEOUT_MS,
  prepareTabUrlForCheck,
  validateIdentifier,
} from './protocol.mjs';

export function extractDocumentId(tab, topFrame = null) {
  if (topFrame && typeof topFrame.documentId === 'string' && topFrame.documentId.length > 0) {
    return topFrame.documentId;
  }
  if (tab && typeof tab.documentId === 'string' && tab.documentId.length > 0) {
    return tab.documentId;
  }
  return null;
}

/**
 * Capture top-level tab/document identity and validated fragment-stripped URL in memory (§2 item 1).
 */
export function captureTabSnapshot(
  tab,
  { topFrame = null, requestRef, nowMs = Date.now() } = {},
) {
  if (!tab || typeof tab !== 'object') {
    return { ok: false, error: 'input_invalid' };
  }
  if (tab.incognito === true) {
    return { ok: false, error: 'incognito_disabled' };
  }
  if (typeof tab.id !== 'number' || !Number.isInteger(tab.id) || tab.id < 0) {
    return { ok: false, error: 'input_invalid' };
  }
  if (tab.active === false) {
    return { ok: false, error: 'tab_not_active' };
  }
  if (!validateIdentifier(requestRef)) {
    return { ok: false, error: 'input_invalid' };
  }
  if (topFrame && typeof topFrame.frameId === 'number' && topFrame.frameId !== 0) {
    return { ok: false, error: 'not_top_level_frame' };
  }
  const urlCheck = prepareTabUrlForCheck(tab.url);
  if (!urlCheck.ok) {
    return { ok: false, error: urlCheck.error };
  }
  const documentId = extractDocumentId(tab, topFrame);
  return {
    ok: true,
    snapshot: Object.freeze({
      tabId: tab.id,
      windowId: typeof tab.windowId === 'number' ? tab.windowId : null,
      documentId,
      cleanUrl: urlCheck.cleanUrl,
      requestRef,
      capturedAtMs: Number(nowMs),
    }),
  };
}

/**
 * Before banner injection or result display, verify the active tab, top-level document
 * and captured URL are still identical and the request has not expired (§2 item 4).
 */
export function verifySameTabAndDocument(
  snapshot,
  currentTab,
  { currentTopFrame = null, nowMs = Date.now(), maxAgeMs = REQUEST_TIMEOUT_MS } = {},
) {
  if (!snapshot || typeof snapshot !== 'object' || !currentTab || typeof currentTab !== 'object') {
    return { same: false, reason: 'tab_closed_or_missing' };
  }
  if (currentTab.incognito === true) {
    return { same: false, reason: 'incognito_disabled' };
  }
  if (currentTab.active === false) {
    return { same: false, reason: 'tab_switched' };
  }
  if (currentTab.id !== snapshot.tabId) {
    return { same: false, reason: 'tab_switched' };
  }
  if (snapshot.windowId !== null && typeof currentTab.windowId === 'number' && currentTab.windowId !== snapshot.windowId) {
    return { same: false, reason: 'window_switched' };
  }
  const elapsed = Number(nowMs) - Number(snapshot.capturedAtMs);
  if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed > maxAgeMs) {
    return { same: false, reason: 'request_expired' };
  }
  if (currentTopFrame && typeof currentTopFrame.frameId === 'number' && currentTopFrame.frameId !== 0) {
    return { same: false, reason: 'not_top_level_frame' };
  }
  const currentUrlCheck = prepareTabUrlForCheck(currentTab.url);
  if (!currentUrlCheck.ok || currentUrlCheck.cleanUrl !== snapshot.cleanUrl) {
    return { same: false, reason: 'document_navigated' };
  }
  const currentDocId = extractDocumentId(currentTab, currentTopFrame);
  if (snapshot.documentId !== null || currentDocId !== null) {
    if (snapshot.documentId !== currentDocId) {
      return { same: false, reason: 'document_changed' };
    }
  }
  return { same: true, reason: null };
}

/**
 * Ephemeral single-slot pending check tracker (§2 items 4, 6).
 * Never persists state; clears pending snapshot on consumption, cancellation or replacement.
 */
export class PendingCheckTracker {
  constructor() {
    this._pending = null;
  }

  begin(snapshot) {
    this._pending = snapshot || null;
    return this._pending;
  }

  hasPending() {
    return this._pending !== null;
  }

  clear() {
    this._pending = null;
  }

  verifyAndConsume(requestRef, currentTab, options = {}) {
    const active = this._pending;
    this._pending = null;
    if (!active || active.requestRef !== requestRef) {
      return { same: false, reason: 'superseded_or_cancelled' };
    }
    return verifySameTabAndDocument(active, currentTab, options);
  }
}
