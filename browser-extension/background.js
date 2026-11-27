/**
 * Manifest V3 background service worker for ETIS local link check
 * (design docs/design/browser-extension-v1.md §1, §2, §6, §7, §9 steps 4–5).
 *
 * Exposes NO externally_connectable listener and NO content-script analysis bridge.
 * Accepts commands strictly from the extension's own popup.html page, enforces
 * top-level tab/document navigation race guards before rendering or injecting a
 * warning banner, and clears all pending in-memory state after completion or failure.
 */
import {
  CHECK_ENDPOINT,
  CHECK_SCHEMA_VERSION,
  LocalSettingsStore,
  PAIR_ENDPOINT,
  PAIR_SCHEMA_VERSION,
  sendLocalRequest,
  validateCheckResponse,
  validateExtensionId,
  validatePairResponse,
} from './protocol.mjs';
import {
  PendingCheckTracker,
  captureTabSnapshot,
} from './navigation_guard.mjs';
import { injectWarningBanner } from './banner.mjs';

const defaultTracker = new PendingCheckTracker();

function randomTokenHex(byteCount = 16) {
  const bytes = new Uint8Array(byteCount);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function isTrustedPopupSender(sender, runtimeId, popupUrlPrefix) {
  if (!sender || typeof runtimeId !== 'string' || !runtimeId) {
    return false;
  }
  if (sender.id !== runtimeId) {
    return false;
  }
  if (sender.tab) {
    // Reject any message originating from a content script or webpage tab.
    return false;
  }
  if (typeof sender.url !== 'string' || !sender.url.startsWith(popupUrlPrefix)) {
    return false;
  }
  return true;
}

export async function handlePopupMessage(message, sender, env) {
  const {
    runtimeId,
    popupUrlPrefix,
    settingsStore,
    queryActiveTab,
    queryTopFrame = async () => null,
    scriptingApi = null,
    fetchImpl,
    pendingTracker = defaultTracker,
    nowFn = () => Date.now(),
  } = env;

  if (!isTrustedPopupSender(sender, runtimeId, popupUrlPrefix)) {
    return { ok: false, error: 'untrusted_sender' };
  }
  if (!message || typeof message.action !== 'string') {
    return { ok: false, error: 'input_invalid' };
  }

  const settings = await settingsStore.readSettings();

  if (message.action === 'GET_STATE') {
    return {
      ok: true,
      paired: Boolean(settings.pairingToken && settings.serverInstanceId),
      language: settings.language,
    };
  }

  if (message.action === 'SET_LANGUAGE') {
    try {
      await settingsStore.writeSettings({ language: message.language });
      return { ok: true, language: message.language };
    } catch {
      return { ok: false, error: 'input_invalid' };
    }
  }

  if (message.action === 'UNPAIR') {
    pendingTracker.clear();
    await settingsStore.clearPairing();
    return { ok: true, paired: false };
  }

  if (message.action === 'PAIR') {
    const idCheck = validateExtensionId(runtimeId);
    if (!idCheck.ok) {
      return { ok: false, error: 'pairing_invalid' };
    }
    const secret = typeof message.pairingSecret === 'string' ? message.pairingSecret.trim() : '';
    if (secret.length < 16 || secret.length > 128) {
      return { ok: false, error: 'pairing_invalid' };
    }
    const instanceId = settings.extensionInstanceId || `ext_${randomTokenHex(16)}`;
    const netResp = await sendLocalRequest(
      PAIR_ENDPOINT,
      {
        schema_version: PAIR_SCHEMA_VERSION,
        pairing_secret: secret,
        extension_instance_id: instanceId,
      },
      { fetchImpl },
    );
    if (!netResp.ok) {
      return { ok: false, error: netResp.error || 'pairing_invalid' };
    }
    const parsed = validatePairResponse(netResp.payload, instanceId);
    if (!parsed.ok) {
      return { ok: false, error: parsed.error };
    }
    await settingsStore.writeSettings({
      pairingToken: parsed.extensionToken,
      serverInstanceId: parsed.serverInstanceId,
      extensionInstanceId: parsed.extensionInstanceId,
    });
    return { ok: true, paired: true };
  }

  if (message.action === 'CHECK_ACTIVE_TAB') {
    if (!settings.pairingToken || !settings.serverInstanceId) {
      return { ok: false, error: 'pairing_required' };
    }
    const initialTab = await queryActiveTab();
    const initialTopFrame = initialTab ? await queryTopFrame(initialTab.id) : null;
    const nonce = `req_${randomTokenHex(16)}`;
    const snapRes = captureTabSnapshot(initialTab, {
      topFrame: initialTopFrame,
      requestRef: nonce,
      nowMs: nowFn(),
    });
    if (!snapRes.ok) {
      pendingTracker.clear();
      return { ok: false, error: snapRes.error };
    }
    const snapshot = pendingTracker.begin(snapRes.snapshot);

    try {
      const netResp = await sendLocalRequest(
        CHECK_ENDPOINT,
        {
          schema_version: CHECK_SCHEMA_VERSION,
          url: snapshot.cleanUrl,
          request_ref: nonce,
        },
        { token: settings.pairingToken, fetchImpl },
      );
      if (!netResp.ok) {
        if (netResp.error === 'pairing_invalid' || netResp.error === 'pairing_required') {
          await settingsStore.clearPairing();
        }
        return { ok: false, error: netResp.error || 'service_unavailable' };
      }

      const validated = validateCheckResponse(netResp.payload, nonce, settings.serverInstanceId);
      if (!validated.ok) {
        if (validated.error === 'server_instance_mismatch') {
          await settingsStore.clearPairing();
        }
        return { ok: false, error: validated.error };
      }

      // §2 item 4: Before injection or displaying result, verify active tab/document and URL are still the same.
      const currentTab = await queryActiveTab();
      const currentTopFrame = currentTab ? await queryTopFrame(currentTab.id) : null;
      const checkTimeMs = nowFn();
      const raceCheck = pendingTracker.verifyAndConsume(nonce, currentTab, {
        currentTopFrame,
        nowMs: checkTimeMs,
      });
      if (!raceCheck.same) {
        // Discard stale response; no automatic recheck of the new page.
        return {
          ok: false,
          error: 'stale_navigation_cancelled',
          reason: raceCheck.reason,
        };
      }

      let bannerCoverage = 'not_applicable';
      if (validated.result.verdict === 'HIGH' || validated.result.verdict === 'MEDIUM') {
        const injection = await injectWarningBanner({
          scriptingApi,
          snapshot,
          currentTab,
          currentTopFrame,
          result: validated.result,
          language: settings.language,
          nowMs: checkTimeMs,
        });
        bannerCoverage = injection.coverage;
      }

      return {
        ok: true,
        ...validated.result,
        bannerCoverage,
      };
    } finally {
      pendingTracker.clear();
    }
  }

  return { ok: false, error: 'input_invalid' };
}

if (globalThis.chrome?.runtime?.onMessage && globalThis.chrome?.storage?.local) {
  const store = new LocalSettingsStore(globalThis.chrome.storage.local);
  globalThis.chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const runtimeId = globalThis.chrome.runtime.id;
    const popupUrlPrefix = globalThis.chrome.runtime.getURL('popup.html');
    const queryActiveTab = async () => {
      const tabs = await globalThis.chrome.tabs.query({ active: true, currentWindow: true });
      return tabs && tabs[0] ? tabs[0] : null;
    };
    handlePopupMessage(message, sender, {
      runtimeId,
      popupUrlPrefix,
      settingsStore: store,
      queryActiveTab,
      scriptingApi: globalThis.chrome.scripting || null,
      fetchImpl: globalThis.fetch.bind(globalThis),
    })
      .then((res) => sendResponse(res))
      .catch(() => sendResponse({ ok: false, error: 'service_unavailable' }));
    return true;
  });
}
