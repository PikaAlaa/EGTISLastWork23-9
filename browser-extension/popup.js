/**
 * Trusted popup UI controller for ETIS browser extension v1
 * (design docs/design/browser-extension-v1.md §2, §2.2, §2.4, §6, §7, §9 steps 4 & 6).
 *
 * Retains only the currently displayed check result in memory while open, then clears
 * all state on close. Never reads clipboard programmatically, never reads page content,
 * never schedules background polling, and never persists URLs, hashes or verdicts.
 */
import { POPUP_I18N, buildPopupViewModel } from './i18n.mjs';

let currentLang = 'ar';
let currentTransientResult = null;

function clearTransientState() {
  currentTransientResult = null;
  const secretInput = document.getElementById('pair-secret-input');
  if (secretInput) secretInput.value = '';
  const resultPanel = document.getElementById('result-panel');
  if (resultPanel) resultPanel.hidden = true;
}

function applyLanguage(lang) {
  currentLang = POPUP_I18N[lang] ? lang : 'ar';
  const copy = POPUP_I18N[currentLang];
  document.documentElement.lang = currentLang;
  document.documentElement.dir = copy.dir;
  document.getElementById('app-title').textContent = copy.appTitle;
  document.getElementById('lang-toggle').textContent = copy.toggleBtn;
  document.getElementById('pair-notice').textContent = copy.pairNotice;
  document.getElementById('ext-id-label').textContent = copy.extIdLabel;
  document.getElementById('pair-secret-label').textContent = copy.pairSecretLabel;
  document.getElementById('pair-btn').textContent = copy.pairBtn;
  document.getElementById('check-btn').textContent = copy.checkBtn;
  document.getElementById('retry-btn').textContent = copy.retryBtn;
  document.getElementById('unpair-btn').textContent = copy.unpairBtn;
  document.getElementById('unavailable-heading').textContent = copy.unavailableHeading;
  document.getElementById('trusted-ui-note').textContent = copy.trustedNote;
  if (currentTransientResult) {
    renderTransientResult(currentTransientResult);
  }
}

function renderTransientResult(state) {
  currentTransientResult = state;
  const vm = buildPopupViewModel(state, currentLang);
  const panel = document.getElementById('result-panel');
  const badge = document.getElementById('verdict-badge');
  const summary = document.getElementById('verdict-summary');
  const list = document.getElementById('reasons-list');
  const unavailSection = document.getElementById('unavailable-section');
  const unavailList = document.getElementById('unavailable-list');
  const retryBtn = document.getElementById('retry-btn');
  const coverage = document.getElementById('coverage-note');

  panel.hidden = false;
  badge.className = `verdict-badge verdict-${vm.displayState}`;
  badge.textContent = vm.badgeText;
  summary.textContent = vm.summaryText;

  list.replaceChildren();
  for (const text of vm.detailItems) {
    const li = document.createElement('li');
    li.textContent = text;
    list.appendChild(li);
  }

  unavailList.replaceChildren();
  if (vm.unavailableItems.length > 0) {
    unavailSection.hidden = false;
    for (const text of vm.unavailableItems) {
      const li = document.createElement('li');
      li.textContent = text;
      unavailList.appendChild(li);
    }
  } else {
    unavailSection.hidden = true;
  }

  retryBtn.hidden = !vm.showRetry;

  if (vm.bannerUnavailableNote) {
    coverage.hidden = false;
    coverage.textContent = vm.bannerUnavailableNote;
  } else {
    coverage.hidden = true;
    coverage.textContent = '';
  }
}

async function refreshPopupState() {
  const extIdInput = document.getElementById('ext-id-display');
  if (extIdInput && globalThis.chrome?.runtime?.id) {
    extIdInput.value = globalThis.chrome.runtime.id;
  }
  const resp = await globalThis.chrome.runtime.sendMessage({ action: 'GET_STATE' });
  applyLanguage(resp?.language || 'ar');
  const paired = Boolean(resp?.paired);
  document.getElementById('unpaired-panel').hidden = paired;
  document.getElementById('paired-panel').hidden = !paired;
}

async function runUserTriggeredCheck() {
  const resp = await globalThis.chrome.runtime.sendMessage({ action: 'CHECK_ACTIVE_TAB' });
  renderTransientResult(resp || { ok: false, error: 'service_unavailable' });
  if (resp && (resp.error === 'pairing_required' || resp.error === 'pairing_invalid' || resp.error === 'server_instance_mismatch')) {
    await refreshPopupState();
  }
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    refreshPopupState().catch(() => {
      renderTransientResult({ ok: false, error: 'service_unavailable' });
    });

    document.getElementById('lang-toggle').addEventListener('click', async () => {
      const nextLang = currentLang === 'ar' ? 'en' : 'ar';
      await globalThis.chrome.runtime.sendMessage({ action: 'SET_LANGUAGE', language: nextLang });
      applyLanguage(nextLang);
    });

    document.getElementById('pair-btn').addEventListener('click', async () => {
      const secretInput = document.getElementById('pair-secret-input');
      const secret = (secretInput.value || '').trim();
      secretInput.value = '';
      if (!secret) {
        renderTransientResult({ ok: false, error: 'pairing_invalid' });
        return;
      }
      const resp = await globalThis.chrome.runtime.sendMessage({ action: 'PAIR', pairingSecret: secret });
      if (resp?.ok) {
        clearTransientState();
        await refreshPopupState();
      } else {
        renderTransientResult({ ok: false, error: resp?.error || 'pairing_invalid' });
      }
    });

    document.getElementById('check-btn').addEventListener('click', () => {
      void runUserTriggeredCheck();
    });

    document.getElementById('retry-btn').addEventListener('click', () => {
      void runUserTriggeredCheck();
    });

    document.getElementById('unpair-btn').addEventListener('click', async () => {
      await globalThis.chrome.runtime.sendMessage({ action: 'UNPAIR' });
      clearTransientState();
      await refreshPopupState();
    });
  });

  globalThis.addEventListener('pagehide', clearTransientState);
  globalThis.addEventListener('unload', clearTransientState);
}
