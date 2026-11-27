/**
 * Trusted popup UI controller for ETIS browser extension v1 (design §2, §6, §7, §9 step 4).
 *
 * Retains only the currently displayed check result in memory while open, then clears
 * all state on close. Never reads clipboard programmatically, never reads page content,
 * and never persists URLs, hashes or verdicts.
 */

const UI_TEXT = Object.freeze({
  ar: {
    dir: 'rtl',
    appTitle: 'فحص الروابط المحلي — ETIS',
    toggleBtn: 'English',
    pairNotice: 'يُرسل رابط التبويب الحالي (دون الجزء #) محلياً فقط إلى 127.0.0.1:8000 لهذا الفحص الفوري ولا يُخزّن أو يُسجّل أبداً.',
    extIdLabel: 'معرّف الإضافة (32 حرفاً a–p):',
    pairSecretLabel: 'رمز الاقتران لمرة واحدة:',
    pairBtn: 'اقتران محلي',
    checkBtn: 'فحص التبويب الحالي',
    unpairBtn: 'إلغاء الاقتران',
    trustedNote: 'هذه النافذة المنبثقة هي المكان الموثوق لعرض النتيجة؛ لافتات الصفحة قد تعدّلها الصفحة.',
    bannerUnavailable: 'تعذّر إظهار اللافتة داخل الصفحة (banner_unavailable)؛ النتيجة معروضة هنا.',
    verdicts: {
      HIGH: 'تحذير مرتفع (HIGH) — مؤشرات تصيّد قوية على هذا الرابط',
      MEDIUM: 'تنبيه متوسط (MEDIUM) — مؤشرات تحتاج إلى الحذر',
      INCOMPLETE: 'فحص غير مكتمل (INCOMPLETE) — بعض الفحوص غير متاحة',
      LOW: 'لم يُعثر على تحذير في هذا الفحص المحلي (LOW) — لا يُعدّ ضماناً للأمان',
      UNAVAILABLE: 'نظام ETIS غير متاح — لم يتم فحص هذه الصفحة بالكامل',
    },
  },
  en: {
    dir: 'ltr',
    appTitle: 'ETIS Local Link Check',
    toggleBtn: 'العربية',
    pairNotice: 'The current tab URL (without #fragment) is sent only to local ETIS on 127.0.0.1:8000 for this check and is never retained or logged.',
    extIdLabel: 'Extension ID (32 letters a–p):',
    pairSecretLabel: 'One-use pairing secret:',
    pairBtn: 'Pair with local ETIS',
    checkBtn: 'Check current tab',
    unpairBtn: 'Unpair',
    trustedNote: 'This extension popup is the trusted place to inspect results; in-page DOM banners can be altered by the page.',
    bannerUnavailable: 'In-page banner injection unavailable (banner_unavailable); full result shown here.',
    verdicts: {
      HIGH: 'HIGH warning — strong phishing indicators on this link',
      MEDIUM: 'MEDIUM caution — warning signs detected on this link',
      INCOMPLETE: 'INCOMPLETE check — some local analysis components were unavailable',
      LOW: 'No warning found by this local check (LOW) — not a safety guarantee',
      UNAVAILABLE: 'ETIS unavailable — this page was not fully checked',
    },
  },
});

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
  currentLang = UI_TEXT[lang] ? lang : 'ar';
  const copy = UI_TEXT[currentLang];
  document.documentElement.lang = currentLang;
  document.documentElement.dir = copy.dir;
  document.getElementById('app-title').textContent = copy.appTitle;
  document.getElementById('lang-toggle').textContent = copy.toggleBtn;
  document.getElementById('pair-notice').textContent = copy.pairNotice;
  document.getElementById('ext-id-label').textContent = copy.extIdLabel;
  document.getElementById('pair-secret-label').textContent = copy.pairSecretLabel;
  document.getElementById('pair-btn').textContent = copy.pairBtn;
  document.getElementById('check-btn').textContent = copy.checkBtn;
  document.getElementById('unpair-btn').textContent = copy.unpairBtn;
  document.getElementById('trusted-ui-note').textContent = copy.trustedNote;
  if (currentTransientResult) {
    renderTransientResult(currentTransientResult);
  }
}

function renderTransientResult(state) {
  currentTransientResult = state;
  const copy = UI_TEXT[currentLang];
  const panel = document.getElementById('result-panel');
  const badge = document.getElementById('verdict-badge');
  const summary = document.getElementById('verdict-summary');
  const list = document.getElementById('reasons-list');
  const coverage = document.getElementById('coverage-note');

  panel.hidden = false;
  const kind = state.ok && copy.verdicts[state.verdict] ? state.verdict : 'UNAVAILABLE';
  badge.className = `verdict-badge verdict-${kind}`;
  badge.textContent = kind;
  summary.textContent = copy.verdicts[kind];

  list.replaceChildren();
  const codes = state.ok
    ? [...new Set([state.decisiveReason, ...(state.supportingSignals || []), ...(state.unavailableComponents || [])])].filter(Boolean)
    : [state.error || 'service_unavailable'];
  for (const code of codes) {
    const li = document.createElement('li');
    li.textContent = code;
    list.appendChild(li);
  }

  if (state.bannerCoverage === 'banner_unavailable') {
    coverage.hidden = false;
    coverage.textContent = copy.bannerUnavailable;
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

  document.getElementById('check-btn').addEventListener('click', async () => {
    const resp = await globalThis.chrome.runtime.sendMessage({ action: 'CHECK_ACTIVE_TAB' });
    renderTransientResult(resp || { ok: false, error: 'service_unavailable' });
  });

  document.getElementById('unpair-btn').addEventListener('click', async () => {
    await globalThis.chrome.runtime.sendMessage({ action: 'UNPAIR' });
    clearTransientState();
    await refreshPopupState();
  });
});

globalThis.addEventListener('pagehide', clearTransientState);
globalThis.addEventListener('unload', clearTransientState);
