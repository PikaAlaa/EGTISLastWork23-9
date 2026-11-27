/**
 * Locally bundled warning banner and safe top-level injection for ETIS browser extension v1
 * (design docs/design/browser-extension-v1.md §2 items 4, 5, 6, §6, §7, §8, §9 step 5).
 *
 * Shadow DOM encapsulation, chrome.scripting.executeScript documentIds targeting and
 * restricted-page rejection are marked "to verify" in Chrome and Edge (§10).
 *
 * Security & privacy invariants:
 * - Injected ONLY for HIGH and MEDIUM verdicts; never for LOW, INCOMPLETE or unavailable.
 * - Re-verifies tab/document identity immediately before injection; cancels on race.
 * - The injected function is self-contained, receives no pairing token or URL, never reads
 *   page text/attributes/forms/cookies, adds no external resources, and sends no messages.
 * - Closing the banner removes only its own DOM host element and persists no dismissal list.
 */
import { verifySameTabAndDocument } from './navigation_guard.mjs';

export const BANNER_ROOT_ID = 'etis-local-warning-banner-root';

export const REASON_LABELS = Object.freeze({
  ar: Object.freeze({
    blacklist_exact: 'الرابط مطابق لقائمة التصيّد المحلية',
    blacklist_domain: 'النطاق موجود في قائمة التصيّد المحلية',
    userinfo_brand: 'استخدام اسم علامة قبل @ في الرابط',
    homoglyph_confusable: 'أحرف متشابهة مضللة في اسم النطاق',
    domain_embedding: 'تضمين اسم علامة معروفة داخل نطاق مختلف',
    brand_label_reuse: 'إعادة استخدام اسم علامة معروفة في النطاق',
    brand_resemblance: 'تشابه مع اسم علامة معروفة',
    url_patterns: 'نمط رابط غير معتاد (عنوان IP أو منفذ غير قياسي أو Punycode)',
    url_model: 'مؤشر مرتفع من نموذج فحص الروابط المحلي',
    url_model_corroborated: 'مؤشر نموذج الروابط مؤيد بأدلة إضافية',
  }),
  en: Object.freeze({
    blacklist_exact: 'Exact match in local phishing feed',
    blacklist_domain: 'Domain present in local phishing feed',
    userinfo_brand: 'Brand name used in URL userinfo before @',
    homoglyph_confusable: 'Confusable lookalike characters in domain',
    domain_embedding: 'Known brand embedded inside a different domain',
    brand_label_reuse: 'Known brand label reused in domain',
    brand_resemblance: 'Resembles a known brand domain',
    url_patterns: 'Unusual URL structure (IP host, non-standard port or punycode)',
    url_model: 'Local lexical URL model indicator above threshold',
    url_model_corroborated: 'Local URL model corroborated by brand evidence',
  }),
});

export const BANNER_COPY = Object.freeze({
  ar: Object.freeze({
    dir: 'rtl',
    highTitle: 'تحذير أمني من نظام ETIS المحلي (HIGH)',
    highSummary: 'رصد الفحص المحلي مؤشرات تصيّد قوية على هذا الرابط. تجنّب إدخال كلمات المرور أو البيانات البنكية.',
    mediumTitle: 'تنبيه حذر من نظام ETIS المحلي (MEDIUM)',
    mediumSummary: 'رصد الفحص المحلي مؤشرات تستدعي الحذر على هذا الرابط.',
    trustedNote: 'ملاحظة: يمكن لصفحة الويب تعديل أو إخفاء لافتات الصفحة؛ راجع نافذة إضافة ETIS المنبثقة للتحقق من النتيجة الموثوقة.',
    closeLabel: 'إغلاق التنبيه',
  }),
  en: Object.freeze({
    dir: 'ltr',
    highTitle: 'ETIS Local Security Warning (HIGH)',
    highSummary: 'This local check detected strong phishing indicators on this link. Avoid entering passwords or payment details.',
    mediumTitle: 'ETIS Local Caution Notice (MEDIUM)',
    mediumSummary: 'This local check detected warning signs on this link.',
    trustedNote: 'Note: A webpage can modify or hide in-page DOM banners; open the ETIS extension popup to inspect the trusted result.',
    closeLabel: 'Dismiss notice',
  }),
});

/**
 * Build a sanitized, token-free, URL-free display payload for HIGH/MEDIUM warnings only.
 * Returns null for LOW, INCOMPLETE or invalid results so no banner is ever built for them.
 */
export function buildBannerPayload(result, language = 'ar') {
  if (!result || typeof result !== 'object') {
    return null;
  }
  if (result.verdict !== 'HIGH' && result.verdict !== 'MEDIUM') {
    return null;
  }
  const lang = BANNER_COPY[language] ? language : 'ar';
  const copy = BANNER_COPY[lang];
  const labelsMap = REASON_LABELS[lang];
  const rawCodes = [
    result.decisiveReason,
    ...(Array.isArray(result.supportingSignals) ? result.supportingSignals : []),
  ];
  const seen = new Set();
  const reasonLabels = [];
  for (const code of rawCodes) {
    if (typeof code === 'string' && !seen.has(code) && Object.hasOwn(labelsMap, code)) {
      seen.add(code);
      reasonLabels.push(labelsMap[code]);
    }
  }
  const isHigh = result.verdict === 'HIGH';
  return Object.freeze({
    rootId: BANNER_ROOT_ID,
    verdict: result.verdict,
    lang,
    dir: copy.dir,
    titleText: isHigh ? copy.highTitle : copy.mediumTitle,
    summaryText: isHigh ? copy.highSummary : copy.mediumSummary,
    trustedNoteText: copy.trustedNote,
    closeLabel: copy.closeLabel,
    reasonLabels: Object.freeze(reasonLabels),
  });
}

/**
 * Self-contained DOM injection function executed inside the target top-level document.
 * Must not reference outer module bindings. Never reads page text, forms, attributes or cookies.
 */
export function renderInjectedWarningBanner(payload, doc = globalThis.document) {
  if (!payload || (payload.verdict !== 'HIGH' && payload.verdict !== 'MEDIUM')) {
    return { rendered: false };
  }
  if (!doc || typeof doc.createElement !== 'function' || !doc.documentElement) {
    return { rendered: false };
  }
  const rootId = typeof payload.rootId === 'string' ? payload.rootId : 'etis-local-warning-banner-root';
  const existing = typeof doc.getElementById === 'function' ? doc.getElementById(rootId) : null;
  if (existing && typeof existing.remove === 'function') {
    existing.remove();
  }

  const host = doc.createElement('div');
  host.id = rootId;
  host.setAttribute('dir', payload.dir === 'ltr' ? 'ltr' : 'rtl');
  host.setAttribute('lang', payload.lang === 'en' ? 'en' : 'ar');

  const container = typeof host.attachShadow === 'function'
    ? host.attachShadow({ mode: 'closed' })
    : host;

  const style = doc.createElement('style');
  style.textContent = `
    .etis-banner {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      padding: 12px 16px;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 13px;
      line-height: 1.45;
      box-shadow: 0 2px 8px rgba(15, 23, 42, 0.25);
      border-bottom: 2px solid;
    }
    .etis-banner-HIGH {
      background: #fef2f2;
      color: #7f1d1d;
      border-color: #dc2626;
    }
    .etis-banner-MEDIUM {
      background: #fffbeb;
      color: #78350f;
      border-color: #d97706;
    }
    .etis-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      font-weight: 700;
    }
    .etis-close {
      cursor: pointer;
      border: 1px solid currentColor;
      background: transparent;
      color: inherit;
      border-radius: 4px;
      padding: 4px 10px;
      font-size: 12px;
      font-weight: 600;
    }
    .etis-reasons {
      margin: 6px 0;
      padding-inline-start: 20px;
    }
    .etis-note {
      font-size: 11px;
      opacity: 0.9;
      margin-top: 4px;
    }
  `;

  const wrapper = doc.createElement('section');
  wrapper.className = `etis-banner etis-banner-${payload.verdict}`;
  wrapper.setAttribute('role', 'alert');

  const header = doc.createElement('div');
  header.className = 'etis-header';

  const title = doc.createElement('strong');
  title.textContent = String(payload.titleText || '');

  const closeBtn = doc.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'etis-close';
  closeBtn.textContent = String(payload.closeLabel || 'Close');
  closeBtn.addEventListener('click', () => {
    if (typeof host.remove === 'function') {
      host.remove();
    }
  });

  header.appendChild(title);
  header.appendChild(closeBtn);
  wrapper.appendChild(header);

  const summary = doc.createElement('div');
  summary.textContent = String(payload.summaryText || '');
  wrapper.appendChild(summary);

  if (Array.isArray(payload.reasonLabels) && payload.reasonLabels.length > 0) {
    const ul = doc.createElement('ul');
    ul.className = 'etis-reasons';
    for (const label of payload.reasonLabels) {
      const li = doc.createElement('li');
      li.textContent = String(label);
      ul.appendChild(li);
    }
    wrapper.appendChild(ul);
  }

  const note = doc.createElement('div');
  note.className = 'etis-note';
  note.textContent = String(payload.trustedNoteText || '');
  wrapper.appendChild(note);

  container.appendChild(style);
  container.appendChild(wrapper);

  const mountTarget = doc.body || doc.documentElement;
  mountTarget.appendChild(host);
  return { rendered: true };
}

/**
 * Verify tab/document identity and inject the warning banner into top-level frame 0 only (§2 items 4, 5).
 * Degrades honestly to `banner_unavailable` when injection is denied (e.g. restricted page).
 */
export async function injectWarningBanner({
  scriptingApi,
  snapshot,
  currentTab,
  currentTopFrame = null,
  result,
  language = 'ar',
  nowMs = Date.now(),
} = {}) {
  const payload = buildBannerPayload(result, language);
  if (!payload) {
    return { injected: false, coverage: 'not_applicable' };
  }
  const guard = verifySameTabAndDocument(snapshot, currentTab, {
    currentTopFrame,
    nowMs,
  });
  if (!guard.same) {
    return {
      injected: false,
      coverage: 'stale_navigation_cancelled',
      reason: guard.reason,
    };
  }
  if (!scriptingApi || typeof scriptingApi.executeScript !== 'function') {
    return { injected: false, coverage: 'banner_unavailable' };
  }
  const target = snapshot.documentId
    ? { tabId: snapshot.tabId, frameIds: [0], documentIds: [snapshot.documentId] }
    : { tabId: snapshot.tabId, frameIds: [0] };
  try {
    await scriptingApi.executeScript({
      target,
      func: renderInjectedWarningBanner,
      args: [payload],
    });
    return { injected: true, coverage: 'banner_injected' };
  } catch {
    return { injected: false, coverage: 'banner_unavailable' };
  }
}
