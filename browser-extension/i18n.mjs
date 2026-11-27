/**
 * Bilingual (Arabic & English) UI strings, reason-code labels, unavailable-component
 * labels and error-state descriptions for ETIS browser extension v1
 * (design docs/design/browser-extension-v1.md §2.2, §2.4, §6, §7, §9 step 6).
 *
 * Pure static translations only: no dynamic URL interpolation, no remote strings.
 */

export const POPUP_I18N = Object.freeze({
  ar: Object.freeze({
    dir: 'rtl',
    appTitle: 'فحص الروابط المحلي — ETIS',
    toggleBtn: 'English',
    pairNotice: 'يُرسل رابط التبويب الحالي (دون الجزء #) محلياً فقط إلى 127.0.0.1:8000 لهذا الفحص الفوري ولا يُخزّن أو يُسجّل أبداً.',
    extIdLabel: 'معرّف الإضافة (32 حرفاً a–p):',
    pairSecretLabel: 'رمز الاقتران لمرة واحدة:',
    pairBtn: 'اقتران محلي',
    checkBtn: 'فحص التبويب الحالي',
    retryBtn: 'إعادة الفحص',
    unpairBtn: 'إلغاء الاقتران',
    trustedNote: 'هذه النافذة المنبثقة هي المكان الموثوق لعرض النتيجة؛ لافتات الصفحة قد تعدّلها الصفحة.',
    bannerUnavailable: 'تعذّر إظهار اللافتة داخل الصفحة (banner_unavailable)؛ النتيجة الكاملة معروضة هنا.',
    unavailableHeading: 'الفحوص أو المكونات غير المتاحة:',
    reasonsHeading: 'أكواد الأسباب المرصودة:',
    verdicts: Object.freeze({
      HIGH: 'تحذير مرتفع (HIGH) — مؤشرات تصيّد قوية على هذا الرابط',
      MEDIUM: 'تنبيه متوسط (MEDIUM) — مؤشرات تحتاج إلى الحذر',
      INCOMPLETE: 'فحص غير مكتمل (INCOMPLETE) — بعض مكونات الفحص المحلي غير متاحة',
      LOW: 'لم يُعثر على تحذير في هذا الفحص المحلي (LOW) — لا يُعدّ ضماناً للأمان',
      UNAVAILABLE: 'نظام ETIS غير متاح — لم يتم فحص هذه الصفحة بالكامل',
    }),
    reasons: Object.freeze({
      blacklist_exact: 'الرابط مطابق تماماً لقائمة التصيّد المحلية',
      blacklist_domain: 'النطاق موجود في قائمة التصيّد المحلية',
      userinfo_brand: 'استخدام اسم علامة معروفة قبل @ في الرابط',
      homoglyph_confusable: 'أحرف متشابهة مضللة (Homoglyphs) في اسم النطاق',
      domain_embedding: 'تضمين اسم علامة معروفة داخل نطاق مختلف',
      brand_label_reuse: 'إعادة استخدام اسم علامة معروفة في النطاق',
      brand_resemblance: 'تشابه مع اسم علامة معروفة',
      url_patterns: 'نمط رابط غير معتاد (عنوان IP أو منفذ غير قياسي أو Punycode)',
      url_model: 'مؤشر مرتفع من نموذج فحص الروابط المحلي',
      url_model_corroborated: 'مؤشر نموذج الروابط مؤيد بأدلة إضافية',
      no_warning_signs: 'لم تُرصد علامات تحذير معروفة في هذا الفحص المحلي',
      text_high_corroborated: 'نص مرتفع الخطورة مع أدلة مؤيدة',
      brand_claim_from_mobile_number: 'ادعاء علامة من رقم هاتف محمول',
      text_medium: 'مؤشر نصي متوسط',
      text_keywords: 'كلمات مفتاحية مرتبطة بالتصيّد',
      text_model_high_uncorroborated: 'مؤشر نموذج النص مرتفع دون قرينة إضافية',
    }),
    unavailableComponents: Object.freeze({
      database_unavailable: 'قاعدة البيانات المحلية غير متاحة (database_unavailable)',
      blacklist_empty: 'قائمة الحظر المحلية فارغة (blacklist_empty)',
      blacklist_missing_source: 'أحد مصادر قوائم الحظر المحلية غير مكتمل (blacklist_missing_source)',
      blacklist_stale: 'قائمة الحظر المحلية قديمة وتحتاج إلى تحديث (blacklist_stale)',
      url_model_unavailable: 'نموذج فحص الروابط المحلي غير متاح (url_model_unavailable)',
      text_model_unavailable: 'نموذج فحص النصوص المحلي غير متاح (text_model_unavailable)',
      links_truncated: 'تم اقتطاع الروابط الزائدة عن الحد (links_truncated)',
      invalid_url: 'صيغة الرابط غير صالحة للفحص (invalid_url)',
    }),
    errors: Object.freeze({
      service_unavailable: 'خدمة ETIS المحلية غير متاحة أو متوقفة على 127.0.0.1:8000.',
      pairing_required: 'يلزم إتمام الاقتران المحلي قبل فحص الروابط.',
      pairing_invalid: 'رمز الاقتران غير صالح أو منتهي الصلاحية أو تم إلغاؤه؛ أعد الاقتران.',
      input_invalid: 'هذا التبويب لا يحتوي على رابط HTTP/HTTPS صالح للفحص.',
      limit_exceeded: 'تم تجاوز حد الطول أو معدل الطلبات المحلي؛ حاول مرة أخرى.',
      protocol_mismatch: 'عدم توافق إصدار البروتوكول مع خادم ETIS المحلي.',
      nonce_mismatch: 'تم رفض الاستجابة لعدم تطابق رمز الطلب العشوائي (nonce_mismatch).',
      server_instance_mismatch: 'تغيّرت جلسة خادم ETIS المحلي (إعادة تشغيل)؛ يلزم إعادة الاقتران.',
      stale_navigation_cancelled: 'تم إلغاء النتيجة لأن التبويب أو المستند تغيّر أثناء الفحص.',
      incognito_disabled: 'فحص التصفح المتخفي معطّل في الإصدار الأول (v1).',
      tab_not_active: 'التبويب لم يعد نشطاً.',
      not_top_level_frame: 'الفحص مقتصر على المستند الرئيسي للتبويب فقط.',
      untrusted_sender: 'تم رفض طلب من مصدر غير موثوق.',
    }),
  }),
  en: Object.freeze({
    dir: 'ltr',
    appTitle: 'ETIS Local Link Check',
    toggleBtn: 'العربية',
    pairNotice: 'The current tab URL (without #fragment) is sent only to local ETIS on 127.0.0.1:8000 for this check and is never retained or logged.',
    extIdLabel: 'Extension ID (32 letters a–p):',
    pairSecretLabel: 'One-use pairing secret:',
    pairBtn: 'Pair with local ETIS',
    checkBtn: 'Check current tab',
    retryBtn: 'Retry check',
    unpairBtn: 'Unpair',
    trustedNote: 'This extension popup is the trusted place to inspect results; in-page DOM banners can be altered by the page.',
    bannerUnavailable: 'In-page banner injection unavailable (banner_unavailable); full result shown here.',
    unavailableHeading: 'Unavailable checks or components:',
    reasonsHeading: 'Observed reason codes:',
    verdicts: Object.freeze({
      HIGH: 'HIGH warning — strong phishing indicators on this link',
      MEDIUM: 'MEDIUM caution — warning signs detected on this link',
      INCOMPLETE: 'INCOMPLETE check — some local analysis components were unavailable',
      LOW: 'No warning found by this local check (LOW) — not a safety guarantee',
      UNAVAILABLE: 'ETIS unavailable — this page was not fully checked',
    }),
    reasons: Object.freeze({
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
      no_warning_signs: 'No known warning signs found by this local check',
      text_high_corroborated: 'High text score corroborated by supporting evidence',
      brand_claim_from_mobile_number: 'Brand claim sent from a mobile number',
      text_medium: 'Medium text indicator',
      text_keywords: 'Phishing-related keyword match',
      text_model_high_uncorroborated: 'High text model score without corroboration',
    }),
    unavailableComponents: Object.freeze({
      database_unavailable: 'Local database unavailable (database_unavailable)',
      blacklist_empty: 'Local blacklist is empty (blacklist_empty)',
      blacklist_missing_source: 'A required local feed source is missing (blacklist_missing_source)',
      blacklist_stale: 'Local blacklist feed is stale (blacklist_stale)',
      url_model_unavailable: 'Local URL lexical model unavailable (url_model_unavailable)',
      text_model_unavailable: 'Local text model unavailable (text_model_unavailable)',
      links_truncated: 'Additional links were truncated (links_truncated)',
      invalid_url: 'URL format is invalid for analysis (invalid_url)',
    }),
    errors: Object.freeze({
      service_unavailable: 'Local ETIS service is stopped or unreachable on 127.0.0.1:8000.',
      pairing_required: 'Local pairing is required before checking links.',
      pairing_invalid: 'Pairing token or secret is invalid, expired or revoked; please re-pair.',
      input_invalid: 'Current tab does not have a checkable HTTP/HTTPS URL.',
      limit_exceeded: 'Local size or rate limit exceeded; please try again.',
      protocol_mismatch: 'Protocol version mismatch with local ETIS server.',
      nonce_mismatch: 'Response rejected due to request nonce mismatch (nonce_mismatch).',
      server_instance_mismatch: 'Local ETIS server instance restarted; please pair again.',
      stale_navigation_cancelled: 'Result discarded because the tab or document changed during the check.',
      incognito_disabled: 'Incognito checking is disabled in v1.',
      tab_not_active: 'Target tab is no longer active.',
      not_top_level_frame: 'Checks apply only to the top-level document.',
      untrusted_sender: 'Rejected request from untrusted sender.',
    }),
  }),
});

/**
 * Derive a pure, presentation-ready popup view model from a check response or failure (§2.2, §2.4, §6).
 * Guarantees that any failed or unreachable check is rendered as UNAVAILABLE (never LOW)
 * and offers a user-triggered retry control.
 */
export function buildPopupViewModel(state, language = 'ar') {
  const lang = POPUP_I18N[language] ? language : 'ar';
  const copy = POPUP_I18N[lang];

  if (!state || state.ok !== true || !copy.verdicts[state.verdict]) {
    const errorCode = (state && typeof state.error === 'string' && state.error) || 'service_unavailable';
    const errorText = copy.errors[errorCode] || copy.errors.service_unavailable;
    const requiresRepair = (
      errorCode === 'pairing_required' ||
      errorCode === 'pairing_invalid' ||
      errorCode === 'server_instance_mismatch'
    );
    return Object.freeze({
      language: lang,
      dir: copy.dir,
      displayState: 'UNAVAILABLE',
      badgeText: 'UNAVAILABLE',
      summaryText: copy.verdicts.UNAVAILABLE,
      detailItems: Object.freeze([errorText]),
      unavailableItems: Object.freeze([]),
      showRetry: !requiresRepair,
      requiresRepair,
      bannerUnavailableNote: null,
      trustedNote: copy.trustedNote,
    });
  }

  const verdict = state.verdict;
  const rawReasons = [
    state.decisiveReason,
    ...(Array.isArray(state.supportingSignals) ? state.supportingSignals : []),
  ].filter((code) => typeof code === 'string' && code.length > 0);
  const uniqueReasons = [...new Set(rawReasons)];
  const detailItems = uniqueReasons
    .filter((code) => !Object.hasOwn(copy.unavailableComponents, code))
    .map((code) => copy.reasons[code] || code);

  const rawUnavailable = Array.isArray(state.unavailableComponents) ? state.unavailableComponents : [];
  const uniqueUnavailable = [...new Set(rawUnavailable.filter((c) => typeof c === 'string' && c.length > 0))];
  const unavailableItems = uniqueUnavailable.map((code) => copy.unavailableComponents[code] || code);

  return Object.freeze({
    language: lang,
    dir: copy.dir,
    displayState: verdict,
    badgeText: verdict,
    summaryText: copy.verdicts[verdict],
    detailItems: Object.freeze(detailItems),
    unavailableItems: Object.freeze(unavailableItems),
    showRetry: verdict === 'INCOMPLETE',
    requiresRepair: false,
    bannerUnavailableNote: state.bannerCoverage === 'banner_unavailable' ? copy.bannerUnavailable : null,
    trustedNote: copy.trustedNote,
  });
}
