import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

const resources = {
  ar: { translation: {
    title: 'نظام استخبارات التهديدات المصري', subtitle: 'تحليل تصيد احتيالي قابل للتفسير ومصمم للسياق المصري',
    scan: 'الفحص', threats: 'التهديدات', stats: 'الإحصائيات', language: 'English',
    url: 'الرابط', text: 'نص الرسالة أو البريد', analyze: 'تحليل الآن', analyzing: 'جارٍ التحليل...',
    result: 'نتيجة التحليل', score: 'درجة الخطر', engines: 'تفاصيل محركات الكشف', notApplied: 'لم يُطبق',
    loadError: 'تعذر تحميل البيانات', emptyInput: 'أدخل رابطاً أو نصاً واحداً على الأقل',
    source: 'المصدر', domain: 'النطاق', brand: 'العلامة المستهدفة', lastSeen: 'آخر ظهور',
    blacklistTotal: 'إجمالي القائمة السوداء', scansTotal: 'عمليات الفحص', model: 'نموذج النص', available: 'متاح', unavailable: 'غير متاح',
    next: 'التالي', previous: 'السابق', page: 'الصفحة', noThreats: 'لا توجد سجلات',
    filter: 'تطبيق الفلاتر', clear: 'مسح', sourceFilter: 'فلترة حسب المصدر', domainFilter: 'بحث في النطاق',
    sourceBreakdown: 'التوزيع حسب المصدر', verdictBreakdown: 'نتائج الفحص', noData: 'لا توجد بيانات بعد',
  }},
  en: { translation: {
    title: 'Egyptian Threat Intelligence System', subtitle: 'Explainable phishing analysis designed for the Egyptian context',
    scan: 'Scan', threats: 'Threat feed', stats: 'Statistics', language: 'العربية',
    url: 'URL', text: 'Message or email text', analyze: 'Analyze now', analyzing: 'Analyzing…',
    result: 'Analysis result', score: 'Risk score', engines: 'Detection-engine details', notApplied: 'Not applied',
    loadError: 'Could not load data', emptyInput: 'Enter at least one URL or text value',
    source: 'Source', domain: 'Domain', brand: 'Target brand', lastSeen: 'Last seen',
    blacklistTotal: 'Blacklist entries', scansTotal: 'Scans', model: 'Text model', available: 'Available', unavailable: 'Unavailable',
    next: 'Next', previous: 'Previous', page: 'Page', noThreats: 'No records',
    filter: 'Apply filters', clear: 'Clear', sourceFilter: 'Filter by source', domainFilter: 'Search domain',
    sourceBreakdown: 'Entries by source', verdictBreakdown: 'Scan verdicts', noData: 'No data yet',
  }},
}

i18n.use(initReactI18next).init({ resources, lng: 'ar', fallbackLng: 'en', interpolation: { escapeValue: false } })
export default i18n
