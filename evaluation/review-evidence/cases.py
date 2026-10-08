"""Exact, anonymised inputs for every API test case in the ETIS review evidence log.

All personal data is invented: phone numbers, card digits and names are placeholders.
The last field of each case lists the verdicts or HTTP statuses that count as a pass: what a
correct detector should return. These are proposed acceptance values for the team and supervisor to confirm.
"""

PHISH_TEXT = (
    "عميلنا العزيز، تم إيقاف بطاقتك مؤقتاً لأسباب أمنية. "
    "لإعادة التفعيل أدخل بيانات البطاقة ورمز التحقق خلال 24 ساعة على الرابط المرفق"
)
CIB_PHISH_TEXT = (
    "CIB: تم تعليق حسابك لأسباب أمنية. قم بتحديث بياناتك فوراً عبر الرابط "
    "لتجنب إغلاق الحساب نهائياً"
)
NEUTRAL_TEXT = "شوف اللينك ده"

# BLACKLISTED_URL is chosen at run time (first test-split phishing URL that is an
# exact blacklist hit and not on a shared-hosting platform) and written to results.

API_CASES = [
    # id, description, body, accept (set of verdicts, or HTTP codes as ints)
    ("D1a", "Userinfo trick: official host before @, real host after", {
        "url": "https://cibeg.com:443@evil.example/login", "text": PHISH_TEXT}, {"HIGH"}),
    ("D1b", "Same URL, no text", {"url": "https://cibeg.com:443@evil.example/login"}, {"HIGH"}),
    ("D2", "Official CIB URL with a phishing message", {
        "url": "https://www.cibeg.com/", "text": PHISH_TEXT}, {"HIGH"}),
    ("D4", "CIB impersonation message and look-alike link", {
        "url": "http://cib-egypt-secure.com/verify", "text": CIB_PHISH_TEXT}, {"HIGH"}),
    ("D5a", "Blacklisted URL inside the message, URL field empty", {
        "text": NEUTRAL_TEXT + ": {BLACKLISTED_URL}"}, {"HIGH"}),
    ("D5b", "Same blacklisted URL in the URL field (reference)", {"url": "{BLACKLISTED_URL}"}, {"HIGH"}),
    ("D6a", "Short-name look-alike: NBE", {"url": "http://nbe-online-login.com/"}, {"HIGH"}),
    ("D6b", "Short-name look-alike: CIB", {"url": "http://cib-eg.net/login"}, {"HIGH"}),
    ("D6c", "Short-name look-alike: QNB", {"url": "http://qnb-verify-account.com/"}, {"HIGH"}),
    ("D7", "Official CIB subdomain", {"url": "https://ebanking.cibeg.com/"}, {"LOW"}),
    ("D8a", "Unrelated word containing a brand label", {"url": "https://afternoon.com/"}, {"LOW"}),
    ("D8b", "Unrelated word containing a brand label", {"url": "https://elite.eg/"}, {"LOW"}),
    ("D9a", "Blacklisted URL with upper-case host", {"url": "{BLACKLISTED_URL_UPPER}"}, {"HIGH"}),
    ("D9b", "Blacklisted URL with a fragment", {"url": "{BLACKLISTED_URL}#x"}, {"HIGH"}),
    ("D9c", "Blacklisted URL with a tracking parameter", {"url": "{BLACKLISTED_URL}?utm_source=sms"}, {"HIGH"}),
    ("D10a", "Popular legitimate link", {"url": "https://www.google.com/"}, {"LOW"}),
    ("D10b", "WhatsApp click-to-chat link", {"url": "https://wa.me/201000000000"}, {"LOW"}),
    ("D10c", "Microsoft Forms link", {"url": "https://forms.office.com/r/AbC123xyz"}, {"LOW"}),
    ("D10d", "OneDrive short link", {"url": "https://1drv.ms/w/s!AbCdEf123"}, {"LOW"}),
    ("D12a", "javascript: scheme", {"url": "javascript:alert(1)"}, {400, 422}),
    ("D12b", "Invalid port", {"url": "http://example.com:99999/"}, {400, 422}),
    ("D13", "50,000-character URL", {"url": "https://example.com/" + "a" * 50000}, {400, 413, 422}),
    ("D14", "Plain word in the URL field", {"url": "hello"}, {400, 422}),
]

# E14: everyday Egyptian SMS (invented, realistic, all legitimate). Pass = LOW.
EVERYDAY_SMS = [
    "تم خصم 350.00 جنيه من بطاقتك المنتهية بـ 0000 لدى كارفور مصر بتاريخ 28/09",
    "كود التحقق الخاص بك هو 000000. لا تشارك هذا الكود مع أي شخص",
    "تم شحن رصيدك بمبلغ 50 جنيه. رصيدك الحالي 63.25 جنيه",
    "موعدك مع دكتور الأسنان يوم الخميس الساعة 7 مساءً. للإلغاء اتصل بالعيادة",
    "طلبك في الطريق، المندوب هيوصل خلال 20 دقيقة",
    "تم سداد فاتورة الكهرباء لشهر سبتمبر بقيمة 412 جنيه. شكراً لاستخدامك فوري",
    "تم إيداع راتب شهر سبتمبر في حسابك المنتهي بـ 0000. الرصيد المتاح 12,450 جنيه",
    "شحنتك رقم 0000 هتتسلم بكرة بين 9 الصبح و 5 المغرب",
    "تذكير: آخر موعد لسداد قسط المدرسة يوم 15 أكتوبر",
    "اجتماع أولياء الأمور يوم السبت الساعة 10 صباحاً في المدرسة",
    "تم تجديد باقة الإنترنت الخاصة بك بنجاح",
    "تم تفعيل خدمة الإنترنت البنكي بنجاح. لأي استفسار اتصل بخدمة العملاء",
]

# Model sensitivity pairs: same message type with and without money/account wording.
CONTROLLED_PAIRS = [
    ("Bank notice", "البنك الأهلي المصري: تم إضافة راتب شهر سبتمبر إلى حسابك",
     "البنك الأهلي المصري: تم تحديث تطبيق الهاتف إلى الإصدار الجديد"),
    ("Wallet notice", "تم تحويل 500 جنيه إلى محفظتك فودافون كاش. الرصيد الحالي 750 جنيه",
     "تم تحديث باقة فودافون الخاصة بك بنجاح. شكرا لك"),
    ("Clinic reminder", "تم إضافة 500 جنيه إلى حسابك. موعدك في العيادة غدا الساعة 5 مساء",
     "موعدك في العيادة غدا الساعة 5 مساء"),
    ("Delivery", "تم خصم 250 جنيه من حسابك مقابل شحنتك من جوميا",
     "شحنتك من جوميا في الطريق، سيتواصل معك المندوب اليوم"),
]

# Robustness cases (proposed acceptance cases; expected verdicts are proposals).
ROBUSTNESS = [
    ("long_legit", "Legitimate message longer than 200 tokens",
     " ".join(["الاجتماع الأسبوعي للفريق هيكون يوم الأحد الساعة 11 الصبح في قاعة الاجتماعات"] * 25), {"LOW"}),
    ("long_phish_tail", "Phishing request placed after 200 tokens of filler",
     " ".join(["أخبار الفريق والمشروع ماشية كويس والحمد لله"] * 40) + " " + PHISH_TEXT, {"HIGH"}),
    ("short_phish", "Very short phishing message", "حسابك اتقفل، ابعت الكود", {"HIGH"}),
    ("mixed_lang", "Mixed Arabic and English phishing", "Dear customer حسابك هيتقفل today، verify بياناتك now", {"HIGH"}),
    ("english_phish", "English phishing", "Your account has been suspended. Verify your card details within 24 hours to avoid closure.", {"HIGH"}),
    ("english_legit", "English legitimate", "Hi, the team meeting moved to 3 pm tomorrow. See you there.", {"LOW"}),
    ("multi_link", "Message with a clean link then a blacklisted link", "الجدول هنا https://www.google.com/ والدفع هنا {BLACKLISTED_URL}", {"HIGH"}),
]
