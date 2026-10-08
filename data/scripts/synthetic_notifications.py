"""Authored training-only examples, never presented as real SMS or evaluation evidence.

Templates describe routine events and explicit requests for secrets. They are independent
of the review's probe strings. Variants stay in the same template group during rebuilding.
"""
import pandas as pd

LEGITIMATE = [
 'إشعار مصرفي: عملية شراء بمبلغ {amount} تمت بنجاح. المرجع {ref}.',
 'ملخص حسابك الشهري جاهز للعرض داخل تطبيق البنك الرسمي.',
 'وصلت حوالة واردة بقيمة {amount} إلى حساب المستفيد المسجل.',
 'تمت إضافة عائد الوديعة إلى الرصيد. تفاصيل الحركة في كشف الحساب.',
 'بيان البطاقة لشهر أكتوبر متاح عبر القنوات المصرفية المعتادة.',
 'تم تنفيذ أمر الدفع الدوري المستحق اليوم دون الحاجة إلى أي إجراء.',
 'تم تسجيل إيداع نقدي عبر ماكينة الصراف الآلي، رقم العملية {ref}.',
 'العملية رقم {ref} بقيمة {amount} مرفوضة لعدم كفاية الرصيد.',
 'استلمنا طلب استخراج كشف حسابك وسوف يكون جاهزاً بالفرع.',
 'تنبيه أمني: موظفو المؤسسة لن يطلبوا منك إرسال كلمة المرور أو رمز الدخول.',
 'رمز الدخول المؤقت {ref}. لا ترسله لأحد ولا تكتبه خارج التطبيق الرسمي.',
 'للحفاظ على أمان محفظتك، لا تبعت رقمك السري ولا أكواد التحقق لأي متصل.',
 'لو حد طلب منك كود أو بيانات سرية، اقفل المكالمة واتصل بالرقم الرسمي.',
 'وصل لحسابك مبلغ {amount} من جهة العمل المسجلة. إشعار للعلم فقط.',
 'كشف العمليات يوضح سحب {amount} من الصراف الآلي، مرجع {ref}.',
 'تم حجز دورك لخدمة العملاء في الفرع. رقم الانتظار {ref}.',
 'بطاقتك الجديدة جاهزة للاستلام من فرع الإصدار ومعك إثبات الشخصية.',
 'تجديد البطاقة تم وفقاً لطلبك السابق. تابع حالة التسليم من التطبيق.',
 'تذكير بمراجعة مصروفاتك الشهرية داخل التطبيق، دون مشاركة بياناتك.',
 'اكتمل دفع رسوم الجامعة للطالب المسجل، رقم الإيصال {ref}.',
 'اشتراك خدمة الهاتف ساري حتى نهاية الشهر، المبلغ المسدد {amount}.',
 'وصل إيصال الدفع الإلكتروني رقم {ref}، شكراً لاستخدام الخدمة.',
 'تم استرداد ثمن مشترياتك بقيمة {amount} إلى وسيلة الدفع الأصلية.',
 'الطلب المسجل تم إلغاؤه بناء على اختيارك، ولا توجد رسوم إضافية.',
 'مواعيد عمل الفرع غداً من التاسعة صباحاً حتى الثانية ظهراً.',
 'حماية الحساب مسؤولية مشتركة. لا تشارك رمز التحقق حتى مع من يدعي أنه البنك.',
 'تم إغلاق بلاغك السابق بعد تنفيذ الحل المتفق عليه. رقم المتابعة {ref}.',
 'تم تحديث عنوانك من داخل التطبيق بناء على طلبك، رقم التأكيد {ref}.',
 'أنت الآن مشترك في الإشعارات المصرفية، ويمكن تعديلها من إعدادات التطبيق.',
 'رصيد البطاقة مسبقة الدفع بعد عملية السداد هو {amount} جنيه.',
 'Your monthly account statement is available in the official banking app.',
 'Security reminder: never send your password or verification code to anyone.',
 'A card purchase of {amount} was completed. Receipt reference {ref}.',
 'Your scheduled payment was processed. No action or reply is required.',
]
PHISHING = [
 'ابعت لنا رمز الدخول عشان نرفع الحظر عن حسابك.',
 'ارسل الرقم السري لمحفظتك في الرد لتجنب الغرامة.',
 'شارك رمز التحقق مع مندوب التفعيل هنا فوراً.',
 'اكتب كلمة سر حسابك البنكي في رد على هذه الرسالة.',
 'حساب المحفظة هيتمسح. ابعت رقمك السري دلوقتي.',
 'بطاقتك محجوزة. ارسل كود التفعيل ورقم البطاقة لنا.',
 'ارسل كود الدخول للموظف على المحادثة عشان حسابك يرجع.',
 'أرسل كلمة مرور البنك إلى مندوب الدعم عبر الرسائل.',
 'محتاجين رقم البطاقة ورمزها السري في الرد عشان نوقف الحظر.',
 'ابعت بيانات بطاقتك كاملة مع رمز التحقق لاستلام جائزة.',
 'Reply with your banking password now to remove the account block.',
 'Send the verification code to our agent in this chat to unlock your wallet.',
 'Your card is blocked. Share your card number and security code by reply.',
 'Avoid account deletion: message us your password immediately.',
]

def generate():
    rows=[]
    for label,templates in [('legitimate',LEGITIMATE),('phishing',PHISHING)]:
        for i,template in enumerate(templates):
            variants=5 if '{' in template else 1
            for n in range(variants):
                text=template.format(amount=120+75*n,ref=480000+100*i+n)
                rows.append(dict(text=text,label=label,source='synthetic_notifications_v2',
                    content_type='text',language='en' if template[0].isascii() else 'ar',date_collected='2026-10-08',
                    synthetic=True,synthetic_template=f'{label}-{i}'))
    return pd.DataFrame(rows)
