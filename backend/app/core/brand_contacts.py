"""Egypt retail hotlines checked against the organizations' own pages on 2026-10-08.
No contact details are taken from submitted text or phishing URLs.
"""
BRAND_CONTACTS={
 'Commercial International Bank (CIB)':{'phone':'19666','source':'https://www.cibeg.com/ar/complaint-form'},
 'National Bank of Egypt (NBE)':{'phone':'19623','source':'https://www.nbe.com.eg/NBE/E/'},
 'Banque Misr':{'phone':'19888','source':'https://www.banquemisr.com/ar-EG/Home/CONTACT-US/Call-Center?sc_lang=en'},
 'QNB Al Ahli':{'phone':'19700','source':'https://www.qnb.com.eg/sites/qnb/qnbegypt/page/en/encontactus.html'},
}
def official_contact(brand):
    contact=BRAND_CONTACTS.get(brand)
    return {**contact,'verified_on':'2026-10-08','country':'EG'} if contact else None
