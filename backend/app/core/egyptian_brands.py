"""Canonical Egyptian institution registry shared by rules and database seeding."""

EGYPTIAN_BRAND_DOMAINS: tuple[tuple[str, str], ...] = (
    ("National Bank of Egypt (NBE)", "nbe.com.eg"),
    ("Banque Misr", "banquemisr.com"),
    ("Commercial International Bank (CIB)", "cibeg.com"),
    ("QNB Al Ahli", "qnbalahli.com"),
    ("Arab African International Bank", "aaib.com"),
    ("Bank of Alexandria", "alexbank.com"),
    ("Instapay", "instapay.eg"),
    ("Fawry", "fawry.com"),
    ("Vodafone Egypt", "vodafone.com.eg"),
    ("Orange Egypt", "orange.eg"),
    ("Etisalat Misr (e&)", "etisalat.eg"),
    ("Telecom Egypt (WE)", "te.eg"),
    ("EgyptAir", "egyptair.com"),
    ("Egypt e-Government portal", "digital.gov.eg"),
    ("Jumia Egypt", "jumia.com.eg"),
    ("Noon Egypt", "noon.com"),
    ("Amazon Egypt", "amazon.eg"),
    ("Talabat Egypt", "talabat.com"),
    ("Breadfast", "breadfast.com"),
)

VERIFIED_DOMAINS = frozenset(domain for _, domain in EGYPTIAN_BRAND_DOMAINS)
