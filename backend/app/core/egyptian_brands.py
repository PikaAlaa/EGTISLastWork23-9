"""
egyptian_brands.py

Single source of truth for the Egyptian brand domain registry. Used by:
- data/scripts/add_egyptian_domains.py (Phase 1 dataset construction)
- app/engines/rule_based/domain_typosquatting_detector.py (Phase 2 detection)
- the future threat-intel database brand table (Phase 3, CLAUDE.md architecture)

Domains verified via web search on 2026-07-15 unless noted otherwise --
see docs/dataset_schema.md and the Phase 1 conversation for verification notes.
October additions/rechecks and official sources: docs/brand-sources.md.
"""

# (brand name, domain) -- some brands have multiple active domains.
EGYPTIAN_BRAND_DOMAINS: list[tuple[str, str]] = [
    ("Commercial International Bank (CIB)", "cibeg.com"),
    ("National Bank of Egypt (NBE)", "nbe.com.eg"),
    ("Banque Misr", "banquemisr.com"),
    ("QNB Al Ahli", "qnbalahli.com"),
    ("QNB Al Ahli", "qnb.com.eg"),
    ("Arab African International Bank", "aaib.com"),
    ("Vodafone Egypt", "vodafone.com.eg"),
    ("Vodafone Group", "vodafone.com"),
    ("Amazon (global stores)", "amazon.com"),
    ("Amazon (global stores)", "amazon.de"),
    ("Amazon (global stores)", "amazon.co.jp"),
    ("Amazon (global stores)", "amazon.com.mx"),
    ("Amazon (global stores)", "amazon.co.za"),
    ("Amazon (global stores)", "amazon.se"),
    ("Orange Polska", "orange.pl"),
    ("Orange Egypt", "orange.eg"),
    ("Etisalat Misr (e&)", "etisalat.eg"),
    ("Etisalat Misr (e&)", "eand.com.eg"),
    ("Telecom Egypt (WE)", "te.eg"),
    ("Instapay", "instapay.eg"),
    ("Fawry", "fawry.com"),
    ("Jumia Egypt", "jumia.com.eg"),
    ("Noon Egypt", "noon.com"),
    ("Amazon Egypt", "amazon.eg"),
    ("Talabat Egypt", "talabat.com"),
    ("Breadfast", "breadfast.com"),
    ("EgyptAir", "egyptair.com"),
    ("Egypt e-Government portal", "digital.gov.eg"),
    ("Paymob", "paymob.com"),
    ("Paymob", "paymob.eg"),
    ("Vodafone Cash", "web.vodafone.com.eg"),
    ("ValU", "valu.com.eg"),
    ("ValU", "valugroup.com"),
    ("Bosta", "bosta.co"),
    ("Aramex Egypt", "aramex.com"),
    ("Egypt Post", "egyptpost.org"),
    ("Egyptian Tax Authority", "eta.gov.eg"),
]

EGYPTIAN_BRAND_DOMAIN_SET = {domain for _, domain in EGYPTIAN_BRAND_DOMAINS}

# Explicit service entry for Vodafone Cash uses its sourced service host; the
# existing Vodafone Egypt parent domain already covers it. No duplicate domain
# ownership is inserted into the database. InstaPay, Fawry and Digital Egypt
# were already present and are rechecked rather than duplicated.
OCTOBER_VERIFIED_DOMAINS = {
    'amazon.com', 'amazon.de', 'amazon.co.jp', 'amazon.com.mx', 'amazon.co.za', 'amazon.se', 'orange.pl',
    'vodafone.com',
    'paymob.com', 'paymob.eg', 'instapay.eg', 'web.vodafone.com.eg',
    'valu.com.eg', 'valugroup.com', 'fawry.com', 'bosta.co', 'aramex.com',
    'egyptpost.org', 'digital.gov.eg', 'eta.gov.eg',
}

BRAND_CATEGORIES = {
    'Amazon (global stores)': 'retail', 'Orange Polska': 'telecom',
    'Vodafone Group': 'telecom',
    'Commercial International Bank (CIB)': 'bank',
    'National Bank of Egypt (NBE)': 'bank', 'Banque Misr': 'bank',
    'QNB Al Ahli': 'bank', 'Arab African International Bank': 'bank',
    'Vodafone Egypt': 'telecom', 'Orange Egypt': 'telecom',
    'Etisalat Misr (e&)': 'telecom', 'Telecom Egypt (WE)': 'telecom',
    'Instapay': 'wallet', 'Fawry': 'wallet', 'Vodafone Cash': 'wallet',
    'Paymob': 'payments', 'ValU': 'finance',
    'Bosta': 'delivery', 'Aramex Egypt': 'delivery', 'Egypt Post': 'postal',
    'Egypt e-Government portal': 'government', 'Egyptian Tax Authority': 'government',
}
