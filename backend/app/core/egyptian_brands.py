"""
egyptian_brands.py

Single source of truth for the Egyptian brand domain registry. Used by:
- data/scripts/add_egyptian_domains.py (Phase 1 dataset construction)
- app/engines/rule_based/domain_typosquatting_detector.py (Phase 2 detection)
- the future threat-intel database brand table (Phase 3, CLAUDE.md architecture)

Domains verified via web search on 2026-07-15 unless noted otherwise --
see docs/dataset_schema.md and the Phase 1 conversation for verification notes.
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
]

EGYPTIAN_BRAND_DOMAIN_SET = {domain for _, domain in EGYPTIAN_BRAND_DOMAINS}
