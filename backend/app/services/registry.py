"""Populate the supplied registry without re-importing archival blacklist snapshots."""
from datetime import date
from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS, BRAND_CATEGORIES, OCTOBER_VERIFIED_DOMAINS
from app.models import EgyptianBrand,BrandDomain
def populate_registry(db):
    for name,domain in EGYPTIAN_BRAND_DOMAINS:
        brand=db.query(EgyptianBrand).filter_by(brand_name=name).first()
        if not brand:
            brand=EgyptianBrand(brand_name=name,category=BRAND_CATEGORIES.get(name,'Registry baseline (July 2026)'));db.add(brand);db.flush()
        elif name in BRAND_CATEGORIES:
            brand.category=BRAND_CATEGORIES[name]
        entry=db.query(BrandDomain).filter_by(domain=domain).first()
        verified=date(2026,10,17) if domain in OCTOBER_VERIFIED_DOMAINS else date(2026,7,15)
        if not entry:
            db.add(BrandDomain(brand_id=brand.id,domain=domain,verified_date=verified))
        elif domain in OCTOBER_VERIFIED_DOMAINS:
            entry.verified_date=verified
    db.commit()
