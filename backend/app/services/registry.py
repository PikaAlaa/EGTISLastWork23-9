"""Populate the supplied registry without re-importing archival blacklist snapshots."""
from datetime import date
from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS
from app.models import EgyptianBrand,BrandDomain
def populate_registry(db):
    for name,domain in EGYPTIAN_BRAND_DOMAINS:
        brand=db.query(EgyptianBrand).filter_by(brand_name=name).first()
        if not brand:
            brand=EgyptianBrand(brand_name=name,category='Registry baseline (July 2026)');db.add(brand);db.flush()
        if not db.query(BrandDomain).filter_by(domain=domain).first():
            db.add(BrandDomain(brand_id=brand.id,domain=domain,verified_date=date(2026,7,15)))
    db.commit()
