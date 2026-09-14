"""
seed_database.py

Seeds the ETIS database from Phase 1 data:
  1. blacklist_entries  <- data/processed/dataset.csv (PhishTank + OpenPhish rows)
  2. egyptian_brands + brand_domains  <- app/core/egyptian_brands.py (canonical registry)

Also logs a FeedUpdate row summarizing the run.

Run this once for the initial seed. Re-running is safe -- existing URLs are
skipped (not duplicated) thanks to the unique constraint on blacklist_entries.url,
and brands/domains are only inserted if not already present.

Usage:
    python seed_database.py
"""

import csv
import hashlib
import sys
from datetime import datetime
from pathlib import Path

# Make the backend/ "app" package importable when running this script directly.
BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS
from app.engines.rule_based.domain_typosquatting_detector import normalize_domain
from app.models import BlacklistEntry, BrandDomain, EgyptianBrand, FeedUpdate

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "dataset.csv"

BATCH_SIZE = 2000


def _hash_url(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def seed_blacklist_entries(db) -> tuple[int, int]:
    """Load PhishTank/OpenPhish rows from dataset.csv into blacklist_entries.
    Returns (rows_added, rows_skipped_as_duplicate)."""

    existing_hashes = {row[0] for row in db.query(BlacklistEntry.url_hash).all()}
    seen_in_this_run = set()

    rows_added = 0
    rows_skipped = 0
    batch = []

    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["source"] not in ("phishtank", "openphish"):
                continue

            url = row["text"]
            url_hash = _hash_url(url)
            if url_hash in existing_hashes or url_hash in seen_in_this_run:
                rows_skipped += 1
                continue
            seen_in_this_run.add(url_hash)

            collected_date = datetime.strptime(row["date_collected"], "%Y-%m-%d").date()
            brand_target = row["brand_impersonated"].strip() or None
            # PhishTank uses "Other" for unidentified brands -- not a real brand name.
            if brand_target == "Other":
                brand_target = None

            batch.append(
                BlacklistEntry(
                    url=url,
                    url_hash=url_hash,
                    domain=normalize_domain(url),
                    source=row["source"],
                    brand_target=brand_target,
                    first_seen=collected_date,
                    last_seen=collected_date,
                )
            )

            if len(batch) >= BATCH_SIZE:
                db.add_all(batch)
                db.commit()
                rows_added += len(batch)
                print(f"  ...{rows_added:,} rows inserted so far")
                batch = []

    if batch:
        db.add_all(batch)
        db.commit()
        rows_added += len(batch)

    return rows_added, rows_skipped


def seed_brand_registry(db) -> tuple[int, int]:
    """Load the canonical Egyptian brand registry. Returns (brands_added, domains_added)."""
    existing_brand_names = {row[0] for row in db.query(EgyptianBrand.brand_name).all()}
    existing_domains = {row[0] for row in db.query(BrandDomain.domain).all()}

    brands_by_name: dict[str, EgyptianBrand] = {}
    brands_added = 0
    domains_added = 0
    today = datetime.now().date()

    for brand_name, domain in EGYPTIAN_BRAND_DOMAINS:
        if domain in existing_domains:
            continue

        if brand_name not in brands_by_name:
            if brand_name in existing_brand_names:
                brand = db.query(EgyptianBrand).filter_by(brand_name=brand_name).one()
            else:
                # Category left generic here -- categories were tracked informally
                # in Phase 1; refine per-brand if needed later.
                brand = EgyptianBrand(brand_name=brand_name, category="Uncategorized")
                db.add(brand)
                db.flush()  # get brand.id without a full commit
                brands_added += 1
            brands_by_name[brand_name] = brand

        db.add(BrandDomain(brand_id=brands_by_name[brand_name].id, domain=domain, verified_date=today))
        domains_added += 1

    db.commit()
    return brands_added, domains_added


def main() -> None:
    db = SessionLocal()

    print("Seeding blacklist_entries from PhishTank + OpenPhish...")
    blacklist_added, blacklist_skipped = seed_blacklist_entries(db)
    print(f"  -> {blacklist_added:,} added, {blacklist_skipped:,} already present (skipped)")

    print("Seeding egyptian_brands + brand_domains...")
    brands_added, domains_added = seed_brand_registry(db)
    print(f"  -> {brands_added} brands added, {domains_added} domains added")

    db.add(FeedUpdate(source="initial_seed", rows_added=blacklist_added, rows_updated=0))
    db.commit()

    db.close()
    print()
    print("Seeding complete.")


if __name__ == "__main__":
    main()
