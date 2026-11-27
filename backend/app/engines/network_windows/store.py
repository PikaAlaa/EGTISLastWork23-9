"""Read-only views of the core indicator store for network.windows N3 (design network-windows-v1 §2.1 N3).

N3 matches a queried registered domain against active `domain` and `url` indicators seen by
another source (a phishing Finding or a feed), after the core correlation exclusions (shared
hosting stoplist, official brand domains). Indicators seen only by network.windows itself are
not used, so an import never matches its own earlier output.
"""
from __future__ import annotations

from app.models import Indicator, IndicatorSighting
from app.services.findings import _exclusions

ENGINE_NAME = 'network.windows'


def indicator_domain_hashes(db) -> frozenset[str]:
    rows = (db.query(Indicator.type, Indicator.value_hash, Indicator.registered_domain_hash)
            .join(IndicatorSighting, IndicatorSighting.indicator_id == Indicator.id)
            .filter(Indicator.type.in_(('domain', 'url')), IndicatorSighting.active.is_(True),
                    IndicatorSighting.source_name != ENGINE_NAME)
            .distinct())
    _, excluded = _exclusions(db)
    hashes = set()
    for kind, value_hash, domain_hash in rows:
        if domain_hash:
            hashes.add(domain_hash)
        if kind == 'domain':
            hashes.add(value_hash)
    return frozenset(hashes - excluded)
