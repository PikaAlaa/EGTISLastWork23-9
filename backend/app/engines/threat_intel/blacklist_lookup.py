import hashlib
from datetime import date, timedelta
from sqlalchemy import func
from app.core.settings import settings
from app.core.url_utils import parse_url, lookup_keys
from app.models.blacklist import BlacklistEntry
from app.models.snapshot import FeedSnapshot

SHARED_HOSTING_DOMAINS = {
    'google.com', 'docs.google.com', 'sites.google.com', 'drive.google.com', 'forms.gle',
    'forms.office.com', '1drv.ms', 'onedrive.live.com', 'wa.me', 'web.whatsapp.com',
    'bit.ly', 'tinyurl.com', 't.co', 't.me', 'rebrand.ly', 'dropbox.com', 'weebly.com',
    'gravatar.com', 'genspark.ai', 'beacons.ai', 'taplink.cc', 'ipfs.io', 'jotform.com',
    'flowcode.com', 'qrco.de', 'q-r.to', 'did.li', 'hsforms.com', 'adobe.com',
}

def blacklist_health(db):
    count, latest = db.query(func.count(BlacklistEntry.id), func.max(BlacklistEntry.last_seen)).filter(BlacklistEntry.is_active.is_(True)).one()
    if not count:
        return {'available': False, 'reason': 'blacklist_empty', 'count': 0}
    snapshots = db.query(FeedSnapshot.source,FeedSnapshot.captured_at).filter_by(accepted=True).order_by(FeedSnapshot.id.desc()).all()
    sources = {}
    from app.services.feeds import EXPIRY_DAYS
    for snapshot in snapshots:
        if snapshot.source not in sources:
            max_age = min(settings.blacklist_max_age_days, EXPIRY_DAYS.get(snapshot.source,30))
            sources[snapshot.source] = {'last_seen':str(snapshot.captured_at.date()),
                'stale':snapshot.captured_at.date() < date.today()-timedelta(days=max_age)}
    missing=[source for source in settings.required_feeds if source not in sources]
    for source in missing:sources[source]={'last_seen':None,'stale':True,'missing':True}
    stale = any(s['stale'] for s in sources.values()) if sources else latest < date.today()-timedelta(days=settings.blacklist_max_age_days)
    return {'available': not stale, 'reason': 'blacklist_missing_source' if missing else 'blacklist_stale' if stale else None, 'count': count, 'last_seen': str(latest),'sources':sources}

def calculate_blacklist_reputation_score(url, db):
    parsed = parse_url(url)
    hashes = [hashlib.sha256(key.encode()).hexdigest() for key in lookup_keys(url)]
    exact = db.query(BlacklistEntry).filter(BlacklistEntry.url_hash.in_(hashes), BlacklistEntry.is_active.is_(True)).first()
    if exact:
        return {'score': exact.reputation_score, 'match_type': 'exact', 'matched_entry': {
            'source': exact.source, 'brand_target': exact.brand_target,
            'first_seen': str(exact.first_seen), 'last_seen': str(exact.last_seen)}}
    if any(parsed.host == shared or parsed.host.endswith('.'+shared) for shared in SHARED_HOSTING_DOMAINS):
        return {'score': 0.0, 'match_type': None, 'matched_entry': None}
    count = db.query(func.count(BlacklistEntry.id)).filter_by(domain=parsed.host, is_active=True).scalar()
    return {'score': min(85.0, 60.0+5*(count-1)) if count else 0.0,
            'match_type': 'domain' if count else None,
            'matched_entry': {'hit_count': count} if count else None}
