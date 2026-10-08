"""Validated feed snapshots, transaction-based activation, source expiry and rollback."""
import csv,io,json,hashlib
from datetime import date,datetime,timedelta
import requests
from sqlalchemy import func
from app.core.url_utils import parse_url,url_hash
from app.models import BlacklistEntry,FeedSnapshot,FeedObservation

FEEDS={'phishtank':'https://data.phishtank.com/data/online-valid.csv','openphish':'https://openphish.com/feed.txt'}
EXPIRY_DAYS={'phishtank':30,'openphish':7,'manual':90}
def fetch_feed(source):
    with requests.get(FEEDS[source],headers={'User-Agent':'ETIS-Local-Research/0.2'},timeout=(10,60),stream=True) as response:
        response.raise_for_status();chunks=[];size=0
        for chunk in response.iter_content(65536):
            size+=len(chunk)
            if size>50_000_000:raise ValueError('feed_too_large')
            chunks.append(chunk)
        content=b''.join(chunks).decode('utf-8-sig')
    if source=='phishtank':
        reader=csv.DictReader(io.StringIO(content))
        if not {'url','verified','online'}<=set(reader.fieldnames or []):raise ValueError('invalid_feed_schema')
        urls=[r['url'] for r in reader if r['verified']=='yes' and r['online']=='yes']
    else:urls=content.splitlines()
    return urls

def expire_sources(db,as_of=None):
    as_of=as_of or date.today()
    active={}
    observations=db.query(FeedObservation).all()
    observed={o.url_hash for o in observations}
    for observation in observations:
        if observation.last_seen>=as_of-timedelta(days=EXPIRY_DAYS.get(observation.source,30)):
            active[observation.url_hash]=max(active.get(observation.url_hash,date.min),observation.last_seen)
    for entry in db.query(BlacklistEntry).all():
        if entry.url_hash in observed:
            entry.is_active=entry.url_hash in active
            if entry.is_active:entry.last_seen=active[entry.url_hash]
        elif entry.source in EXPIRY_DAYS:
            if entry.last_seen<as_of-timedelta(days=EXPIRY_DAYS[entry.source]):entry.is_active=False

def activate_snapshot(db,source,urls,captured_at=None,validate=True):
    if source not in EXPIRY_DAYS:raise ValueError('invalid_source')
    captured_at=captured_at or datetime.now()
    valid={};invalid=0
    for value in urls:
        try:p=parse_url(value);valid[p.canonical]=p.host
        except Exception:invalid+=1
    if not valid or (validate and invalid>max(3,len(urls)*.02)):
        raise ValueError('invalid_or_empty_feed')
    previous=db.query(FeedSnapshot).filter_by(source=source,accepted=True).order_by(FeedSnapshot.id.desc()).first()
    if validate and previous and len(valid)<previous.row_count*.5:
        raise ValueError('suspiciously_small_feed')
    version=hashlib.sha256((source+captured_at.isoformat()+json.dumps(sorted(valid))).encode()).hexdigest()
    # Staging and validation occur before this transaction. Any exception rolls back all activation.
    existing={e.url_hash:e for e in db.query(BlacklistEntry).all()}
    observations={o.url_hash:o for o in db.query(FeedObservation).filter_by(source=source).all()}
    today=captured_at.date()
    for url,host in valid.items():
        digest=url_hash(url);entry=existing.get(digest)
        observation=observations.get(digest)
        if observation:observation.last_seen=max(observation.last_seen,today)
        else:db.add(FeedObservation(url_hash=digest,source=source,last_seen=today))
        if entry:
            entry.last_seen=max(entry.last_seen,today);entry.is_active=True
        else:
            entry=BlacklistEntry(url=url,url_hash=digest,domain=host,source=source,first_seen=today,last_seen=today)
            db.add(entry);existing[digest]=entry
    db.flush();expire_sources(db,today)
    db.add(FeedSnapshot(source=source,version=version,captured_at=captured_at,row_count=len(valid),payload=list(valid),accepted=True))
    db.commit()
    return {'source':source,'version':version,'rows':len(valid),'invalid_rows':invalid}

def rollback_snapshot(db,version):
    snapshot=db.query(FeedSnapshot).filter_by(version=version).one()
    # Remove the source's newer activations, then restore the selected snapshot atomically.
    previous_hashes={o.url_hash for o in db.query(FeedObservation).filter_by(source=snapshot.source)}
    db.query(FeedObservation).filter_by(source=snapshot.source).delete(synchronize_session=False)
    hashes={url_hash(url) for url in snapshot.payload}
    for digest in hashes:db.add(FeedObservation(url_hash=digest,source=snapshot.source,last_seen=snapshot.captured_at.date()))
    db.flush()
    # Entries observed only in later snapshots of this source are removed, while other sources survive.
    surviving={o.url_hash for o in db.query(FeedObservation)}
    for entry in db.query(BlacklistEntry).filter(BlacklistEntry.url_hash.in_(list(previous_hashes-hashes))):
        if entry.url_hash not in surviving:entry.is_active=False
    expire_sources(db)
    # The snapshot remains an immutable record. Restoring it never invents a fresh collection date.
    db.query(FeedSnapshot).filter(FeedSnapshot.source==snapshot.source,FeedSnapshot.id>snapshot.id).update(
        {'accepted':False},synchronize_session=False)
    db.commit()
    return {'source':snapshot.source,'version':snapshot.version,'rows':snapshot.row_count,'restored':True}
