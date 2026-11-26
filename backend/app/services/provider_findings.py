"""Attach additive provider Findings to an existing scan's retention owner.

No new persistence path, model calls, policy feedback, or database commit.
Open question: an explicit import deletion owner must be designed before import
storage is enabled; this service accepts existing scan_requests only.
"""
from datetime import datetime, timezone
import hashlib

from app.engines.registry import Observation, registry
from app.models import FindingRecord, ScanRequest
from app.services.findings import record_findings


def record_provider_scan(db, scan_id: int, *, text: str | None = None, url: str | None = None,
                         sender_id: str | None = None, sender_display: str | None = None,
                         channel: str = 'unknown', now: datetime | None = None, engine=None):
    """Called after scoring, in the scan transaction. Idempotent per engine version.

    channel is explicit: the existing /analyze API does not declare SMS delivery,
    so it passes unknown and cannot acquire a Mobile mapping merely from text.
    Input bytes must match the existing scan, preventing accidental cross-scan joins.
    """
    if type(scan_id) is not int or scan_id < 1:
        raise ValueError('provider_scan_owner_required')
    scan = db.get(ScanRequest, scan_id)
    digest = lambda value: hashlib.sha256(value.encode('utf-8')).hexdigest() if value else None
    if scan is None or scan.text_hash != digest(text) or scan.url_hash != digest(url):
        raise ValueError('provider_scan_owner_mismatch')
    engine = engine or registry.get('phishing.provider_claim')
    existing = db.query(FindingRecord).filter_by(scan_request_id=scan_id, engine_name=engine.name,
                                               engine_version=engine.version).all()
    if existing:
        return existing
    observation = Observation('provider_message', f'scan_requests:{scan_id}', now or datetime.now(timezone.utc),
                              {'text': text, 'url': url, 'sender_id': sender_id,
                               'sender_display': sender_display, 'channel': channel})
    return record_findings(db, engine.analyze(observation), scan_request_id=scan_id)
