import importlib.util
from pathlib import Path
from datetime import datetime,date,timedelta
import pytest
from app.services.feeds import activate_snapshot,rollback_snapshot,expire_sources
from app.models import BlacklistEntry,FeedSnapshot,ScanRequest,ScanResult

def test_invalid_refresh_preserves_snapshot(db):
    first=activate_snapshot(db,'openphish',[f'https://sample{i}.example/' for i in range(10)])
    before=db.query(BlacklistEntry).count()
    with pytest.raises(ValueError):activate_snapshot(db,'openphish',[])
    with pytest.raises(ValueError):activate_snapshot(db,'openphish',['https://only-one.example/'])
    assert db.query(BlacklistEntry).count()==before
    assert db.query(FeedSnapshot).count()==1
def test_snapshot_rollback(db):
    first=activate_snapshot(db,'openphish',['https://old.example/'])
    activate_snapshot(db,'openphish',['https://new.example/'])
    rollback_snapshot(db,first['version'])
    assert db.query(BlacklistEntry).filter_by(domain='old.example',is_active=True).count()==1
    assert db.query(BlacklistEntry).filter_by(domain='new.example',is_active=True).count()==0
def test_retention_deletes_old_results(db):
    spec=importlib.util.spec_from_file_location('retention',Path(__file__).resolve().parents[2]/'data/scripts/retention.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    old=ScanRequest(input_type='text',text_hash='a'*64,submitted_at=datetime.now()-timedelta(days=90));db.add(old);db.flush()
    db.add(ScanResult(scan_request_id=old.id,verdict='LOW',engine_breakdown={},final_score=0));db.commit()
    assert module.delete_expired(db,30)==1
    assert db.query(ScanResult).count()==0

def test_expiry_respects_each_source(db):
    old=datetime.now()-timedelta(days=10)
    activate_snapshot(db,'openphish',['https://overlap.example/'],captured_at=old)
    activate_snapshot(db,'phishtank',['https://overlap.example/'],captured_at=old)
    expire_sources(db);db.commit()
    assert db.query(BlacklistEntry).filter_by(domain='overlap.example',is_active=True).count()==1
    expire_sources(db,date.today()+timedelta(days=31));db.commit()
    assert db.query(BlacklistEntry).filter_by(domain='overlap.example',is_active=True).count()==0

def test_fresh_source_does_not_hide_stale_source(db):
    from app.engines.threat_intel.blacklist_lookup import blacklist_health
    activate_snapshot(db,'phishtank',['https://old-feed.example/'],captured_at=datetime.now()-timedelta(days=40))
    activate_snapshot(db,'openphish',['https://fresh-feed.example/'])
    health=blacklist_health(db)
    assert not health['available'];assert health['sources']['phishtank']['stale']

def test_rollback_keeps_other_source_evidence(db):
    first=activate_snapshot(db,'openphish',['https://original.example/'])
    activate_snapshot(db,'openphish',['https://both.example/'])
    activate_snapshot(db,'phishtank',['https://both.example/'])
    rollback_snapshot(db,first['version'])
    assert db.query(BlacklistEntry).filter_by(domain='both.example',is_active=True).count()==1

def test_missing_configured_source_is_degraded(db,monkeypatch):
    from dataclasses import replace
    from app.engines.threat_intel import blacklist_lookup
    monkeypatch.setattr(blacklist_lookup,'settings',replace(blacklist_lookup.settings,required_feeds=('phishtank','openphish')))
    activate_snapshot(db,'openphish',['https://fresh.example/'])
    assert blacklist_lookup.blacklist_health(db)['reason']=='blacklist_missing_source'

def test_database_failure_rolls_back_entire_activation(db,monkeypatch):
    first=activate_snapshot(db,'openphish',['https://preserved.example/'])
    def fail():raise RuntimeError('simulated_commit_failure')
    with monkeypatch.context() as patch:
        patch.setattr(db,'commit',fail)
        with pytest.raises(RuntimeError):activate_snapshot(db,'openphish',['https://partial.example/'])
        db.rollback()
    assert db.query(FeedSnapshot).count()==1
    assert db.query(BlacklistEntry).filter_by(domain='partial.example').count()==0
    assert db.query(BlacklistEntry).filter_by(domain='preserved.example',is_active=True).count()==1
