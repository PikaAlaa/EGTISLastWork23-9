"""Engine protocol, registry and per-engine health (design core-v1 §8). Invented values only."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.core.findings import Finding
from app.engines.phishing_findings import phishing_findings
from app.engines.registry import EngineRegistry, Observation, PhishingAnalyzeEngine, registry
from app.models import FindingRecord
from app.services.findings import record_findings

NOW = datetime(2026, 11, 18, 12, tzinfo=timezone.utc)


class DemoEngine:
    """A test-only network engine: proves a future engine plugs in without touching /analyze."""
    name = 'network.demo'
    version = 'demo-v1'
    domain = 'network'

    def analyze(self, observation):
        return [Finding.model_validate(dict(
            engine={'name': self.name, 'version': self.version}, domain='network', kind='known_bad_destination',
            severity='medium', confidence='single_signal', observed_at=observation.observed_at,
            created_at=observation.observed_at, source={'kind': 'import', 'ref': observation.source_ref},
            attack=[{'technique_id': 'T1566', 'matrix': 'enterprise', 'attack_version': '20.0', 'basis': 'demo'}]))]

    def health(self, context):
        return {'available': True, 'reason': None}


class BrokenHealthEngine(DemoEngine):
    name = 'host.broken'
    domain = 'host'

    def health(self, context):
        raise RuntimeError('private-marker-health')


def test_builtin_phishing_engine_is_registered():
    assert registry.names() == ['phishing.analyze', 'phishing.provider_claim']
    engine = registry.get('phishing.analyze')
    assert engine.domain == 'phishing' and engine.version.startswith('decision-v2+url:ee0ba9f0077c1fd140aa')


@pytest.mark.parametrize('mutate,error', [
    (lambda e: setattr(e, 'name', 'NoDots'), 'invalid_engine_name'),
    (lambda e: setattr(e, 'domain', 'fraud'), 'invalid_engine_domain'),
])
def test_registration_validates_name_and_domain(mutate, error):
    engine = DemoEngine()
    mutate(engine)
    with pytest.raises(ValueError, match=error):
        EngineRegistry().register(engine)


def test_duplicate_and_non_engine_are_refused():
    local = EngineRegistry()
    local.register(DemoEngine())
    with pytest.raises(ValueError, match='engine_already_registered'):
        local.register(DemoEngine())
    with pytest.raises(TypeError):
        local.register(SimpleNamespace(name='network.x', version='1', domain='network'))


def test_one_failing_health_check_does_not_mask_another(caplog):
    local = EngineRegistry()
    local.register(DemoEngine())
    local.register(BrokenHealthEngine())
    report = local.health({})
    assert report['network.demo'] == {'domain': 'network', 'version': 'demo-v1', 'available': True, 'reason': None}
    assert report['host.broken']['available'] is False and report['host.broken']['reason'] == 'health_check_failed'
    assert 'private-marker' not in caplog.text


@pytest.mark.parametrize('blacklist,text_model,available,reason', [
    (True, True, True, None), (True, False, True, 'degraded_components'), (False, False, False, 'no_component'),
])
def test_phishing_engine_health_mirrors_ready_components(blacklist, text_model, available, reason):
    status = PhishingAnalyzeEngine().health({'blacklist': {'available': blacklist}, 'text_model': {'available': text_model}})
    assert status == {'available': available, 'reason': reason}


def test_phishing_adapter_equals_the_pure_emitter():
    result = {'verdict': 'MEDIUM', 'final_score': 40.0, 'decisive_reason': 'text_keywords',
              'supporting_signals': ['text_keywords'], 'checked_links': [], 'links_truncated': False,
              'text_finding': {'version': 'tv'}, 'analysis_complete': True, 'checks_unavailable': [],
              'policy_version': 'decision-v2', 'timing_ms': 1.0}
    observation = Observation(kind='analyze_result', source_ref='scan_requests:3', observed_at=NOW,
                              data={'result': result, 'text': 'invented', 'url': None, 'scan_request_id': 3})
    via_registry, = registry.get('phishing.analyze').analyze(observation)
    direct, = phishing_findings(result, SimpleNamespace(text='invented', url=None), 3, now=NOW)
    assert via_registry.model_dump(exclude={'id'}) == direct.model_dump(exclude={'id'})
    with pytest.raises(ValueError, match='unsupported_observation'):
        registry.get('phishing.analyze').analyze(Observation(kind='pcap', source_ref='x', observed_at=NOW))


def test_future_engine_findings_flow_through_record_findings(db):
    findings = DemoEngine().analyze(Observation(kind='log_record', source_ref='import:demo-1', observed_at=NOW))
    record_findings(db, findings)
    db.commit()
    stored = db.query(FindingRecord).one()
    assert (stored.engine_name, stored.domain, stored.source_kind) == ('network.demo', 'network', 'import')


def test_ready_reports_engines_without_changing_status(client, monkeypatch):
    from app.engines import text_model
    from app.engines.threat_intel import blacklist_lookup
    monkeypatch.setattr(blacklist_lookup, 'blacklist_health', lambda _: dict(available=True))
    body = client.get('/health/ready').json()
    assert body['engines']['phishing.analyze']['domain'] == 'phishing'
    assert body['status'] in ('ready', 'degraded')
    monkeypatch.setattr(text_model, 'score_text', lambda _: (_ for _ in ()).throw(FileNotFoundError()))
    monkeypatch.setattr(blacklist_lookup, 'blacklist_health', lambda _: dict(available=False, reason='database_unavailable'))
    response = client.get('/health/ready')
    assert response.status_code == 503 and response.json()['status'] == 'unavailable'
    assert response.json()['engines']['phishing.analyze'] == {
        'domain': 'phishing', 'version': registry.get('phishing.analyze').version,
        'available': False, 'reason': 'no_component'}
