"""Engine protocol and registry (design core-v1 §8).

Every ETIS engine — today `phishing.analyze`, later network, malware and host engines —
turns a local Observation into `finding-v1` Findings. Engines never persist anything:
`app.services.findings.record_findings` does persistence, indicator upsert, ATT&CK
validation and correlation. Engines read local files or local sensors only; none may
contact an external analysis service or fetch an indicator.

This module is distinct from `app.services.registry`, which populates the brand registry.
See docs/engine-authors.md for the full contract.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping, Protocol, runtime_checkable

from app.core.findings import Finding

logger = logging.getLogger(__name__)
EngineDomain = Literal['phishing', 'malware', 'network', 'host']
DOMAINS = ('phishing', 'malware', 'network', 'host')
NAME = re.compile(r'^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$')


@dataclass(frozen=True)
class Observation:
    """One unit of local input for an engine (a finished scan result, a log record, a file)."""
    kind: str
    source_ref: str
    observed_at: datetime
    data: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class Engine(Protocol):
    name: str
    version: str
    domain: EngineDomain

    def analyze(self, observation: Observation) -> list[Finding]: ...

    def health(self, context: Mapping[str, Any]) -> dict: ...


class EngineRegistry:
    def __init__(self):
        self._engines: dict[str, Engine] = {}

    def register(self, engine: Engine) -> Engine:
        if not isinstance(engine, Engine):
            raise TypeError('engine_protocol_not_satisfied')
        if not NAME.match(engine.name or ''):
            raise ValueError('invalid_engine_name')
        if engine.domain not in DOMAINS:
            raise ValueError('invalid_engine_domain')
        if engine.name in self._engines:
            raise ValueError('engine_already_registered')
        self._engines[engine.name] = engine
        return engine

    def get(self, name: str) -> Engine:
        return self._engines[name]

    def names(self) -> list[str]:
        return sorted(self._engines)

    def health(self, context: Mapping[str, Any] | None = None) -> dict[str, dict]:
        """Per-engine status. One failing health check never hides another engine's state."""
        report = {}
        for name in self.names():
            engine = self._engines[name]
            try:
                status = dict(engine.health(context or {}))
                status['available'] = bool(status.get('available'))
            except Exception:
                logger.warning('engine_health_failed')
                status = {'available': False, 'reason': 'health_check_failed'}
            try:
                version = str(engine.version)
            except Exception:
                version = 'unknown'
            report[name] = {'domain': engine.domain, 'version': version, **status}
        return report


class PhishingAnalyzeEngine:
    """Adapter for the existing /analyze flow. `analyze` maps a *finished* decision-v2 result
    to Findings via the pure emitter; it never re-scores, so verdicts are untouched."""
    name = 'phishing.analyze'
    domain: EngineDomain = 'phishing'

    @property
    def version(self) -> str:
        from app.engines.phishing_findings import url_candidate_id
        from app.engines.risk_scoring import POLICY_VERSION
        return f'{POLICY_VERSION}+url:{url_candidate_id()}'

    def analyze(self, observation: Observation) -> list[Finding]:
        from types import SimpleNamespace
        from app.engines.phishing_findings import phishing_findings
        if observation.kind != 'analyze_result':
            raise ValueError('unsupported_observation')
        payload = SimpleNamespace(text=observation.data.get('text'), url=observation.data.get('url'))
        return phishing_findings(observation.data['result'], payload, observation.data['scan_request_id'],
                                 now=observation.observed_at)

    def health(self, context: Mapping[str, Any]) -> dict:
        # Mirrors /health/ready: usable when the blacklist or the text model is available.
        blacklist = bool((context.get('blacklist') or {}).get('available'))
        text_model = bool((context.get('text_model') or {}).get('available'))
        available = blacklist or text_model
        return {'available': available,
                'reason': None if blacklist and text_model else 'degraded_components' if available else 'no_component'}


registry = EngineRegistry()
registry.register(PhishingAnalyzeEngine())
