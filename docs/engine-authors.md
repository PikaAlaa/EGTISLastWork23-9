# Writing an ETIS engine

This guide is for team members adding a network, malware or host engine to ETIS core v1.
The contract is defined in [the core v1 design](design/core-v1.md) §1 and §8 and implemented
in `backend/app/engines/registry.py`. Today the only registered engine is the
`phishing.analyze` adapter. No other engine exists yet.

## Rules

1. **Free and local only.** Engines read local files or local sensors only. Examples are Zeek
   or Suricata logs from the operator's own network, YARA rules over files the operator
   supplies, and Sysmon or EVTX exports. Never call a cloud sandbox, VirusTotal, Safe
   Browsing or any other external analysis service. Never resolve, open or fetch an
   indicator. URLs are inert strings.
2. **Return Findings, nothing else.** `analyze(observation)` returns `list[Finding]`
   (`app.core.findings.Finding`, schema `finding-v1`). Engines never write to the
   database. `app.services.findings.record_findings` persists findings, upserts
   indicators, validates ATT&CK ids against the local catalogue and correlates incidents.
3. **Never change the phishing verdict path.** Engines must not import or alter
   `risk_scoring`, its thresholds or any frozen model. The `/analyze` verdict parity gate
   (`backend/tests/test_findings_parity.py`) must keep passing.
4. **No submitted or private content in evidence.** `evidence.details` holds reason codes,
   versions, thresholds and indicator strengths only. Indicators derived from user or
   operator data are sent hash-only (`value=None`, `value_hash` from
   `app.core.indicators.normalize`). Plaintext `value` is allowed only for public feed,
   analyst-entered or sensor-owned values.
5. **Categorical confidence.** Use `confirmed`, `corroborated`, `single_signal` or
   `undetermined`. Never use a percentage. Document how severity and confidence are
   derived in the engine's module docstring.
6. **Versioned ATT&CK mapping.** Each engine ships its own mapping table (for example
   `network-map-v1`). Every id must exist, neither revoked nor deprecated, in the pinned
   local ATT&CK version (`data/attack-lock.json`, currently 20.0). Use the right matrix:
   `enterprise` or `mobile`.
7. **Malware samples are never executed.** Static rules only.
8. **Honest health.** `health(context)` returns `{'available': bool, 'reason': str | None}`.
   A failing health check is reported for that engine only and never hides another
   engine's state.

## Skeleton

```python
from app.core.findings import Finding
from app.core.indicators import normalize
from app.engines.registry import Observation, registry

class ZeekConnEngine:
    name = 'network.zeek_conn'          # lower-case dotted name, unique
    version = 'zeek-conn-v1'
    domain = 'network'

    def analyze(self, observation: Observation) -> list[Finding]:
        # observation.data comes from a local log import; never fetch anything here.
        ...
        return [Finding.model_validate({...})]

    def health(self, context) -> dict:
        return {'available': True, 'reason': None}

registry.register(ZeekConnEngine())
```

## Required tests for a new engine

- Its Findings validate against `finding-v1` and contain no submitted content (a marker-string test).
- Each mapping row produces the expected severity, confidence and ATT&CK ids.
- Every emitted ATT&CK id exists in the v20.0 fixture `backend/tests/fixtures/attack-20.0-subset.json`
  (extend the fixture from the pinned files if needed, without descriptions).
- `record_findings` stores the engine's findings and correlation behaves as documented.
- The `/analyze` parity gate and the full suite still pass. Also run database initialization,
  frontend build and lint, as for every change.
