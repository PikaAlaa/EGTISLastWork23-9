"""INVENTED providers/messages/contacts only. example.eg names are inert strings.

Nothing in this module is an authentic Egyptian observation or provider contact.
The numeric contacts below are invented test tokens, never dialled or researched.
"""
from datetime import date, datetime, timezone
import hashlib
import json

from app.core.provider_registry import MATCHING_TABLE, ProviderRegistry, ReleasePin, digest_json, load_registry

NOW = datetime(2026, 11, 26, 12, tzinfo=timezone.utc)
TODAY = NOW.date()
INVENTED_URL = 'https://different.example.eg/invented-action'
INVENTED_PHONE = '12345'


def invented_provider():
    """A wholly invented provider, including its purported official publication."""
    fields = ['display_name', 'aliases.0', 'aliases.1', 'aliases.2', 'domains.0',
              'sender_ids.0', 'sms_short_codes.0', 'hotlines.0', 'coverage.domains',
              'coverage.sender_ids', 'coverage.sms_short_codes', 'coverage.hotlines']
    return dict(
        provider_id='invented_example_bank', category='bank', display_name='Invented Example Bank', invented=True,
        aliases=[dict(value=value, language=language, claim_context='identity', source_ref='invented_source')
                 for value, language in [('بنك المثال المخترع', 'ar'), ('بنكنا المخترع', 'ar_EG'),
                                         ('bank el methal el mo5tara3', 'franco')]],
        domains=[dict(host='bank.example.eg', match_scope='exact_host', channel='web',
                      purpose='invented', source_ref='invented_source')],
        sender_ids=[dict(value='INVENTEDBANK', channel='sms', comparison='literal', source_ref='invented_source')],
        sms_short_codes=[dict(value='54321', channel='sms', purpose='outbound_sender', source_ref='invented_source')],
        hotlines=[dict(value='65432', channel='phone', purpose='callback', source_ref='invented_source')],
        sources=[dict(id='invented_source', url='https://bank.example.eg/invented-source', read_at='2026-11-24',
                      verifier='invented_verifier', reviewer='invented_reviewer', field_paths=fields,
                      note_digest=hashlib.sha256(b'invented-source-note').hexdigest())],
        coverage=dict(domains='documented_complete', sender_ids='documented_complete',
                      sms_short_codes='documented_complete', hotlines='documented_complete'),
        verified_at='2026-11-25', review_due_at='2026-12-25', status='example_only')


def invented_registry():
    return dict(schema_version='provider-registry-v1', registry_version='invented-v1',
                released_at='2026-11-26', example_only=True, entries=[invented_provider()])


def write_invented_registry(tmp_path, payload=None, raw=None, allow_invented=True):
    """Pin exact invented bytes independently of the loader."""
    raw = raw if raw is not None else json.dumps(payload or invented_registry(), ensure_ascii=False).encode()
    path = tmp_path / 'invented-registry.json'
    path.write_bytes(raw)
    pin = ReleasePin('invented-v1', hashlib.sha256(raw).hexdigest(),
                     digest_json(ProviderRegistry.model_json_schema()), digest_json(MATCHING_TABLE))
    return load_registry(path, pin, allow_invented=allow_invented, today=TODAY)
