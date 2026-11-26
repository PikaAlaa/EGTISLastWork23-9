"""Offline schema/loader checks. All provider/contact/source fixtures are INVENTED."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import socket

import pytest

from app.core.provider_registry import (RegistryUnavailable, load_bundled_registry, load_registry)
from provider_fixtures import TODAY, invented_registry, write_invented_registry


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('provider test attempted network access')
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr'):
        monkeypatch.setattr(socket, name, blocked)


def test_shipped_registry_is_genuinely_empty():
    loaded = load_bundled_registry()
    assert loaded.registry.entries == ()
    assert not loaded.registry.example_only


def test_invented_examples_require_explicit_test_mode(tmp_path):
    with pytest.raises(RegistryUnavailable, match='^provider_registry_unavailable$'):
        write_invented_registry(tmp_path, allow_invented=False)
    loaded = write_invented_registry(tmp_path)
    assert loaded.registry.entries[0].invented
    with pytest.raises(Exception):
        loaded.registry.entries[0].display_name = 'invented mutation'


@pytest.mark.parametrize('pin_field', ['registry_sha256', 'schema_sha256', 'matching_sha256',
                                     'normalization_version', 'registry_version'])
def test_each_pin_fails_closed(tmp_path, pin_field):
    loaded = write_invented_registry(tmp_path)
    with pytest.raises(RegistryUnavailable):
        load_registry(tmp_path / 'invented-registry.json', replace(loaded.pin, **{pin_field: 'wrong'}),
                      allow_invented=True, today=TODAY)


def test_exact_bytes_missing_file_and_future_release(tmp_path):
    loaded = write_invented_registry(tmp_path)
    path = tmp_path / 'invented-registry.json'
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(RegistryUnavailable):
        load_registry(path, loaded.pin, allow_invented=True)
    path.unlink()
    with pytest.raises(RegistryUnavailable):
        load_registry(path, loaded.pin)
    with pytest.raises(RegistryUnavailable):
        load_registry(tmp_path / 'missing', loaded.pin)
    payload = invented_registry()
    payload['released_at'] = '2027-01-01'
    with pytest.raises(RegistryUnavailable):
        write_invented_registry(tmp_path, payload)


@pytest.mark.parametrize('mutate', [
    lambda p: p.update(extra='invented-private-marker'),
    lambda p: p['entries'].append(deepcopy(p['entries'][0])),
    lambda p: p['entries'][0].update(status='active'),
    lambda p: p['entries'][0].update(verified_at='2027-01-01'),
    lambda p: p['entries'][0].update(review_due_at='2026-11-24'),
    lambda p: p['entries'][0]['sources'][0].update(reviewer='invented_verifier'),
    lambda p: p['entries'][0]['sources'][0].update(read_at='2027-01-01'),
    lambda p: p['entries'][0]['sources'][0].update(url='data:invented'),
    lambda p: p['entries'][0]['sources'][0].update(url='https://invented@bank.example.eg/'),
    lambda p: p['entries'][0]['sources'][0].update(field_paths=[]),
    lambda p: p['entries'][0]['sources'][0].update(field_paths=['display_name']),
    lambda p: p['entries'][0]['domains'][0].update(source_ref='invented_missing'),
    lambda p: p['entries'][0]['domains'][0].update(host='BANK.example.eg'),
    lambda p: p['entries'][0]['domains'][0].update(host='127.0.0.1'),
    lambda p: p['entries'][0]['domains'][0].update(host='bank.example.eg/path'),
    lambda p: p['entries'][0]['domains'][0].update(match_scope='wildcard'),
    lambda p: p['entries'][0]['hotlines'][0].update(value='not-a-number'),
    lambda p: p['entries'][0]['sms_short_codes'][0].update(value='+201000000001'),
    lambda p: p['entries'][0]['sender_ids'][0].update(comparison='ignore_everything'),
    lambda p: p['entries'][0].update(domains=[]),
])
def test_invalid_schema_and_provenance_return_only_code(tmp_path, mutate):
    payload = invented_registry()
    mutate(payload)
    with pytest.raises(RegistryUnavailable) as error:
        write_invented_registry(tmp_path, payload)
    assert str(error.value) == 'provider_registry_unavailable'
    assert error.value.__suppress_context__


def test_contact_ownership_conflict_is_rejected(tmp_path):
    payload = invented_registry()
    second = deepcopy(payload['entries'][0])
    second['provider_id'] = 'invented_other_provider'
    payload['entries'].append(second)
    with pytest.raises(RegistryUnavailable):
        write_invented_registry(tmp_path, payload)


@pytest.mark.parametrize('raw', [b'{"registry_version":"a","registry_version":"b"}', b'NaN', b'{', b'[]'])
def test_invalid_json_and_duplicate_keys(tmp_path, raw):
    with pytest.raises(RegistryUnavailable):
        write_invented_registry(tmp_path, raw=raw)


def test_stale_flags_cover_due_disputed_withdrawn_and_explicit_state(tmp_path):
    provider = write_invented_registry(tmp_path).registry.entries[0]
    assert not provider.is_stale(TODAY)
    assert provider.is_stale(provider.review_due_at)
    assert provider.model_copy(update={'source_disputed': True}).is_stale(TODAY)
    for status in ('stale', 'withdrawn'):
        assert provider.model_copy(update={'status': status}).is_stale(TODAY)
