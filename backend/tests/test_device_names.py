"""Shared device names and the server-side srv: wrap (design core-v2 §3.2, step 7a).

Names, keys and refs are invented. No network access: names come from monkeypatched sources.
"""
import hashlib
import hmac
import importlib.util
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.core import device_names as dn
from app.core.findings import Finding
from app.engines.host.pseudonyms import Pseudonymizer

ROOT = Path(__file__).resolve().parents[2]
SERVER_KEY = bytes(range(32))
OTHER_SERVER_KEY = bytes(range(1, 33))
HOST_KEY = bytes(range(100, 132))
ENDPOINT = 'hmac:' + '0123456789abcdef' * 2


@pytest.mark.parametrize('raw', ['PC-01', 'pc-01.corp.example', 'PC-01.', ' pc-01 ', 'Pc-01.Corp.Example.'])
def test_local_device_name_one_name_for_every_shape(raw):
    assert dn.local_device_name(raw) == 'pc-01'


@pytest.mark.parametrize('raw', ['', '   ', '.', '.corp.example', None, 7])
def test_local_device_name_empty_is_none(raw):
    assert dn.local_device_name(raw) is None


def test_source_order_gethostname_then_computername_then_platform(monkeypatch):
    monkeypatch.setattr(dn.socket, 'gethostname', lambda: 'Host-A.corp.example')
    monkeypatch.setenv('COMPUTERNAME', 'NETBIOS-B')
    monkeypatch.setattr(dn.platform, 'node', lambda: 'node-c')
    assert dn.this_pc_name() == 'host-a'
    monkeypatch.setattr(dn.socket, 'gethostname', lambda: '')
    assert dn.this_pc_name() == 'netbios-b'
    monkeypatch.delenv('COMPUTERNAME')
    assert dn.this_pc_name() == 'node-c'

    def broken():
        raise OSError('no name')
    monkeypatch.setattr(dn.socket, 'gethostname', broken)
    monkeypatch.setattr(dn.platform, 'node', lambda: '')
    assert dn.this_pc_name() is None


def test_endpoint_ref_equals_host_ref_of_the_short_name():
    pseudo = Pseudonymizer(HOST_KEY)
    assert dn.endpoint_device_ref(pseudo, 'PC-01.corp.example') == pseudo.host_ref('pc-01')
    assert dn.endpoint_device_ref(pseudo, '') is None


def test_wrap_ref_deterministic_srv_form():
    stored = dn.wrap_ref(ENDPOINT, 'device', SERVER_KEY)
    assert stored == dn.wrap_ref(ENDPOINT, 'device', SERVER_KEY)
    assert re.fullmatch(r'srv:[0-9a-f]{32}', stored) and len(stored) == 36
    expected = hmac.new(SERVER_KEY, ('device\0' + ENDPOINT).encode(), hashlib.sha256).hexdigest()[:32]
    assert stored == 'srv:' + expected


def test_wrap_ref_differs_by_key_and_by_purpose():
    device = dn.wrap_ref(ENDPOINT, 'device', SERVER_KEY)
    assert device != dn.wrap_ref(ENDPOINT, 'device', OTHER_SERVER_KEY)
    assert device != dn.wrap_ref(ENDPOINT, 'account', SERVER_KEY)


@pytest.mark.parametrize('ref,code', [
    ('srv:' + '0' * 32, 'ref_prefix_invalid'),
    ('hmac:' + 'A' * 32, 'ref_format_invalid'),
    ('hmac:' + '0' * 31, 'ref_format_invalid'),
    ('PC-01', 'ref_format_invalid'),
    ('', 'ref_format_invalid'),
    (None, 'ref_format_invalid'),
    ('sid:S-1-5-18', 'ref_format_invalid'),   # well-known SIDs are account refs, not device refs
])
def test_wrap_ref_rejects_anything_but_hmac(ref, code):
    with pytest.raises(dn.RefError) as info:
        dn.wrap_ref(ref, 'device', SERVER_KEY)
    assert str(info.value) == code


@pytest.mark.parametrize('sid', ['sid:S-1-5-18', 'sid:S-1-5-19', 'sid:S-1-5-20'])
def test_wrap_ref_leaves_well_known_account_sids_unchanged(sid):
    assert dn.wrap_ref(sid, 'account', SERVER_KEY) == sid


def test_wrap_ref_purpose_and_key_checked():
    with pytest.raises(dn.RefError, match='^ref_purpose_invalid$'):
        dn.wrap_ref(ENDPOINT, 'path', SERVER_KEY)
    with pytest.raises(dn.ServerRefKeyError, match='^server_ref_key_missing$'):
        dn.wrap_ref(ENDPOINT, 'device', b'short')


@pytest.mark.parametrize('value', ['', 'not-hex', '00' * 16, '00' * 31])
def test_server_key_missing_or_short_raises_fixed_code(tmp_path, monkeypatch, value):
    monkeypatch.delenv(dn.SERVER_KEY_ENV, raising=False)
    env = tmp_path / '.env'
    env.write_text(f'{dn.SERVER_KEY_ENV}={value}\n', encoding='utf-8')
    with pytest.raises(dn.ServerRefKeyError) as info:
        dn.load_server_key(env)
    assert str(info.value) == 'server_ref_key_missing'


def test_server_key_read_from_env_file_and_environment(tmp_path, monkeypatch):
    monkeypatch.delenv(dn.SERVER_KEY_ENV, raising=False)
    env = tmp_path / '.env'
    env.write_text(f'{dn.SERVER_KEY_ENV}={SERVER_KEY.hex()}\n', encoding='utf-8')
    assert dn.load_server_key(env) == SERVER_KEY
    monkeypatch.setenv(dn.SERVER_KEY_ENV, OTHER_SERVER_KEY.hex())
    assert dn.load_server_key(env) == OTHER_SERVER_KEY
    assert dn.load_server_key(tmp_path / 'absent.env') == OTHER_SERVER_KEY


def _finding(details=None):
    now = datetime(2026, 11, 28, tzinfo=timezone.utc)
    return Finding(engine={'name': 'malware.files', 'version': 'v'}, domain='malware', kind='known_bad_hash',
                   severity='high', confidence='corroborated',
                   evidence={'reasons': ['hash_list_malicious'], 'details': details or {'size_band': 'small'}},
                   observed_at=now, created_at=now, source={'kind': 'import', 'ref': 'malware_scans:1'})


def test_attach_device_ref_adds_the_endpoint_ref_without_changing_the_rest():
    finding = _finding()
    attached = dn.attach_device_ref(finding, HOST_KEY, 'PC-01.corp.example')
    assert attached.evidence.details == {'size_band': 'small', 'device_ref': Pseudonymizer(HOST_KEY).host_ref('pc-01')}
    assert attached.id == finding.id and attached.evidence.reasons == finding.evidence.reasons
    assert 'device_ref' not in finding.evidence.details


def test_attach_device_ref_without_key_or_name_leaves_no_device(monkeypatch):
    finding = _finding()
    assert dn.attach_device_ref(finding, None, 'PC-01') is finding
    monkeypatch.setattr(dn, 'this_pc_name', lambda: None)
    assert dn.attach_device_ref(finding, HOST_KEY) is finding


def _initialize():
    spec = importlib.util.spec_from_file_location('etis_initialize_device_names', ROOT / 'scripts/initialize.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_initialize_creates_server_key_once_and_keeps_it(tmp_path):
    module = _initialize()
    env = tmp_path / '.env'
    env.write_text('ETIS_API_KEY=x\n', encoding='utf-8')
    module.ensure_env_secrets(env)
    first = env.read_bytes()
    value = next(line.split('=', 1)[1] for line in first.decode().splitlines() if line.startswith('ETIS_SERVER_REF_KEY='))
    assert len(bytes.fromhex(value)) == 32
    module.ensure_env_secrets(env)
    assert env.read_bytes() == first
    blank = tmp_path / 'blank.env'
    blank.write_text('ETIS_SERVER_REF_KEY=\n', encoding='utf-8')
    module.ensure_env_secrets(blank)
    assert re.search(r'^ETIS_SERVER_REF_KEY=[0-9a-f]{64}$', blank.read_text(encoding='utf-8'), re.M)
    assert os.getenv('ETIS_SERVER_REF_KEY', '') != value
