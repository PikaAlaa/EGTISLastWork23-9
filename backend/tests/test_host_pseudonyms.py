"""Host pseudonyms, source locality and the HMAC key in initialize (design host-engine-v1 §6.4, §7, §8.7)."""
import importlib.util
import logging
import re
from pathlib import Path

import pytest

from app.engines.host.pseudonyms import (HostKeyError, Pseudonymizer, load_key, locality, parse_local_nets)

ROOT = Path(__file__).resolve().parents[2]
KEY_A, KEY_B = bytes(range(32)), bytes(range(1, 33))
MARKER = 'invented-marker-4410'


def test_refs_are_stable_with_one_key_and_change_with_another():
    a, a2, b = Pseudonymizer(KEY_A), Pseudonymizer(KEY_A), Pseudonymizer(KEY_B)
    assert a.host_ref('INVENTED-PC') == a2.host_ref('INVENTED-PC') != b.host_ref('INVENTED-PC')
    assert a.account_ref(name='invented-user', domain='INVENTED-PC') == a2.account_ref(name='invented-user',
                                                                                       domain='INVENTED-PC')
    assert a.account_ref(name='invented-user') != b.account_ref(name='invented-user')
    assert re.fullmatch(r'hmac:[0-9a-f]{32}', a.host_ref('INVENTED-PC'))


def test_normalisation_and_domain_separation():
    p = Pseudonymizer(KEY_A)
    assert p.host_ref('invented-pc') == p.host_ref(' INVENTED-PC ') == p.host_ref('INVENTED-PC.lan.example')
    assert p.account_ref(name='Invented-User', domain='invented-pc') == p.account_ref(name='invented-user',
                                                                                      domain='INVENTED-PC')
    # The same text as a host and as an account never gives the same reference.
    assert p.host_ref('invented') != p.account_ref(name='invented')
    assert p.account_ref(name='invented-user', domain='A') != p.account_ref(name='invented-user', domain='B')


def test_real_sids_are_preferred_and_never_returned_in_clear():
    p = Pseudonymizer(KEY_A)
    sid = 'S-1-5-21-1111-2222-3333-1001'
    by_sid = p.account_ref(sid=sid, name='invented-user')
    assert by_sid == p.account_ref(sid=sid, name='other-spelling') and sid not in by_sid
    # Null SID and '-' fall back to the name.
    assert p.account_ref(sid='S-1-0-0', name='invented-user') == p.account_ref(name='invented-user')
    assert p.account_ref(sid='-', name='invented-user') == p.account_ref(name='invented-user')
    assert p.account_ref() is None and p.account_ref(name='-') is None and p.host_ref('') is None


@pytest.mark.parametrize('sid,name,domain,expected', [
    ('S-1-5-18', None, None, 'sid:S-1-5-18'),
    ('S-1-5-19', None, None, 'sid:S-1-5-19'),
    ('S-1-5-20', None, None, 'sid:S-1-5-20'),
    (None, 'SYSTEM', 'NT AUTHORITY', 'sid:S-1-5-18'),
    (None, 'LOCAL SERVICE', 'NT AUTHORITY', 'sid:S-1-5-19'),
    (None, 'network service', 'nt authority', 'sid:S-1-5-20'),
])
def test_well_known_principals_keep_their_sid(sid, name, domain, expected):
    assert Pseudonymizer(KEY_A).account_ref(sid=sid, name=name, domain=domain) == expected


def test_system_named_account_outside_nt_authority_is_pseudonymised():
    assert Pseudonymizer(KEY_A).account_ref(name='SYSTEM', domain='INVENTED-PC').startswith('hmac:')


def test_key_loading_requires_a_long_hex_key(monkeypatch, caplog):
    monkeypatch.setenv('ETIS_HOST_PSEUDONYM_KEY', KEY_A.hex())
    assert load_key() == KEY_A
    for bad in ('', 'zz' * 32, 'ab' * 15):
        monkeypatch.setenv('ETIS_HOST_PSEUDONYM_KEY', bad)
        with pytest.raises(HostKeyError) as exc:
            load_key()
        assert str(exc.value) == 'host_pseudonym_key_missing'
    monkeypatch.delenv('ETIS_HOST_PSEUDONYM_KEY')
    with pytest.raises(HostKeyError):
        load_key()


def test_refs_and_logs_never_contain_the_input(caplog):
    caplog.set_level(logging.DEBUG)
    p = Pseudonymizer(KEY_A)
    refs = [p.host_ref(MARKER), p.account_ref(name=MARKER, domain=MARKER), p.account_ref(sid=f'S-1-5-21-{MARKER}')]
    assert all(MARKER not in ref for ref in refs) and MARKER not in caplog.text
    assert MARKER not in repr(p) and KEY_A.hex() not in repr(p)


@pytest.mark.parametrize('address,expected', [
    ('10.1.2.3', 'local'), ('172.16.0.9', 'local'), ('192.168.1.10', 'local'), ('127.0.0.1', 'local'),
    ('169.254.10.10', 'local'), ('::1', 'local'), ('fe80::1', 'local'), ('fd00::5', 'local'),
    ('::ffff:192.168.1.10', 'local'),
    ('203.0.113.9', 'outside'), ('198.51.100.20', 'outside'), ('2001:db8::1', 'outside'), ('100.64.0.1', 'outside'),
    ('-', 'unknown'), ('', 'unknown'), (None, 'unknown'), ('0.0.0.0', 'unknown'), ('::', 'unknown'),
    ('not-an-address', 'unknown'), ('INVENTED-WS', 'unknown'),
])
def test_locality_rules(address, expected):
    assert locality(address) == expected


def test_local_net_option_extends_local_ranges():
    nets = parse_local_nets(['203.0.113.0/24'])
    assert locality('203.0.113.9', nets) == 'local' and locality('198.51.100.20', nets) == 'outside'
    with pytest.raises(ValueError) as exc:
        parse_local_nets([f'{MARKER}/99'])
    assert str(exc.value) == 'invalid_local_net'


def _initialize_module():
    spec = importlib.util.spec_from_file_location('etis_initialize', ROOT / 'scripts/initialize.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_initialize_generates_the_host_key_once_and_keeps_it(tmp_path):
    module = _initialize_module()
    env = tmp_path / '.env'
    env.write_text('ETIS_API_KEY=invented\nETIS_HOST_PSEUDONYM_KEY=\n', encoding='utf-8')
    module.ensure_env_secrets(env)
    first = re.search(r'^ETIS_HOST_PSEUDONYM_KEY=([0-9a-f]{64})$', env.read_text(encoding='utf-8'), re.M)
    assert first, 'key not generated'
    assert env.read_text(encoding='utf-8').count('ETIS_HOST_PSEUDONYM_KEY=') == 1
    module.ensure_env_secrets(env)
    assert re.search(r'^ETIS_HOST_PSEUDONYM_KEY=([0-9a-f]{64})$', env.read_text(encoding='utf-8'), re.M).group(1) \
        == first.group(1)
    missing = tmp_path / 'other.env'
    missing.write_text('ETIS_API_KEY=invented\n', encoding='utf-8')
    module.ensure_env_secrets(missing)
    text = missing.read_text(encoding='utf-8')
    assert re.search(r'^ETIS_HOST_PSEUDONYM_KEY=[0-9a-f]{64}$', text, re.M) and 'ETIS_DB_PASSWORD=' in text


def test_env_example_documents_the_key_without_a_value():
    lines = (ROOT / '.env.example').read_text(encoding='utf-8').splitlines()
    assert 'ETIS_HOST_PSEUDONYM_KEY=' in lines
