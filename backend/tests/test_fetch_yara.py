"""signature-base YARA rule fetch: pinned files, SHA-256 and git blob checks, licence census (design malware-engine-v1 §3.3, §3.7).

Uses invented, harmless rule text and a fake session; no network access and no real rule text.
"""
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fetch_yara', ROOT / 'data/scripts/fetch_yara.py')
fy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fy)

COMMIT = 'a' * 40

RULE_A = b'''/*
   Invented header. License: https://creativecommons.org/licenses/by-nc/4.0/
*/
rule Invented_No_Licence : tag_one
{
    meta:
        author = "invented author"
        description = "has // slashes and a fake rule x { inside a string"
    strings:
        $a = "invented-marker-one"
        $b = /invented\\/path\\/[a-z]+/
    condition:
        $a or $b
}

// rule Commented_Out { condition: true }
'''

RULE_B = b'''private rule Invented_Drl_Field {
    meta:
        author = "invented author"
        license = "Detection Rule License 1.1 https://example.com/LICENSE"
    condition:
        filesize < 10
}
rule Invented_Other_Licence {
    meta:
        license = "CC BY 4.0"
        score = 50
    strings:
        $h = { 41 42 [2-4] 43 }
    condition:
        $h
}
/* rule Hidden_In_Block { condition: true } */
'''

LIST = b'invented_b.yar\nmissing_file.yar\n'

FILES = {'yara/invented_a.yar': RULE_A, 'yara/invented_b.yar': RULE_B, fy.SB_LIST: LIST}


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def iter_content(self, size):
        for start in range(0, len(self.body), 7):
            yield self.body[start:start + 7]


class FakeSession:
    def __init__(self, files):
        self.files, self.urls = files, []

    def get(self, url, **_):
        self.urls.append(url)
        path = url[len(f'{fy.SB_RAW}{COMMIT}/'):]
        return contextlib.nullcontext(FakeResponse(self.files[path]))


def make_lock(files=FILES) -> dict:
    entries = [{'path': p, 'size': len(b), 'sha256': hashlib.sha256(b).hexdigest(), 'git_blob_sha1': fy.git_blob_sha1(b)}
               for p, b in sorted(files.items())]
    return {
        'destination': fy.DESTINATION,
        'source': {'repository': fy.SB_REPO, 'commit': COMMIT, 'url_prefix': f'{fy.SB_RAW}{COMMIT}/',
                   'directory': 'signature-base/aaaaaaaaaaaa', 'files': entries},
        'rule_tree_sha256': fy.tree_sha256((e['path'], e['sha256']) for e in entries),
        'census': fy.census_of({p: b.decode() for p, b in files.items()}),
        'dropped_sources': [],
    }


def test_git_blob_sha1_matches_git():
    # `git hash-object` of "hello\n"
    assert fy.git_blob_sha1(b'hello\n') == 'ce013625030ba8dba906f756967f9e9ca394464a'


def test_committed_lock_pins_signature_base_only():
    lock = fy.load_lock()
    source = lock['source']
    assert source['repository'] == 'Neo23x0/signature-base'
    assert source['commit'] == 'de3c7252c22b3376352b5a68defa46459a12a693'
    assert source['file_count'] == len(source['files']) > 700
    assert all(fy.is_kept(e['path']) for e in source['files'])
    assert fy.SB_LIST in {e['path'] for e in source['files']}
    assert lock['rule_tree_sha256'] == fy.tree_sha256((e['path'], e['sha256']) for e in source['files'])
    census = lock['census']
    assert census['rules'] == (census['rules_without_license_field_so_drl_1_1']
                               + census['rules_with_drl_1_1_license_field'] + census['rules_with_other_license'])
    assert census['rules_with_other_license'] == len(census['other_license_rules'])
    assert census['external_variable_list']['listed_files_missing'] == []
    (dropped,) = lock['dropped_sources']
    assert dropped['repository'] == 'YARAHQ/yara-forge' and dropped['release'] == '20261108'
    assert dropped['asset'] == 'yara-forge-rules-core.zip' and dropped['size'] == 1744187
    assert dropped['sha256'] == '9a01ef66c573991036cbd2e805f59d5b5e8ca3a56375e567b6a3433855f74707'
    assert 'Trojan:Win32/Znyonm!rfn' in dropped['outcome']


def test_rules_directory_is_ignored_by_git():
    assert 'data/external/yara/' in (ROOT / '.gitignore').read_text(encoding='utf-8').splitlines()


def test_committed_census_is_reproducible_from_local_rules():
    lock = fy.load_lock()
    base = ROOT / lock['destination']
    if not (base / lock['source']['directory']).is_dir():
        pytest.skip('pinned rules not downloaded on this machine')
    assert fy.verify(lock, base) == []
    assert fy.census(lock, base) == fy.census(lock, base) == lock['census']


def test_fetch_downloads_verifies_and_then_skips(tmp_path):
    lock, session = make_lock(), FakeSession(FILES)
    assert fy.fetch(lock, tmp_path, session) == 'downloaded_and_verified'
    assert len(session.urls) == 3 and all(u.startswith(f'{fy.SB_RAW}{COMMIT}/yara/') for u in session.urls)
    root = tmp_path / 'signature-base/aaaaaaaaaaaa'
    assert (root / 'yara/invented_b.yar').read_bytes() == RULE_B
    assert fy.verify(lock, tmp_path) == []
    assert fy.fetch(lock, tmp_path, session) == 'already_verified' and len(session.urls) == 3
    assert not list(tmp_path.rglob('*.part'))


def test_a_changed_byte_fails_verification(tmp_path):
    lock = make_lock()
    fy.fetch(lock, tmp_path, FakeSession(FILES))
    target = tmp_path / 'signature-base/aaaaaaaaaaaa/yara/invented_a.yar'
    body = bytearray(target.read_bytes())
    body[10] ^= 1
    target.write_bytes(bytes(body))
    assert fy.verify(lock, tmp_path) == ['file_mismatch:yara/invented_a.yar']


def test_a_changed_download_is_refused(tmp_path):
    lock = make_lock()
    changed = {**FILES, 'yara/invented_b.yar': RULE_B.replace(b'50', b'51')}
    with pytest.raises(ValueError, match='sha256_mismatch:yara/invented_b.yar'):
        fy.fetch(lock, tmp_path, FakeSession(changed))
    assert not (tmp_path / 'signature-base/aaaaaaaaaaaa/yara/invented_b.yar').exists()


def test_a_lock_with_a_changed_census_fails_verification(tmp_path):
    lock = make_lock()
    fy.fetch(lock, tmp_path, FakeSession(FILES))
    lock['census'] = {**lock['census'], 'rules': lock['census']['rules'] + 1}
    assert fy.verify(lock, tmp_path) == ['census_mismatch']


def test_fetch_stops_when_a_file_disappears_after_writing(tmp_path, monkeypatch):
    original, real_write = fy.read_file, fy.write_checked
    written = set()

    def vanishing(path):
        # Simulates antivirus removing one file immediately after it is written.
        if Path(path).name in written:
            return None
        return original(path)

    def tracking_write(target, body):
        if Path(target).name == 'invented_b.yar':
            written.add(Path(target).name)
        return real_write(target, body)

    monkeypatch.setattr(fy, 'read_file', vanishing)
    monkeypatch.setattr(fy, 'write_checked', tracking_write)
    with pytest.raises(fy.RemovedAfterWrite) as exc:
        fy.fetch(make_lock(), tmp_path, FakeSession(FILES))
    assert exc.value.paths == ['yara/invented_b.yar']


def test_main_reports_removed_files_with_exit_code_2(monkeypatch, capsys):
    def removed(*_):
        raise fy.RemovedAfterWrite(['yara/x.yar'])

    monkeypatch.setattr(fy, 'fetch', removed)
    assert fy.main([]) == 2
    assert json.loads(capsys.readouterr().out) == {'status': 'removed_after_write', 'files': ['yara/x.yar']}


def test_census_counts_on_invented_rules():
    census = fy.census_of({p: b.decode() for p, b in FILES.items()})
    assert census['rule_files'] == 2 and census['rules'] == 3
    assert census['rules_without_license_field_so_drl_1_1'] == 1
    assert census['rules_with_drl_1_1_license_field'] == 1
    assert census['other_license_rules'] == [
        {'rule': 'Invented_Other_Licence', 'file': 'yara/invented_b.yar', 'license': 'CC BY 4.0'}]
    assert census['other_license_counts'] == {'CC BY 4.0': 1}
    assert census['rules_with_author_field'] == 2 and census['rules_without_author_field'] == 1
    assert census['external_variable_list'] == {
        'file': fy.SB_LIST, 'entries': 2, 'entries_are': 'rule file names under yara/', 'listed_files_present': 1,
        'listed_files_missing': ['yara/missing_file.yar'], 'rules_in_listed_files': 2}
    review = census['comment_licence_review']
    assert review['by_file'] == [{'file': 'yara/invented_a.yar', 'comment_licences': ['CC BY-NC 4.0'], 'rules': 1,
                                  'rules_without_license_field': 1}]
    assert review['rules_without_license_field_in_files_with_non_drl_comment_licence'] == 1
    assert fy.census_of({p: b.decode() for p, b in FILES.items()}) == census


def test_parser_ignores_comments_strings_and_regexes():
    rules = fy.parse_rules(RULE_A.decode() + RULE_B.decode())
    assert [r['name'] for r in rules] == ['Invented_No_Licence', 'Invented_Drl_Field', 'Invented_Other_Licence']
    assert ('score', '50') in rules[2]['meta']


@pytest.mark.parametrize('change', [
    {'url_prefix': 'https://example.com/'},
    {'commit': 'not-a-commit'},
    {'directory': '../escape'},
])
def test_lock_rejects_unpinned_locations(tmp_path, change):
    lock = json.loads((ROOT / 'data/yara-lock.json').read_text(encoding='utf-8'))
    lock['source'].update(change)
    path = tmp_path / 'lock.json'
    path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(ValueError):
        fy.load_lock(path)


def test_lock_rejects_files_outside_the_rule_folder(tmp_path):
    lock = json.loads((ROOT / 'data/yara-lock.json').read_text(encoding='utf-8'))
    lock['source']['files'][0]['path'] = 'iocs/hash-iocs.txt'
    path = tmp_path / 'lock.json'
    path.write_text(json.dumps(lock), encoding='utf-8')
    with pytest.raises(ValueError):
        fy.load_lock(path)
