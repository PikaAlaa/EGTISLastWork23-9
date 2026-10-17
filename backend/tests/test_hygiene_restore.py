"""Recovery from an intentionally data-free clone without weakening hash guards."""
import hashlib
import importlib.util
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('hygiene_restore', ROOT/'data/scripts/restore_raw_data.py')
restore=importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


def test_check_all_reports_every_missing_file_with_authorised_restore_command(tmp_path):
    entry={'path':'data/raw/fixture.csv','sha256':hashlib.sha256(b'a\nb\n').hexdigest()}
    result=restore.check_all({'files':[entry]},tmp_path)
    assert result['missing']==1
    assert '--input "<authorised-original-copy>"' in result['files'][0]['restore_command']
    assert result['network_requests']==0


def test_inventory_accepts_only_exact_newline_variants_and_keeps_bytes(tmp_path):
    entry={'path':'data/raw/fixture.csv','sha256':hashlib.sha256(b'a\nb\n').hexdigest()}
    target=tmp_path/entry['path'];target.parent.mkdir(parents=True);target.write_bytes(b'a\r\nb\r\n')
    result=restore.check_all({'files':[entry]},tmp_path)
    assert result['files'][0]['status']=='verified_newline_variant'
    assert target.read_bytes()==b'a\r\nb\r\n'
    target.write_bytes(b'changed\r\nb\r\n')
    assert restore.check_all({'files':[entry]},tmp_path)['checksum_mismatch']==1
