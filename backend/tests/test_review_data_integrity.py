"""Critical safeguards for pinned data restoration and host-only inference."""
import hashlib,importlib.util
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('restore_raw_data',ROOT/'data/scripts/restore_raw_data.py')
restore=importlib.util.module_from_spec(spec);spec.loader.exec_module(restore)

def test_restore_rejects_changed_data_without_overwriting(tmp_path):
    target=tmp_path/'data/raw/original.csv';target.parent.mkdir(parents=True);target.write_bytes(b'unchanged user data')
    incoming=tmp_path/'incoming';incoming.write_bytes(b'replacement')
    entry={'path':'data/raw/original.csv','sha256':hashlib.sha256(b'replacement').hexdigest()}
    with pytest.raises(ValueError,match='SHA-256'):restore.restore(entry,tmp_path,incoming)
    assert target.read_bytes()==b'unchanged user data'

def test_restore_checks_input_before_creating_output(tmp_path):
    incoming=tmp_path/'incoming';incoming.write_bytes(b'wrong snapshot')
    entry={'path':'data/raw/data.csv','sha256':hashlib.sha256(b'expected').hexdigest()}
    with pytest.raises(ValueError,match='SHA-256'):restore.restore(entry,tmp_path,incoming)
    assert not (tmp_path/entry['path']).exists()

def test_restore_refuses_out_of_raw_path(tmp_path):
    with pytest.raises(ValueError,match='inside data/raw'):restore.target_path(tmp_path,'data/raw/../../outside')

def test_host_model_is_invariant_to_scheme_path_and_query():
    from app.engines.url_model import ARTIFACT,score_url
    if not ARTIFACT.exists():pytest.skip('Packaged model unavailable')
    a=score_url('https://example.com/')
    b=score_url('http://example.com/account/verify?id=123456789')
    assert a['probability']==b['probability']
    assert a['threshold']==b['threshold']

def test_frozen_text_manifest_cannot_be_rewritten(tmp_path,monkeypatch):
    import pandas as pd
    from evaluation import run_text_v3 as training
    monkeypatch.setattr(training,'OUT',tmp_path)
    path=tmp_path/'input.csv'
    frame=pd.DataFrame([{'id':'fixture','text':'temporary unit fixture','label':'legitimate','content_type':'text','source':'unit-test','language':'en','group_id':'fixture-group','split':'train'}])
    frame.to_csv(path,index=False)
    training.build_split(path);before=(tmp_path/'text_split.json').read_bytes()
    monkeypatch.setattr(training,'versions',lambda:{'unit-test':'changed environment'})
    training.build_split(path)
    assert (tmp_path/'text_split.json').read_bytes()==before
    frame.loc[0,'text']='modified unit fixture';frame.to_csv(path,index=False)
    with pytest.raises(ValueError,match='refusing to overwrite'):training.build_split(path)
    assert (tmp_path/'text_split.json').read_bytes()==before
