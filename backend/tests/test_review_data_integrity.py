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

def test_packaged_url_model_uses_its_declared_representation():
    from app.engines.url_model import ARTIFACT,score_url
    if not ARTIFACT.exists():pytest.skip('Packaged model unavailable')
    a=score_url('https://example.com/')
    b=score_url('http://example.com/account/verify?id=123456789')
    from app.engines.url_model import _load
    artifact = _load()
    representation = artifact.get('deployment_schema', {}).get('representation', 'host_only')
    if representation == 'host_only':
        assert a['probability']==b['probability']
    else:
        # v2 explicitly includes existing full-URL candidates. Verify the
        # packaged model consumes full URL characters, with no schema drift.
        from app.core.url_utils import parse_url
        from app.engines.url_model import _extractor
        from app.engines.url_features import phresh_features, url_features, shortcut_features
        value = 'http://example.com/account/verify?id=123456789'
        if 'pipeline' in artifact:
            expected = artifact['pipeline'].predict_proba([value])[0, 1]
        else:
            feature = value
            if artifact['vectorizer'].__class__.__name__ == 'DictVectorizer':
                feature = (shortcut_features(value) if representation == 'shortcut_only' else
                           phresh_features(value, parse_url(value).host, _extractor(), True)
                           if artifact['deployment_schema']['phresh_schema'] else url_features(value, _extractor()))
            expected = artifact['classifier'].predict_proba(artifact['vectorizer'].transform([feature]))[0, 1]
        assert b['probability'] == float(expected)
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
