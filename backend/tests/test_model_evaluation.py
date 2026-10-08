"""Independent guards for portable identity and honest three-model validation."""
import csv
import importlib.util
import hashlib
import json
from pathlib import Path
import pandas as pd
import pytest
from app.core.dataset_identity import dataset_identity

ROOT=Path(__file__).resolve().parents[2]

def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/f'ml/{name}.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def write_csv(path,rows,newline='\n',quoting=csv.QUOTE_MINIMAL):
    with path.open('w',encoding='utf-8',newline='') as stream:
        csv.writer(stream,lineterminator=newline,quoting=quoting).writerows(rows)

def test_content_identity_ignores_platform_newlines_and_csv_quoting(tmp_path):
    lf=tmp_path/'lf.csv';crlf=tmp_path/'crlf.csv'
    write_csv(lf,[['text','label'],['اهلا\nبك','legitimate']])
    write_csv(crlf,[['text','label'],['اهلا\r\nبك','legitimate']],'\r\n',csv.QUOTE_ALL)
    a,b=dataset_identity(lf),dataset_identity(crlf)
    assert a['dataset_sha256']==b['dataset_sha256']
    assert a['dataset_file_sha256']!=b['dataset_file_sha256']

def test_identity_preserves_values_row_order_and_duplicates(tmp_path):
    original=tmp_path/'source.csv';other=tmp_path/'other.csv'
    rows=[['text','label'],['alpha','legitimate'],['beta','phishing']]
    write_csv(original,rows);digest=dataset_identity(original)['dataset_sha256']
    for changed in [rows[:1]+rows[:0:-1],rows+[rows[1]],rows[:1]+[['alpha ','legitimate'],rows[2]]]:
        write_csv(other,changed);assert dataset_identity(other)['dataset_sha256']!=digest
    write_csv(other,[[r[1],r[0]] for r in rows])
    assert dataset_identity(other)['dataset_sha256']==digest

@pytest.mark.parametrize('rows',[[['text','text'],['a','b']],[['text','label'],['missing']]])
def test_malformed_csv_identity_rejected(tmp_path,rows):
    path=tmp_path/'bad.csv';write_csv(path,rows)
    with pytest.raises(ValueError):dataset_identity(path)

def validation_fixture(tmp_path):
    frame=pd.DataFrame({'text':['phishing','ordinary','bank notice','benign'],
        'label':['phishing','legitimate','legitimate','legitimate'],
        'source':['translated','translated','dialect_sms','dialect_sms'],
        'language':['ar']*4,'content_type':['email','email','text','text'],'split':['val']*4})
    path=tmp_path/'data.csv';frame.to_csv(path,index=False)
    return path,frame

def test_subgroup_report_exposes_false_alarm_hidden_by_pooling(tmp_path):
    path,frame=validation_fixture(tmp_path)
    report=load('validation').summarize(path,'test',[1,0,0,0],[.99,.01,.995,.01],frame)
    assert report['validation_n']==4
    group=report['by_source']['dialect_sms']
    assert group['n']==2 and group['phishing_n']==0 and group['legitimate_n']==2
    assert group['rates']['confusion']['fp']==1
    assert group['rates']['false_positive_rate']['value']==.5
    assert group['rates']['false_positive_rate']['n']==2
    assert group['auc'] is None
    assert report['by_source']['translated']['rates']['confusion']['fp']==0
    assert sum(r['n'] for r in report['by_content_type'].values())==4

def test_threshold_report_rejects_test_rows(tmp_path):
    path,frame=validation_fixture(tmp_path);frame.loc[0,'split']='test'
    with pytest.raises(ValueError,match='validation rows only'):
        load('validation').summarize(path,'test',[1,0,0,0],[.99,.01,.9,.01],frame)

def candidate_fixture(tmp_path):
    dataset,frame=validation_fixture(tmp_path)
    model_dir=tmp_path/'ml/models';model_dir.mkdir(parents=True)
    for name in ['char','bilstm','lightgbm']:
        artifact=model_dir/(name+'_candidate'+('.keras' if name=='bilstm' else '.joblib'))
        artifact.write_bytes(('model-'+name).encode())
        report={**dataset_identity(dataset),'by_source':{'example':{}},'by_language':{'ar':{}},
                'by_content_type':{'text':{}},'artifact_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest()}
        if name=='bilstm':
            tokenizer=artifact.with_suffix('.tokenizer.pkl');tokenizer.write_bytes(b'tokenizer')
            report['tokenizer_sha256']=hashlib.sha256(tokenizer.read_bytes()).hexdigest()
        artifact.with_suffix('.json').write_text(json.dumps(report))
    return dataset

def test_comparison_requires_all_three_matching_candidates(tmp_path):
    dataset=candidate_fixture(tmp_path);selection=load('select_model')
    _,reports=selection.checked_reports(dataset,tmp_path)
    assert set(reports)=={'char','bilstm','lightgbm'}
    path=tmp_path/'ml/models/lightgbm_candidate.json'
    report=json.loads(path.read_text());report['dataset_sha256']='earlier-dataset'
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError,match='lightgbm candidate dataset differs'):
        selection.checked_reports(dataset,tmp_path)
    path.unlink()
    with pytest.raises(FileNotFoundError):selection.checked_reports(dataset,tmp_path)

def test_candidate_validation_artifact_cannot_be_swapped(tmp_path):
    dataset=candidate_fixture(tmp_path)
    (tmp_path/'ml/models/char_candidate.joblib').write_bytes(b'different-model')
    with pytest.raises(ValueError,match='artifact differs'):
        load('select_model').checked_reports(dataset,tmp_path)

def test_model_comparison_accepts_equivalent_csv_on_another_platform(tmp_path):
    dataset=candidate_fixture(tmp_path)
    content=dataset.read_text();dataset.write_bytes(content.replace('\n','\r\n').encode())
    _,reports=load('select_model').checked_reports(dataset,tmp_path)
    assert len(reports)==3
