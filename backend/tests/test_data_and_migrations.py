import importlib.util,os,subprocess,sys,sqlite3,json
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def test_grouping_before_split_and_synthetic_training_only(tmp_path):
    module=load('rebuild',ROOT/'data/scripts/rebuild_dataset.py')
    rows=[{'text':'Your account number 1234 has a new notice','label':'legitimate','source':'reviewed','content_type':'text'},
        {'text':'Your account number 9876 has a new notice','label':'legitimate','source':'reviewed','content_type':'text'},
        {'text':'اضغط الان لتحديث بطاقتك','label':'phishing','source':'synthetic_test','content_type':'text'},
        {'text':'https://a.example.co.uk/page','label':'phishing','source':'phishtank','content_type':'url'},
        {'text':'https://b.example.co.uk/other','label':'phishing','source':'phishtank','content_type':'url'}]
    source=tmp_path/'source.csv';pd.DataFrame(rows).to_csv(source,index=False)
    module.rebuild(source,tmp_path/'out');result=pd.read_csv(tmp_path/'out/dataset.csv')
    duplicates=result[result.text.str.startswith('Your')];assert duplicates.group_id.nunique()==1;assert duplicates.split.nunique()==1
    assert result[result.source=='synthetic_test'].split.eq('train').all()
    urls=result[result.content_type=='url'];assert urls.group_id.nunique()==1;assert urls.split.nunique()==1
def test_privacy_migration_keeps_verdict_removes_raw_columns(tmp_path):
    db=tmp_path/'migration.db';env={**os.environ,'DATABASE_URL':'sqlite:///'+db.as_posix()}
    def migrate(revision):subprocess.run([sys.executable,'-m','alembic','upgrade',revision],cwd=ROOT,env=env,check=True,capture_output=True)
    migrate('001_baseline')
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO scan_requests (id,text_value) VALUES (1,'private-marker')")
        conn.execute("INSERT INTO scan_results (scan_request_id,rule_based_score,final_score,verdict,engine_breakdown) VALUES (1,0,0,'LOW',?)",(json.dumps({'matched_words':['private-marker']}),))
    migrate('head');migrate('head')
    with sqlite3.connect(db) as conn:
        columns={row[1] for row in conn.execute('PRAGMA table_info(scan_requests)')}
        assert 'text_value' not in columns and 'url_value' not in columns
        assert len(conn.execute('SELECT text_hash FROM scan_requests').fetchone()[0])==64
        verdict,breakdown=conn.execute('SELECT verdict,engine_breakdown FROM scan_results').fetchone()
        assert verdict=='LOW';assert 'private-marker' not in breakdown
def test_window_tail_and_normalization():
    from app.core.text_utils import text_windows,normalize_arabic_text
    text=' '.join(['filler']*400)+' phishing-tail'
    assert text_windows(text)[-1].endswith('phishing-tail')
    assert max(len(w.split()) for w in text_windows(text))<=150
    assert normalize_arabic_text('إِدَارَة أَمان')=='اداره امان'

def test_new_domain_split_keeps_private_hosting_under_registered_parent():
    from app.core.url_utils import registered_domain
    assert registered_domain('tenant.weebly.com')=='weebly.com'
    assert registered_domain('other.weebly.com')=='weebly.com'
