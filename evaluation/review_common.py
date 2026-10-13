"""Read the frozen development split without rewriting it; corrected metadata is an overlay."""
import hashlib
import json
from pathlib import Path
import re
import pandas as pd
from evaluation.run_text_v3 import ROOT, OUT as PREVIOUS, versions, sha

OUT = PREVIOUS / 'review-2026-10-13'
DIALECT = 'kaggle_dialectal_arabic_sms'
PROVENANCE = {
 'kaggle_arabic_phishing_fully_dataset': 'translated fraud letters and translated UCI ham; not Egyptian SMS',
 'salloum_gaber_bilingual_corpus': 'translated/parallel emails; not Egyptian SMS',
 DIALECT: 'mixed-regional, including non-Egyptian markers; apparently templated; origin/licence unverified; training only',
 'everyday_probes': '12 existing invented development fixtures; not authentic Egyptian SMS',
}

def read_frozen():
    manifest = json.loads((PREVIOUS/'text_split.json').read_text(encoding='utf-8'))
    rows = pd.read_csv(ROOT/'evaluation/local-results/v3-data/text-trainval-only.csv', dtype=str).fillna('')
    expected = {r['row_id']: r for r in manifest['rows']}
    assert len(rows) == len(expected) and not rows.id.duplicated().any()
    for row in rows.itertuples():
        old = expected[str(row.id)]
        assert hashlib.sha256(row.text.encode()).hexdigest() == old['content_sha256']
        assert all(str(getattr(row,k)) == old[k] for k in ['group_id','split','label','source'])
    assert set(rows.split) == {'train','val'}
    assert rows.groupby('group_id').split.nunique().max() == 1
    return rows, manifest

def language(text):
    # Arabic script plus actual Latin letters, not a blanket dialect/source assumption.
    arabic = bool(re.search(r'[\u0621-\u064a\u066e-\u06d3\u06fa-\u06fc]', text))
    latin = bool(re.search(r'[A-Za-z]', text))
    return 'mixed' if arabic and latin else 'ar' if arabic else 'en' if latin else 'und'

def write(name, obj):
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((PREVIOUS/'text_split.json').read_text(encoding='utf-8'))
    obj.setdefault('data_sha256', manifest['data_sha256'])
    obj.setdefault('model_sha256', None)
    obj.setdefault('libraries', versions())
    obj.setdefault('final_test_run', False)
    (OUT/name).write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=lambda x:x.item())+'\n', encoding='utf-8')

if __name__ == '__main__':
    rows, manifest = read_frozen()
    print({'verified_development_rows':len(rows), 'frozen_file_sha256':sha(PREVIOUS/'text_split.json')})
