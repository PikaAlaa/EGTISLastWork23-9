"""Fresh host-only fits under the frozen v3 PhreshPhish protocol, with v4 reporting.

Only aggregate results go to reports. Data and row scores stay ignored. Destinations
are never fetched. The precommitted selection rule fixes thresholds before evaluation.
"""
import gc
import hashlib
import json
import subprocess
import sys
import time
import warnings
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
import joblib
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import GroupKFold
from sklearn.svm import LinearSVC
from threadpoolctl import threadpool_limits
from app.engines.url_features import url_features
from evaluation import run_phreshphish as previous
from evaluation.phreshphish_utils import at_threshold, hand_features, libraries, threshold_at_fpr
from evaluation.probe_legit_hosts import HOSTS, probe

OUT = ROOT / 'evaluation/reports/2026-10-v4'
LOCAL = ROOT / 'evaluation/local-results/v4'
MODELS = ROOT / 'release-artifacts/v4'
PROTOCOL = ROOT / 'evaluation/reports/2026-10-v3/phreshphish/protocol.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def benign_subdomain(host, extractor):
    if not isinstance(host, str) or not host:
        return False
    sub = extractor(host).subdomain
    return any(label != 'www' for label in sub.split('.') if label)


def scores(artifact, frame, extractor, deployed=False):
    result = np.full(len(frame), np.nan)
    valid = np.flatnonzero(frame.host.notna().to_numpy())
    for offset in range(0, len(valid), 4096):
        indices = valid[offset:offset + 4096]
        rows = frame.iloc[indices]
        if deployed:
            values = [url_features(host, extractor) for host in rows.host]
        elif artifact['model'] == 'lightgbm':
            values = [hand_features(row.url, row.host, extractor, False) for row in rows.itertuples()]
        else:
            values = rows.host.tolist()
        result[indices] = artifact['classifier'].predict_proba(artifact['vectorizer'].transform(values))[:, 1]
    return result


def verify_etis_rows():
    """Check content and membership against the immutable review manifest."""
    manifest = json.loads((ROOT / 'evaluation/reports/2026-10-v3/review-2026-10-13/url_split_manifest.json').read_text())
    expected = {row['row_id']: row for row in manifest['rows']}
    rows = previous.read_dev()
    selected = rows[rows.id.isin(expected)]
    assert len(selected) == len(expected) and not selected.id.duplicated().any()
    for row in selected.itertuples():
        record = expected[row.id]
        assert hashlib.sha256(row.text.encode()).hexdigest() == record['content_sha256']
        assert row.split == record['split'] and row.label == record['label'] and row.source == record['source']


def baseline_artifact():
    """Reproduction after promotion must still compare the original artifact."""
    expected = json.loads((OUT / 'probe_before.json').read_text())['artifact_sha256']
    archived = ROOT / 'release-artifacts/prior-deployment/url_host_v3.joblib'
    deployed = ROOT / 'ml/models/url_host_v3.joblib'
    path = archived if archived.exists() else deployed
    if sha(path) != expected:
        original = subprocess.check_output(['git', 'show', 'b8bf8c2:ml/models/url_host_v3.joblib'], cwd=ROOT)
        if hashlib.sha256(original).hexdigest() != expected:
            raise ValueError('Historical baseline hash does not match the frozen probe')
        archived.parent.mkdir(parents=True, exist_ok=True)
        archived.write_bytes(original)
        path = archived
    assert sha(path) == expected
    return path


def main():
    assert (OUT / 'url_selection_rule.md').is_file()
    LOCAL.mkdir(parents=True, exist_ok=True)
    MODELS.mkdir(parents=True, exist_ok=True)
    verify_etis_rows()
    # Reuse the audited preparation code, redirecting ALL mutable outputs to v4.
    # Its protocol input remains the original frozen file, unchanged.
    previous.LOCAL = LOCAL
    previous.write = write
    cache = previous.prepare()
    fit, cal = cache['pools']['combined']
    extractor = previous.ext()
    test = cache['tests']['phreshphish_test']
    mask = (test.label_binary == 0).to_numpy() & test.host.map(lambda h: benign_subdomain(h, extractor)).to_numpy()
    cohorts = {**cache['tests'], 'phreshphish_test_benign_subdomains': test[mask].reset_index(drop=True)}
    result = {'protocol_sha256': sha(PROTOCOL), 'selection_rule_sha256': sha(OUT / 'url_selection_rule.md'),
              'data_sha256': cache['data_sha256'], 'libraries': libraries(),
              'deployment_operating_point': '0_1pct', 'models': {},
              'sealed_test_run': False, 'genuine_egyptian_sms_test_count': 0,
              'subset_definition': 'Benign official test rows with any non-www private-PSL subdomain label',
              'subset_n': int(mask.sum()), 'test_unparseable_hosts': int(test.host.isna().sum()),
              'warning': 'Exposed development selection, not independent final validation; PPV is a prior scenario.'}
    current_path = baseline_artifact()
    current = joblib.load(current_path)
    artifacts = [('current_artifact', current_path, current, True)]
    for name in ['lightgbm', 'char_calibrated_svm']:
        print('FITTING combined/host_only/' + name, flush=True)
        begin = time.perf_counter()
        if name == 'lightgbm':
            vec = DictVectorizer(dtype=np.float32)
            values = [hand_features(row.url, row.host, extractor, False) for row in fit.itertuples()]
            matrix = vec.fit_transform(values)
            clf = LGBMClassifier(n_estimators=250, learning_rate=.05, num_leaves=31,
                                 class_weight='balanced', random_state=42, n_jobs=2, verbosity=-1)
            del values
        else:
            vec = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), min_df=2,
                                  max_features=50000, sublinear_tf=True, dtype=np.float32)
            matrix = vec.fit_transform(fit.host.tolist())
            folds = list(GroupKFold(n_splits=2).split(matrix, fit.label_binary, fit.registered_domain))
            clf = CalibratedClassifierCV(LinearSVC(class_weight='balanced', random_state=42),
                                         method='sigmoid', cv=folds)
        with warnings.catch_warnings(record=True) as caught, threadpool_limits(limits=2):
            warnings.simplefilter('always', ConvergenceWarning)
            clf.fit(matrix, fit.label_binary.to_numpy())
        artifact = {'vectorizer': vec, 'classifier': clf, 'representation': 'host_only',
                    'research_feature_version': 'phresh-1', 'model': name,
                    'protocol_sha256': sha(PROTOCOL), 'data_sha256': cache['data_sha256']}
        # This happens before ANY evaluation predictions and uses calibration only.
        cp = scores(artifact, cal, extractor)
        artifact['thresholds'] = {key: threshold_at_fpr(cal.label_binary, cp, cap)
                                  for key, cap in [('1pct', .01), ('0_1pct', .001)]}
        artifact['thresholds']['medium'] = artifact['thresholds']['0_1pct']
        artifact['calibration_metrics'] = {key: at_threshold(cal.label_binary, cp, value)
                                           for key, value in artifact['thresholds'].items() if key != 'medium'}
        artifact['fit_seconds'] = time.perf_counter() - begin
        artifact['warnings'] = sorted({str(w.message) for w in caught if issubclass(w.category, ConvergenceWarning)})
        path = MODELS / (name + '.joblib')
        joblib.dump(artifact, path, compress=3)
        artifacts.append(('combined/host_only/' + name, path, artifact, False))
        del matrix
        gc.collect()
    # All fresh thresholds are frozen before evaluation of any candidate.
    for key, path, artifact, deployed in artifacts:
        thresholds = {'deployed': artifact['thresholds']['medium']} if deployed else {
            k: artifact['thresholds'][k] for k in ['1pct', '0_1pct']}
        entry = {'model_sha256': sha(path), 'artifact_path': str(path.relative_to(ROOT)).replace('\\', '/'),
                 'thresholds': thresholds, 'cohorts': {}, 'calibration': artifact.get('calibration_metrics'),
                 'fit_seconds': artifact.get('fit_seconds'), 'warnings': artifact.get('warnings', [])}
        for cohort, frame in cohorts.items():
            print('SCORING', key, cohort, flush=True)
            probability = scores(artifact, frame, extractor, deployed)
            entry['cohorts'][cohort] = {name: at_threshold(frame.label_binary, probability, threshold)
                                        for name, threshold in thresholds.items()}
            np.savez_compressed(LOCAL / (key.replace('/', '_') + '_' + cohort + '.npz'), score=probability,
                                row_id=frame.row_id.to_numpy(dtype=str))
        import pandas as pd
        probe_frame = pd.DataFrame({'url': ['https://' + host + '/' for host in HOSTS], 'host': HOSTS})
        probe_scores = scores(artifact, probe_frame, extractor, deployed)
        threshold = artifact['thresholds']['medium']
        mapping = {host: float(value) for host, value in zip(HOSTS, probe_scores)}
        def score_probe(value):
            from app.core.url_utils import parse_url
            return {'probability': mapping[parse_url(value).host], 'threshold': threshold, 'version': sha(path)[:16]}
        with patch('app.engines.risk_scoring.score_url', side_effect=score_probe):
            # probe()'s model section uses the deployed artifact; replace it below
            # so the full-scanner comparison and candidate scores cannot be confused.
            probe_result = probe()
        entry['probe'] = [{'host': row['host'], 'probability': mapping[row['host']],
                           'above_threshold': mapping[row['host']] >= threshold, 'threshold': threshold,
                           'full_scanner_verdict': row['verdict'], 'signals': row['signals']} for row in probe_result['rows']]
        entry['deployment_point'] = 'deployed' if deployed else '0_1pct'
        point = entry['deployment_point']
        entry['passes_subdomain_gate'] = entry['cohorts']['phreshphish_test_benign_subdomains'][point]['false_positive_rate'] <= .01
        result['models'][key] = entry
        write('url_comparison.json', result)
    passing = [(key, entry) for key, entry in result['models'].items() if entry['passes_subdomain_gate']]
    winner = max(passing, key=lambda item: item[1]['cohorts']['phreshphish_test'][item[1]['deployment_point']]['recall'])[0] if passing else None
    result['selection'] = {'winner': winner, 'promote_new_model': winner not in (None, 'current_artifact'),
                           'fallback_required': winner is None,
                           'tie_order': ['current_artifact', 'combined/host_only/lightgbm', 'combined/host_only/char_calibrated_svm']}
    write('url_comparison.json', result)
    print(json.dumps(result['selection']), flush=True)


if __name__ == '__main__':
    main()
