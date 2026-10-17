"""Offline v2 selection over existing artifacts; freeze calibration before scoring.

URL-only scanner evaluation uses actual non-model engine results once per row.
For these inputs MEDIUM/HIGH is exactly baseline OR unsuppressed model support;
corroboration already creates a baseline warning. Full scanner rescans verify the
factorization for every candidate, including boundary and model-only rows.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
import joblib
import numpy as np
from threadpoolctl import threadpool_limits
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.core.database import Base
from app.core.exceptions import InvalidScanInputError
from app.engines import risk_scoring
from app.engines.rule_based import domain_typosquatting_detector as brand_engine
from app.engines.url_features import url_features
from app.services.registry import populate_registry
from evaluation.phreshphish_utils import at_threshold, threshold_at_fpr, hand_features
from evaluation.run_url_review import shortcut
from evaluation.run_url_subdomains_v4 import benign_subdomain, verify_etis_rows
from evaluation.run_phreshphish import fingerprint
from evaluation.run_url_v3 import ext

OUT = ROOT / 'evaluation/reports/2026-10-v4'
LOCAL = ROOT / 'evaluation/local-results/v4-v2'
RULE = OUT / 'url_selection_rule_v2.md'
CAPS = [.01, .005, .001, .0005, .0001, 0.]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8', newline='\n')


def inventory():
    manifest = json.loads((ROOT / 'release-artifacts/MANIFEST.json').read_text())
    paths = [ROOT / r['local_path'] for r in manifest['files']
             if r['local_path'].endswith('.joblib') and
             ('/url' in r['local_path'] or '/phreshphish/' in r['local_path'])]
    paths += list((ROOT / 'release-artifacts/v4').glob('*.joblib'))
    paths += list((ROOT / 'release-artifacts/prior-deployment').glob('*.joblib'))
    # v1 source stays stable even after the runtime artifact is replaced.
    paths += [ROOT / 'release-artifacts/v4/char_calibrated_svm.joblib']
    unique = {}
    for path in sorted(set(paths)):
        digest = sha(path)
        original = next((r for r in manifest['files'] if ROOT / r['local_path'] == path), None)
        if original:
            assert digest == original['sha256'], path
        if digest in unique:
            unique[digest]['aliases'].append(path.relative_to(ROOT).as_posix())
            continue
        text = path.as_posix()
        pp = '/phreshphish/' in text or '/release-artifacts/v4/' in text
        representation = 'shortcut_only' if 'shortcut_only' in text else 'full_url' if 'full_url' in text else 'host_only'
        setting = path.name.split('_')[0] if '/phreshphish/' in text else 'combined' if '/release-artifacts/v4/' in text else 'historical'
        unique[digest] = {'path': path.relative_to(ROOT).as_posix(), 'sha256': digest,
                          'aliases': [], 'phresh_schema': pp, 'setting': setting,
                          'representation': representation,
                          'calibration_pool': setting if pp else 'phreshphish_excluding_all_etis_train_domains',
                          'historical_training_exposure': not pp}
    v1 = sha(ROOT / 'release-artifacts/v4/char_calibrated_svm.joblib')
    unique[v1]['aliases'].append('ml/models/url_host_v3.joblib (v1 snapshot)')
    return list(unique.values())


def predict(artifact, record, frame, extractor):
    output = np.full(len(frame), np.nan)
    valid = np.flatnonzero(frame.host.notna().to_numpy())
    for offset in range(0, len(valid), 4096):
        indices = valid[offset:offset + 4096]
        rows = frame.iloc[indices]
        # Match the scanner's outer-whitespace normalization; row IDs and
        # cohort membership are unchanged (calibration has no such rows).
        rows = rows.assign(url=rows.url.str.strip())
        column = 'url' if record['representation'] == 'full_url' else 'host'
        if 'pipeline' in artifact:
            values = rows[column].tolist()
            classifier = artifact['pipeline']
        else:
            classifier = artifact['classifier']
            # Character research models also use vectorizer/classifier keys.
            if artifact['vectorizer'].__class__.__name__ != 'DictVectorizer':
                values = rows[column].tolist()
            elif record['phresh_schema']:
                values = [hand_features(r.url, r.host, extractor, column == 'url') for r in rows.itertuples()]
            else:
                values, kept = [], []
                for idx, row in zip(indices, rows.itertuples()):
                    try:
                        value = shortcut(row.url) if record['representation'] == 'shortcut_only' else url_features(getattr(row, column), extractor)
                    except InvalidScanInputError:
                        continue
                    values.append(value)
                    kept.append(idx)
                indices = np.asarray(kept, dtype=int)
            if not len(indices):
                continue
            values = artifact['vectorizer'].transform(values)
        output[indices] = classifier.predict_proba(values)[:, 1]
    return output


def data():
    verify_etis_rows()
    protocol = ROOT / 'evaluation/reports/2026-10-v3/phreshphish/protocol.json'
    prepared = ROOT / 'evaluation/local-results/v4/prepared.joblib'
    if not prepared.exists():
        prepared = LOCAL / 'prepared.joblib'
    if prepared.exists():
        cache = joblib.load(prepared)
    else:
        from evaluation import run_phreshphish as preparation
        from evaluation.phreshphish_utils import target_key
        original = json.loads(protocol.read_text())
        preparation.LOCAL = LOCAL
        preparation.write = lambda name, value: write(OUT / ('v2_' + name), value)
        preparation.brand_match = lambda target: original['strict_target_aliases'].get(target_key(target))
        cache = preparation.prepare()
    lock = json.loads((ROOT / 'data/phreshphish-lock.json').read_text())
    assert cache['protocol_sha256'] == sha(protocol)
    assert cache['data_sha256'] == lock['data_sha256']
    audit = json.loads((OUT / 'data_audit.json').read_text())
    for setting, (fit, cal) in cache['pools'].items():
        assert fingerprint(fit) == audit['settings'][setting]['fit_sha256']
        assert fingerprint(cal) == audit['settings'][setting]['calibration_sha256']
    return cache


def calibrate():
    assert RULE.is_file()
    LOCAL.mkdir(parents=True, exist_ok=True)
    cache = data()
    extractor = ext()
    records = inventory()
    # Legacy artifacts fitted ETIS training, so use only external calibration
    # domains absent from every ETIS training URL, including excluded rows.
    from evaluation.run_url_v3 import read_dev, domain
    from evaluation.phreshphish_utils import host_of
    training = read_dev().query("split == 'train'")
    etis_domains = {domain(h, extractor) for h in training.text.map(host_of).dropna()}
    # Early v3 artifacts additionally fitted the archived PY35J Tranco list.
    # Conservatively remove its entire domain list, regardless of old partition.
    from evaluation.run_url_v3 import TRANCO
    tranco_domains = {domain(line.strip().split(',')[-1].lower().rstrip('.'), extractor)
                      for line in TRANCO.read_text(encoding='utf-8-sig').splitlines() if line.strip()}
    etis_domains |= tranco_domains
    historical = cache['pools']['phreshphish'][1]
    historical = historical[~historical.registered_domain.isin(etis_domains)].reset_index(drop=True)
    prior_path = OUT / 'url_v2_frozen_thresholds.json'
    prior = json.loads(prior_path.read_text()) if prior_path.exists() else None
    if prior:
        assert prior['rule_sha256'] == sha(RULE)
    for record in records:
        print('CALIBRATE', record['path'], flush=True)
        path = ROOT / record['path']
        artifact = joblib.load(path)
        cal = historical if record['setting'] == 'historical' else cache['pools'][record['setting']][1]
        prior_record = next((r for r in prior['models'] if r['sha256'] == record['sha256']) , None) if prior else None
        if prior_record and prior_record['calibration_fingerprint'] == fingerprint(cal):
            record.update(prior_record)
            continue
        assert not cal.official_split.eq('test').any()
        held = set().union(*(set(f.registered_domain) for f in cache['tests'].values()))
        assert set(cal.registered_domain).isdisjoint(held)
        probabilities = predict(artifact, record, cal, extractor)
        thresholds = {}
        for cap in CAPS:
            threshold = threshold_at_fpr(cal.label_binary, probabilities, cap)
            if threshold not in thresholds:
                thresholds[threshold] = {'threshold': threshold, 'calibration_fpr_caps': []}
            thresholds[threshold]['calibration_fpr_caps'].append(cap)
        record['thresholds'] = list(thresholds.values())
        record['calibration_rows'] = len(cal)
        record['calibration_fingerprint'] = fingerprint(cal)
        record['calibration_metrics'] = [at_threshold(cal.label_binary, probabilities, t['threshold']) for t in record['thresholds']]
    result = {'created_at': datetime.now(timezone.utc).isoformat(), 'rule_sha256': sha(RULE),
              'protocol_sha256': cache['protocol_sha256'], 'data_sha256': cache['data_sha256'],
              'historical_calibration_excludes_entire_archived_tranco_list': True,
              'thresholds_use_evaluation_scores': False, 'models': records}
    write(OUT / 'url_v2_frozen_thresholds.json', result)
    print('FROZEN', len(records), 'models', sum(len(r['thresholds']) for r in records), 'candidates', flush=True)


def isolated():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    return engine


def verify_acceleration(frames):
    """Check exact unit-cost distance against the production DP implementation."""
    from rapidfuzz.distance import Levenshtein
    from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS
    original = brand_engine.calculate_levenshtein_distance
    hosts = list(dict.fromkeys(h for frame in frames.values() for h in frame.host.dropna()))
    chosen = np.random.default_rng(42).choice(len(hosts), size=min(250, len(hosts)), replace=False)
    checked = 0
    for idx in chosen:
        for _, domain in EGYPTIAN_BRAND_DOMAINS:
            assert original(hosts[idx], domain) == Levenshtein.distance(hosts[idx], domain)
            checked += 1
    for a, b in [('', ''), ('', 'abc'), ('abc', ''), ('same', 'same'), ('café', 'cafe'), ('أهلا', 'اهلا')]:
        assert original(a, b) == Levenshtein.distance(a, b)
        checked += 1
    return {'library': 'rapidfuzz==3.14.6', 'function': 'distance.Levenshtein.distance',
            'weights': [1, 1, 1], 'processor': None, 'cutoff': None,
            'original_distance_equivalence_pairs': checked,
            'source': 'https://rapidfuzz.github.io/RapidFuzz/Usage/distance/Levenshtein.html',
            'runtime_implementation_changed': False}


def baseline(frame, db):
    base, eligible, corroborates, valid = [], [], [], []
    counts = Counter()
    benign_reasons, benign_signals = Counter(), Counter()
    for index, row in enumerate(frame.itertuples()):
        try:
            scan = risk_scoring.calculate_final_risk_score(url=row.url, db=db)
            link = scan['checked_links'][0]
            base.append(scan['verdict'] in {'MEDIUM', 'HIGH'})
            eligible.append(not link['verified_official_host'] and not link['shared_hosting_domain'])
            corroborates.append(bool(link['brand']['score'] or link['patterns'] or link['blacklist']['match_type'] == 'domain'))
            valid.append(True)
            counts[scan['verdict']] += 1
            if row.label_binary == 0 and scan['verdict'] in {'MEDIUM', 'HIGH'}:
                benign_reasons[scan['decisive_reason']] += 1
                benign_signals.update(scan['supporting_signals'])
        except InvalidScanInputError:
            base.append(False)
            eligible.append(False)
            corroborates.append(False)
            valid.append(False)
            counts['INVALID_INPUT'] += 1
        if (index + 1) % 10000 == 0:
            print('SCANNER BASELINE', index + 1, '/', len(frame), flush=True)
    return {'base': np.array(base), 'eligible': np.array(eligible), 'corroborates': np.array(corroborates),
            'valid': np.array(valid), 'verdict_counts': dict(counts),
            'benign_alert_reasons': dict(benign_reasons), 'benign_alert_signals': dict(benign_signals)}


def metrics(frame, flags):
    return at_threshold(frame.label_binary, np.asarray(flags, dtype=float), .5)


def passes(cohorts, key):
    return (cohorts['phreshphish_test_benign_subdomains'][key]['false_positive_rate'] <= .01
            and cohorts['etis_grouped_validation'][key]['false_positive_rate'] <= .005
            and cohorts['phreshphish_test'][key]['false_positive_rate'] <= .005)


def sort_key(candidate, kind='model'):
    c = candidate['cohorts']
    return (-c['phreshphish_test'][kind]['recall'],
            c['etis_grouped_validation'][kind]['false_positive_rate'],
            c['phreshphish_test'][kind]['false_positive_rate'], candidate['artifact_path'], candidate['threshold'])


def evaluate():
    frozen = json.loads((OUT / 'url_v2_frozen_thresholds.json').read_text())
    assert frozen['rule_sha256'] == sha(RULE)
    cache = data()
    extractor = ext()
    cohorts = cache['tests']
    test = cohorts['phreshphish_test']
    subset = (test.label_binary.eq(0) & test.host.map(lambda h: benign_subdomain(h, extractor))).to_numpy()
    cohorts['phreshphish_test_benign_subdomains'] = test[subset].reset_index(drop=True)
    report = {'rule_sha256': sha(RULE), 'frozen_thresholds_sha256': sha(OUT / 'url_v2_frozen_thresholds.json'),
              'protocol_sha256': cache['protocol_sha256'], 'data_sha256': cache['data_sha256'],
              'created_at': datetime.now(timezone.utc).isoformat(), 'candidates': [], 'comparators': {},
              'method': 'Actual URL-only scanner baseline on every original row; exact Boolean factoring of model support with full-scanner equivalence rescans for every candidate.',
              'blacklist': 'isolated empty in-memory SQLite, health forced available; no live feed or database',
              'input': 'original corpus URL in url field, no text or sender context; invalid/overlength runtime inputs count as misses',
              'destination_requests': 0, 'sealed_test_run': False, 'genuine_egyptian_sms_test_count': 0}
    report['evaluation_acceleration'] = verify_acceleration(cache['tests'])
    from rapidfuzz.distance import Levenshtein
    original_distance = brand_engine.calculate_levenshtein_distance
    brand_engine.calculate_levenshtein_distance = Levenshtein.distance
    engine = isolated()
    try:
        with Session(engine) as db, patch.object(risk_scoring, 'blacklist_health', return_value={'available': True, 'reason': None}):
            populate_registry(db)
            baselines = {}
            for name, frame in cache['tests'].items():
                if name == 'phreshphish_test_benign_subdomains':
                    continue
                location = LOCAL / (name + '_scanner.joblib')
                source = sha(ROOT / 'backend/app/engines/risk_scoring.py') + sha(ROOT / 'backend/app/core/egyptian_brands.py')
                identity = source + fingerprint(frame)
                if location.exists() and joblib.load(location)['identity'] == identity:
                    b = joblib.load(location)['baseline']
                else:
                    with patch.object(risk_scoring, 'score_url', return_value=None):
                        b = baseline(frame, db)
                    joblib.dump({'identity': identity, 'baseline': b}, location, compress=3)
                baselines[name] = b
                report.setdefault('scanner_baseline', {})[name] = {'metrics': metrics(frame, b['base']), 'verdict_counts': b['verdict_counts'],
                    'benign_alert_reasons': b['benign_alert_reasons'], 'benign_alert_signals': b['benign_alert_signals']}
            b = baselines['phreshphish_test']
            baselines['phreshphish_test_benign_subdomains'] = {k: v[subset] for k, v in b.items() if isinstance(v, np.ndarray)}
            for record in frozen['models']:
                path = ROOT / record['path']
                assert sha(path) == record['sha256']
                print('EVALUATE', record['path'], flush=True)
                artifact = joblib.load(path)
                probabilities = {}
                for name, frame in cohorts.items():
                    if name == 'phreshphish_test_benign_subdomains':
                        probabilities[name] = probabilities['phreshphish_test'][subset]
                        continue
                    probabilities[name] = predict(artifact, record, frame, extractor)
                    np.savez_compressed(LOCAL / (record['sha256'] + '_' + name + '.npz'),
                                        score=probabilities[name], row_id=frame.row_id.to_numpy(dtype=str))
                points = [(t, None) for t in record['thresholds']]
                if record['path'] == 'release-artifacts/prior-deployment/url_host_v3.joblib':
                    points.append(({'threshold': artifact['thresholds']['medium']}, 'old_v3_deployed'))
                if record['path'] == 'release-artifacts/v4/char_calibrated_svm.joblib':
                    points.append(({'threshold': artifact['thresholds']['medium']}, 'v1_selected'))
                for point, comparator in points:
                    t = point['threshold']
                    candidate = {'artifact_path': record['path'], 'artifact_sha256': record['sha256'],
                                 'representation': record['representation'], 'phresh_schema': record['phresh_schema'],
                                 'threshold': t, 'calibration_fpr_caps': point.get('calibration_fpr_caps'), 'cohorts': {}}
                    verified = 0
                    for name, frame in cohorts.items():
                        b, p = baselines[name], probabilities[name]
                        above = np.isfinite(p) & (p >= t)
                        ordinary = b['base'] | (b['valid'] & b['eligible'] & above)
                        corroboration = b['base'] | (b['valid'] & b['eligible'] & above & b['corroborates'])
                        candidate['cohorts'][name] = {'model': at_threshold(frame.label_binary, p, t),
                                                     'ordinary': metrics(frame, ordinary),
                                                     'corroboration_only': metrics(frame, corroboration)}
                        if name.endswith('benign_subdomains'):
                            continue
                        # Boundary, model-only, positive, negative and invalid rows.
                        choices = np.unique(np.concatenate([np.arange(min(5, len(frame))),
                            np.flatnonzero(above & ~b['base'])[:5], np.flatnonzero(b['base'])[:5],
                            np.flatnonzero(~b['valid'])[:3], np.argsort(np.abs(p - t))[:5]]))
                        for idx in choices:
                            response = {'probability': float(p[idx]), 'threshold': t} if np.isfinite(p[idx]) else None
                            for policy, expected in [('ordinary', ordinary), ('corroboration_only', corroboration)]:
                                with patch.object(risk_scoring, 'score_url', return_value=response), patch.object(risk_scoring, 'URL_MODEL_POLICY', policy):
                                    try:
                                        scan = risk_scoring.calculate_final_risk_score(url=frame.iloc[idx].url, db=db)
                                        actual = scan['verdict'] in {'MEDIUM', 'HIGH'}
                                    except InvalidScanInputError:
                                        actual = False
                                assert actual == bool(expected[idx]), (record['path'], name, idx, policy)
                                verified += 1
                    candidate['full_scanner_equivalence_checks'] = verified
                    candidate['passes_model_v2'] = passes(candidate['cohorts'], 'model')
                    candidate['passes_integrated_v2'] = passes(candidate['cohorts'], 'ordinary')
                    candidate['passes_corroboration_v2'] = passes(candidate['cohorts'], 'corroboration_only')
                    if comparator:
                        report['comparators'][comparator] = candidate
                    else:
                        report['candidates'].append(candidate)
                if record['path'] == 'release-artifacts/v4/char_calibrated_svm.joblib':
                    frame = cohorts['etis_grouped_validation']
                    p = probabilities['etis_grouped_validation']
                    t = artifact['thresholds']['medium']
                    flags = frame.label_binary.eq(0).to_numpy() & np.isfinite(p) & (p >= t)
                    assert int(flags.sum()) == 78, 'v1 ETIS false-positive count must reproduce'
                    rows = [{'row_id': str(r.row_id), 'domain': r.host, 'registered_domain': r.registered_domain,
                             'probability': float(p[i]), 'threshold': t} for i, r in enumerate(frame.itertuples()) if flags[i]]
                    write(OUT / 'v1_etis_validation_benign_flags.json', {'model_sha256': record['sha256'], 'threshold': t,
                          'benign_n': int(frame.label_binary.eq(0).sum()), 'flagged_rows': len(rows),
                          'unique_domains': len({r['domain'] for r in rows}), 'destination_requests': 0, 'rows': rows})
                write(OUT / 'url_v2_comparison.json', report)
    finally:
        engine.dispose()
        brand_engine.calculate_levenshtein_distance = original_distance
    candidates = report['candidates']
    model_pass = [c for c in candidates if c['passes_model_v2']]
    ordinary_pass = [c for c in model_pass if c['passes_integrated_v2']]
    corroboration_pass = [c for c in candidates if c['passes_corroboration_v2']]
    best = min(model_pass, key=sort_key) if model_pass else None
    if ordinary_pass:
        deployed = min(ordinary_pass, key=sort_key)
        policy = 'ordinary'
    else:
        pool = corroboration_pass or candidates
        def fallback_key(c):
            cc = c['cohorts']
            return (-cc['phreshphish_test']['corroboration_only']['recall'],
                    sum(cc[n]['corroboration_only']['false_positive_rate'] for n in ['phreshphish_test', 'etis_grouped_validation']),
                    c['artifact_path'], c['threshold'])
        deployed = min(pool, key=fallback_key)
        policy = 'corroboration_only'
    report['selection'] = {'model_passing_candidates': len(model_pass), 'ordinary_passing_candidates': len(ordinary_pass),
                           'corroboration_passing_candidates': len(corroboration_pass), 'best_v2_model': best,
                           'deployed_candidate': deployed, 'deployed_policy': policy}
    write(OUT / 'url_v2_comparison.json', report)
    print(json.dumps({'policy': policy, 'model_pass': len(model_pass), 'ordinary_pass': len(ordinary_pass),
                      'corroboration_pass': len(corroboration_pass), 'deployed': deployed['artifact_path'], 'threshold': deployed['threshold']}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['calibrate', 'evaluate'])
    args = parser.parse_args()
    with threadpool_limits(limits=2):
        (calibrate if args.stage == 'calibrate' else evaluate)()
