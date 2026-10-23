"""Execute the unchanged v4 rule offline; calibration is a separate freeze stage.

Only aggregate evidence is published. Prepared URL/label frames and predictions
stay local. No HTML, destination requests, model fitting, or sealed test access.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
import joblib
import numpy as np
import pandas as pd
from threadpoolctl import threadpool_limits
from evaluation import run_url_selection_v2 as v2
from evaluation import run_url_followup_v3 as v3
from evaluation.phreshphish_utils import at_threshold, threshold_at_fpr, host_of
from evaluation.run_phreshphish import fingerprint
from evaluation.run_url_v3 import ext, read_dev, domain, TRANCO
from evaluation.probe_query_shortcut import HOSTS as QUERY_HOSTS, VARIANTS
from evaluation.probe_legit_hosts import HOSTS

OUT = v2.OUT
LOCAL = ROOT / 'evaluation/local-results/v4-selection'
RULE = OUT / 'url_selection_rule_v4.md'
FROZEN = OUT / 'url_v4_frozen_thresholds.json'
LOCK = OUT / 'url_v4_frozen_thresholds.sha256'
V2_HASH = 'cc85a74db40f420daf2414efdbfe255891e64302933d00caf13bcab13496e7ca'
PREPROCESSOR = 'remove first # and everything after it, then first ? and everything after it; preserve every remaining character'
PREPROCESSOR_HASH = hashlib.sha256(PREPROCESSOR.encode()).hexdigest()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    v2.write(path, value)


def stripped(value):
    return str(value).split('#', 1)[0].split('?', 1)[0]


def calibration_pools(data, extractor):
    training = read_dev().query("split == 'train'")
    excluded = {domain(h, extractor) for h in training.text.map(host_of).dropna()}
    excluded |= {domain(line.strip().split(',')[-1].lower().rstrip('.'), extractor)
                 for line in TRANCO.read_text(encoding='utf-8-sig').splitlines() if line.strip()}
    historical = data['pools']['phreshphish'][1]
    historical = historical[~historical.registered_domain.isin(excluded)].reset_index(drop=True)
    return {**{s: p[1] for s, p in data['pools'].items()}, 'historical': historical}


def load_inputs():
    assert (ROOT / 'evaluation/local-results/v4/prepared.joblib').is_file(), 'Restore the original prepared URL-only cache; do not rebuild frozen pools here'
    assert sha(OUT / 'url_v2_frozen_thresholds.json') == V2_HASH
    # The unchanged rule prints a 63-character digest (one missing 'e'). Pin
    # the actual a80e790 audit bytes and disclose the transcription discrepancy.
    assert sha(OUT / 'query-shortcut/query-fragment-counts.json') == 'b248342ee2357e36bfff43059a71d2708f5e17480a682c7edeeedc5fa1370d06'
    assert sha(ROOT / 'evaluation/probe_query_shortcut.py') == 'd5b385111e83b433f43ccf53ac9d877cf9aab168440530c9bc36378e602b4f86'
    assert sha(ROOT / 'evaluation/probe_legit_hosts.py') == '0542f04ff6c442f1cfa424b60f4be09321eb30f6f5f22a477aecdca101463a95'
    data = v2.data()
    extractor = ext()
    return data, extractor, calibration_pools(data, extractor)


def transform(frame, record, variant='O'):
    result = frame.copy()
    if variant != 'O':
        result['url'] = result.url.map(stripped)
        if variant == 'N':
            result['url'] += '?utm_source=sms'
    if record['input_mode'] == 'host_path':
        result['url'] = result.url.map(stripped)
    # host and row membership are intentionally retained. Query/fragment removal
    # cannot alter the original authority; original abstentions are preserved.
    return result


def predict(artifact, record, frame, extractor, variant='O'):
    transformed = transform(frame, record, variant)
    return v2.predict(artifact, record, transformed, extractor)


def freeze():
    if FROZEN.exists() or LOCK.exists():
        raise RuntimeError('v4 inventory already frozen; do not recalibrate after evaluation')
    rule_hash = sha(RULE)
    data, extractor, pools = load_inputs()
    prior = json.loads((OUT / 'url_v2_frozen_thresholds.json').read_text())
    records = []
    LOCAL.mkdir(parents=True, exist_ok=True)
    for source in prior['models']:
        assert sha(ROOT / source['path']) == source['sha256']
        cal = pools[source['setting']]
        assert fingerprint(cal) == source['calibration_fingerprint']
        assert len(cal) == source['calibration_rows']
        assert not cal.official_split.eq('test').any()
        original = deepcopy(source)
        original.update(input_mode='original', preprocessing='identity', preprocessing_sha256=hashlib.sha256(b'identity').hexdigest())
        records.append(original)
        if source['representation'] != 'full_url':
            continue
        record = deepcopy(source)
        record.update(input_mode='host_path', preprocessing=PREPROCESSOR, preprocessing_sha256=PREPROCESSOR_HASH)
        artifact = joblib.load(ROOT / source['path'])
        print('CALIBRATION ONLY', source['path'], flush=True)
        p = predict(artifact, record, cal, extractor)
        thresholds = {}
        for cap in v2.CAPS:
            t = threshold_at_fpr(cal.label_binary, p, cap)
            thresholds.setdefault(t, {'threshold': t, 'calibration_fpr_caps': []})['calibration_fpr_caps'].append(cap)
        record.update(thresholds=list(thresholds.values()),
                      calibration_metrics=[at_threshold(cal.label_binary, p, t) for t in thresholds],
                      transformed_calibration_fingerprint=fingerprint(transform(cal, record)),
                      calibration_row_membership_sha256=hashlib.sha256('\n'.join(cal.row_id).encode()).hexdigest(),
                      threshold_derivation='evaluation.phreshphish_utils.threshold_at_fpr; original calibration pool and exclusions; no evaluation predictions',
                      fitting_exposure='unchanged full-URL fitted weights/schema; not trained on stripped inputs')
        records.append(record)
        np.savez_compressed(LOCAL / (source['sha256'] + '_host_path_cal.npz'), score=p, row_id=cal.row_id.to_numpy(dtype=str))
    assert sha(RULE) == rule_hash
    result = dict(created_at=datetime.now(timezone.utc).isoformat(), rule_sha256=rule_hash,
                  v2_inventory_sha256=V2_HASH, protocol_sha256=data['protocol_sha256'], data_sha256=data['data_sha256'],
                  prepared_cache_sha256=sha(ROOT / 'evaluation/local-results/v4/prepared.joblib'),
                  thresholds_use_evaluation_scores=False, model_weights_fitted=False,
                  coverage_audit_hash_discrepancy={'rule_literal': 'b248342ee2357e36bfff43059a71d2708f5e17480a682c7edeedc5fa1370d06',
                      'actual_unchanged_a80e790_bytes': sha(OUT / 'query-shortcut/query-fragment-counts.json'),
                      'rule_amended': False},
                  registry_sha256=sha(ROOT / 'backend/app/core/egyptian_brands.py'),
                  pattern_policy='four_structural_only', models=records)
    write(FROZEN, result)
    LOCK.write_text(sha(FROZEN) + '\n', encoding='ascii')
    print('FROZEN BEFORE EVALUATION', sha(FROZEN), len(records), sum(len(r['thresholds']) for r in records), flush=True)


def frozen():
    assert sha(FROZEN) == LOCK.read_text().strip()
    result = json.loads(FROZEN.read_text())
    assert result['rule_sha256'] == sha(RULE)
    assert result['v2_inventory_sha256'] == sha(OUT / 'url_v2_frozen_thresholds.json') == V2_HASH
    assert result['registry_sha256'] == sha(ROOT / 'backend/app/core/egyptian_brands.py')
    assert result['prepared_cache_sha256'] == sha(ROOT / 'evaluation/local-results/v4/prepared.joblib')
    return result


def components(frame):
    groups = {key: np.zeros(len(frame), dtype=bool) for key in ['query_present', 'query_absent', 'fragment_present', 'fragment_absent', 'both_present', 'parse_failures']}
    for i, value in enumerate(frame.url):
        try:
            parsed = urlsplit(value if '://' in value else 'http://' + value)
        except ValueError:
            groups['parse_failures'][i] = True
            continue
        q, f = bool(parsed.query), bool(parsed.fragment)
        groups['query_present' if q else 'query_absent'][i] = True
        groups['fragment_present' if f else 'fragment_absent'][i] = True
        groups['both_present'][i] = q and f
    return groups


def coverage(frame, groups):
    return {label: {**{'total': int((frame.label_binary == y).sum())},
                    **{k: int((mask & frame.label_binary.eq(y).to_numpy()).sum()) for k, mask in groups.items()}}
            for y, label in [(0, 'benign'), (1, 'phishing')]}


def invariance(frame, scores, t):
    alerts = {v: np.isfinite(p) & (p >= t) for v, p in scores.items()}
    counts = {v: int(a.sum()) for v, a in alerts.items()}
    abstentions = {v: int((~np.isfinite(p)).sum()) for v, p in scores.items()}
    extra = {v: int((np.isfinite(scores['O']) & ~np.isfinite(p)).sum()) for v, p in scores.items() if v != 'O'}
    comparisons = {}
    n = len(frame)
    for v, b in [('O', 'S'), ('N', 'S'), ('S', 'O'), ('N', 'O')]:
        delta = counts[v] - counts[b]
        comparisons[v + '-' + b] = dict(alert_delta=delta, delta_percentage_points=100 * delta / n if n else None,
            exact_200_times_delta=200 * delta, passes=bool(n and 200 * delta <= n),
            newly_alerting=int((alerts[v] & ~alerts[b]).sum()), no_longer_alerting=int((~alerts[v] & alerts[b]).sum()))
    return dict(n=n, cohort_fingerprint=fingerprint(frame), alerts=counts, abstentions=abstentions,
                additional_scoring_failures=extra, comparisons=comparisons,
                passes=bool(n and not any(extra.values()) and all(c['passes'] for c in comparisons.values())))


def measurement(frame, p, t, b, mask):
    frame = frame.loc[mask]
    p = p[mask]
    c = {k: v[mask] for k, v in b.items() if isinstance(v, np.ndarray)}
    baseline = c['valid'] & (c['brand'] | v3.pattern_alerts(c['bits'], 'four_structural_only'))
    raw = np.isfinite(p) & (p >= t)
    ordinary = baseline | (c['eligible'] & raw)
    def scanner(alerts):
        m = at_threshold(frame.label_binary, np.where(c['valid'], alerts.astype(float), np.nan), .5)
        non_model = int((baseline & frame.label_binary.eq(0).to_numpy()).sum())
        return dict(tp=m['tp'], phishing_n=m['phishing_n'], recall=m['recall'], total_fp=m['fp'], benign_n=m['benign_n'],
                    non_model_fp=non_model, model_added_fp=m['fp'] - non_model,
                    model_added_fpr=(m['fp'] - non_model) / m['benign_n'] if m['benign_n'] else None,
                    total_fpr=m['false_positive_rate'], abstentions=m['abstentions'])
    return dict(model=at_threshold(frame.label_binary, p, t), ordinary=scanner(ordinary),
                corroboration_only=scanner(baseline), no_model=scanner(baseline),
                distinct_registered_domains=int(frame.loc[frame.registered_domain.ne(''), 'registered_domain'].nunique()),
                scorable_registered_domains=int(frame.loc[np.isfinite(p) & frame.registered_domain.ne('').to_numpy(), 'registered_domain'].nunique()),
                scorable_n=int(np.isfinite(p).sum()), n=len(frame))


def evaluate():
    inventory = frozen()
    data, extractor, pools = load_inputs()
    assert data['data_sha256'] == inventory['data_sha256']
    assert data['protocol_sha256'] == inventory['protocol_sha256']
    frames = data['tests']
    groups = {n: components(f) for n, f in frames.items()}
    test = frames['phreshphish_test']
    subdomains = test.label_binary.eq(0).to_numpy() & test.host.map(lambda h: v2.benign_subdomain(h, extractor)).to_numpy()
    baselines = {}
    for name, frame in frames.items():
        b = dict(np.load(v3.LOCAL / (name + '_components.npz')))
        assert np.array_equal(b['row_id'], frame.row_id.to_numpy(dtype=str))
        baselines[name] = b
    probes = {}
    for name, urls in [('query_path_88', ['https://' + h + suffix for h in QUERY_HOSTS for suffix in VARIANTS.values()]),
                       ('legitimate_hosts_17', ['https://' + h + '/' for h in HOSTS])]:
        frame = pd.DataFrame(dict(url=urls, row_id=[name + ':' + str(i) for i in range(len(urls))], label_binary=0))
        frame['host'] = frame.url.map(host_of)
        frame['registered_domain'] = frame.host.map(lambda h: domain(h, extractor))
        probes[name] = frame
    report = dict(rule_sha256=sha(RULE), frozen_thresholds_sha256=sha(FROZEN), v2_inventory_sha256=V2_HASH,
        data_sha256=data['data_sha256'], protocol_sha256=data['protocol_sha256'],
        created_at=datetime.now(timezone.utc).isoformat(), candidates=[],
        method='Original cohort membership; frozen production registry/four_structural_only; URL-only Boolean factoring of original full-URL non-model components; healthy empty blacklist',
        destination_requests=0, html_access=False, sealed_test_run=False, genuine_egyptian_sms_test_count=0,
        coverage={n: coverage(f, groups[n]) for n, f in frames.items()},
        pool_coverage=json.loads((OUT / 'query-shortcut/query-fragment-counts.json').read_text()),
        historical_comparators=json.loads((OUT / 'url_v3_final_selection.json').read_text())['stages']['four_structural_only']['comparisons'])
    for record in inventory['models']:
        print('EVALUATE', record['input_mode'], record['path'], flush=True)
        assert sha(ROOT / record['path']) == record['sha256']
        artifact = joblib.load(ROOT / record['path'])
        identity = record['sha256'] + '_' + record['input_mode']
        predictions = {n: predict(artifact, record, f, extractor) for n, f in frames.items()}
        cal = pools[record['setting']]
        assert fingerprint(cal) == record['calibration_fingerprint']
        benign = {'calibration_negative': cal[cal.label_binary.eq(0)].reset_index(drop=True),
                  **{n: f[f.label_binary.eq(0)].reset_index(drop=True) for n, f in frames.items()}, **probes}
        variants = {n: {v: predict(artifact, record, f, extractor, v) for v in ['O', 'S', 'N']} for n, f in benign.items()}
        if record['input_mode'] == 'host_path':
            saved = np.load(LOCAL / (record['sha256'] + '_host_path_cal.npz'))
            assert np.array_equal(saved['row_id'], cal.row_id.to_numpy(dtype=str))
            parity = predict(artifact, record, cal, extractor)
            assert np.array_equal(saved['score'], parity, equal_nan=True)
        for name, p in predictions.items():
            np.savez_compressed(LOCAL / (identity + '_' + name + '.npz'), score=p, row_id=frames[name].row_id.to_numpy(dtype=str))
        for name, scores in variants.items():
            np.savez_compressed(LOCAL / (identity + '_invariance_' + name + '.npz'), **scores, row_id=benign[name].row_id.to_numpy(dtype=str))
        for point in record['thresholds']:
            t = point['threshold']
            candidate = dict(artifact_path=record['path'], artifact_sha256=record['sha256'], input_mode=record['input_mode'],
                preprocessing_sha256=record['preprocessing_sha256'], representation=record['representation'], phresh_schema=record['phresh_schema'],
                threshold=t, calibration_fpr_caps=point['calibration_fpr_caps'], rule_sha256=sha(RULE), cohorts={},
                query_invariance={n: invariance(benign[n], s, t) for n, s in variants.items()})
            for name, frame in frames.items():
                masks = {'overall': np.ones(len(frame), dtype=bool), **groups[name]}
                if name == 'phreshphish_test':
                    masks['benign_subdomains'] = subdomains
                candidate['cohorts'][name] = {k: measurement(frame, predictions[name], t, baselines[name], m) for k, m in masks.items()}
            pp = candidate['cohorts']['phreshphish_test']
            et = candidate['cohorts']['etis_grouped_validation']['overall']
            candidate['v3_gates'] = dict(phreshphish_benign_subdomain=pp['benign_subdomains']['model']['false_positive_rate'] <= .01,
                etis_raw=et['model']['false_positive_rate'] <= .005, phreshphish_raw=pp['overall']['model']['false_positive_rate'] <= .005,
                phreshphish_incremental=pp['overall']['ordinary']['model_added_fpr'] <= .005, etis_incremental=et['ordinary']['model_added_fpr'] <= .005)
            candidate['passes_v3'] = all(candidate['v3_gates'].values())
            candidate['passes_query_invariance'] = all(i['passes'] for i in candidate['query_invariance'].values())
            candidate['primary_eligible'] = candidate['passes_v3'] and candidate['passes_query_invariance']
            candidate['id'] = hashlib.sha256((identity + ':' + repr(t)).encode()).hexdigest()[:20]
            report['candidates'].append(candidate)
        frozen()
        write(OUT / 'url_v4_comparison.json', report)
    def key(c):
        pp = c['cohorts']['phreshphish_test']['overall']['ordinary']
        et = c['cohorts']['etis_grouped_validation']['overall']['ordinary']
        return (-pp['recall'], et['model_added_fp'], pp['model_added_fp'], c['artifact_path'], c['threshold'], c['input_mode'])
    primary = sorted([c for c in report['candidates'] if c['primary_eligible']], key=key)
    host = sorted([c for c in report['candidates'] if c['input_mode'] == 'original' and c['representation'] == 'host_only' and c['passes_v3']], key=key)
    report['selection'] = dict(primary_passing=len(primary), host_only_v3_passing=len(host),
        tier='primary' if primary else 'host_only' if host else 'corroboration_only',
        selected_id=(primary or host)[0]['id'] if primary or host else None,
        engineering_completion_pending=True)
    frozen()
    write(OUT / 'url_v4_comparison.json', report)
    print(json.dumps(report['selection']), flush=True)


def finalize_reporting():
    """Exclude the empty unknown-domain sentinel from domain *counts* only.

    This reporting correction does not rescore, select thresholds, alter gates,
    or rerank candidates. The paired prediction files remain untouched.
    """
    frozen()
    path = OUT / 'url_v4_comparison.json'
    report = json.loads(path.read_text())
    assert 'selection' in report, 'Wait for evaluation completion'
    data, extractor, _ = load_inputs()
    masks_by_cohort = {}
    for name, frame in data['tests'].items():
        masks = {'overall': np.ones(len(frame), dtype=bool), **components(frame)}
        if name == 'phreshphish_test':
            masks['benign_subdomains'] = frame.label_binary.eq(0).to_numpy() & frame.host.map(lambda h: v2.benign_subdomain(h, extractor)).to_numpy()
        masks_by_cohort[name] = masks
    cached = {}
    for candidate in report['candidates']:
        key = (candidate['artifact_sha256'], candidate['input_mode'])
        if key not in cached:
            result = {}
            for name, frame in data['tests'].items():
                pfile = np.load(LOCAL / ('_'.join(key) + '_' + name + '.npz'))
                assert np.array_equal(pfile['row_id'], frame.row_id.to_numpy(dtype=str))
                finite = np.isfinite(pfile['score'])
                known = frame.registered_domain.notna().to_numpy() & frame.registered_domain.ne('').to_numpy()
                result[name] = {group: dict(
                    distinct_registered_domains=int(frame.loc[mask & known, 'registered_domain'].nunique()),
                    scorable_registered_domains=int(frame.loc[mask & known & finite, 'registered_domain'].nunique()))
                    for group, mask in masks_by_cohort[name].items()}
            cached[key] = result
        for name, groups in cached[key].items():
            for group, counts in groups.items():
                candidate['cohorts'][name][group].update(counts)
    report['registered_domain_count_definition'] = 'Distinct nonempty registered domains; unknown/empty sentinels excluded. Counts corrected from saved predictions only; scores, thresholds, gates and ranking unchanged.'
    frozen()
    write(path, report)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['freeze', 'evaluate', 'finalize_reporting'])
    with threadpool_limits(limits=2):
        {'freeze': freeze, 'evaluate': evaluate, 'finalize_reporting': finalize_reporting}[parser.parse_args().stage]()
