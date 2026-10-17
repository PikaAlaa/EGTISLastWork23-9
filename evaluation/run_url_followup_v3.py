"""Offline contribution-gated selection and separately frozen pattern proposal."""
import argparse
from collections import Counter
from contextlib import contextmanager
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
from rapidfuzz.distance import Levenshtein
from app.core.exceptions import InvalidScanInputError
from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS
from app.engines.rule_based import domain_typosquatting_detector as brand
from app.engines.rule_based.url_pattern_analyzer import calculate_url_pattern_score
from app.engines.rule_based import url_pattern_analyzer as patterns
from app.engines.threat_intel.blacklist_lookup import SHARED_HOSTING_DOMAINS
from evaluation.phreshphish_utils import at_threshold

OUT = ROOT / 'evaluation/reports/2026-10-v4'
LOCAL = ROOT / 'evaluation/local-results/v4-v3'
OLD_LOCAL = ROOT / 'evaluation/local-results/v4-v2'
FLAGS = ['ip_address_host', 'userinfo_in_url', 'non_standard_port', 'punycode_domain',
         'no_https', 'suspicious_path_keyword', 'long_url', 'many_subdomains']
BITS = {name: 1 << idx for idx, name in enumerate(FLAGS)}
WEAK = ['no_https', 'suspicious_path_keyword', 'long_url']
STRUCTURAL = ['ip_address_host', 'userinfo_in_url', 'non_standard_port', 'punycode_domain', 'many_subdomains']
PREDICTION_CACHE = {}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8', newline='\n')


def read(name):
    return json.loads((OUT / name).read_text(encoding='utf-8'))


def cache():
    assert (OUT / 'url_selection_rule_v3.md').exists()
    assert (OUT / 'url_pattern_acceptance_rule_v3.md').exists()
    result = joblib.load(ROOT / 'evaluation/local-results/v4/prepared.joblib')
    assert result['data_sha256'] == read('url_v2_frozen_thresholds.json')['data_sha256']
    LOCAL.mkdir(parents=True, exist_ok=True)
    return result


def pattern_arrays(frame):
    bits = np.zeros(len(frame), dtype=np.uint8)
    valid = np.zeros(len(frame), dtype=bool)
    for i, row in enumerate(frame.itertuples()):
        try:
            finding = calculate_url_pattern_score(row.url.strip())
            valid[i] = True
            for flag in finding['flags']:
                bits[i] |= BITS[flag[0]]
        except InvalidScanInputError:
            pass
    return bits, valid


def mask(bits, names):
    return (bits & sum(BITS[name] for name in names)) != 0


def pattern_alerts(bits, proposal):
    if proposal == 'legacy':
        return bits != 0
    if proposal in {'structural_or_weak_pair', 'structural_only'}:
        structural = mask(bits, STRUCTURAL)
        if proposal == 'structural_only':
            return structural
        count = sum(((bits & BITS[name]) != 0).astype(int) for name in WEAK)
        return structural | (count >= 2)
    if proposal == 'four_structural_only':
        return mask(bits, STRUCTURAL[:-1])
    if proposal == 'userinfo_or_punycode':
        return mask(bits, ['userinfo_in_url', 'punycode_domain'])
    raise ValueError(proposal)


def metrics(frame, alerts, valid=None):
    values = np.asarray(alerts, dtype=float)
    if valid is not None:
        values = np.where(valid, values, np.nan)
    return at_threshold(frame.label_binary, values, .5)


def flag_counts(frame, bits, valid):
    benign = frame.label_binary.eq(0).to_numpy() & valid
    return {name: int((benign & ((bits & bit) != 0)).sum()) for name, bit in BITS.items()}


def training():
    data = cache()
    fit, cal = data['pools']['combined']
    # No held-out cohort is referenced during proposal selection.
    import pandas as pd
    train = pd.concat([fit, cal], ignore_index=True)
    train = train[(train.source == 'phreshphish') & (train.official_split == 'train')].reset_index(drop=True)
    assert len(train) and not train.official_split.eq('test').any()
    bits, valid = pattern_arrays(train)
    proposals = ['structural_or_weak_pair', 'structural_only', 'four_structural_only', 'userinfo_or_punycode']
    measured = {name: metrics(train, pattern_alerts(bits, name), valid) for name in proposals}
    eligible = [name for name in proposals if measured[name]['false_positive_rate'] <= .005]
    chosen = min(eligible, key=lambda n: (-measured[n]['recall'], measured[n]['false_positive_rate'], proposals.index(n))) if eligible else None
    result = {'created_at': datetime.now(timezone.utc).isoformat(),
              'acceptance_rule_sha256': sha(OUT / 'url_pattern_acceptance_rule_v3.md'),
              'training_only': True, 'test_or_validation_used_for_choice': False,
              'rows': len(train), 'benign_flag_counts': flag_counts(train, bits, valid),
              'current_pattern_metrics': metrics(train, bits != 0, valid),
              'proposals': measured, 'chosen_proposal': chosen,
              'row_membership_sha256': hashlib.sha256('\n'.join(train.row_id).encode()).hexdigest(),
              'destination_requests': 0, 'example_hosts_printed': 0}
    write('pattern_training_proposal_v3.json', result)
    print(json.dumps({'chosen': chosen, 'training_rows': len(train), 'proposal_metrics': {
        k: {'recall': v['recall'], 'fp': v['fp'], 'benign': v['benign_n'], 'fpr': v['false_positive_rate']} for k, v in measured.items()}}), flush=True)


def own_gate(candidate):
    c = candidate['cohorts']
    return (c['phreshphish_test_benign_subdomains']['model']['false_positive_rate'] <= .01
            and c['etis_grouped_validation']['model']['false_positive_rate'] <= .005
            and c['phreshphish_test']['model']['false_positive_rate'] <= .005)


def select_initial():
    assert (OUT / 'url_selection_rule_v3.md').exists()
    prior = read('url_v2_comparison.json')
    frozen = read('url_v2_frozen_thresholds.json')
    assert sha(OUT / 'url_v2_frozen_thresholds.json') == prior['frozen_thresholds_sha256']
    results = []
    for c in prior['candidates']:
        record = next(r for r in frozen['models'] if r['sha256'] == c['artifact_sha256'])
        assert any(p['threshold'] == c['threshold'] for p in record['thresholds'])
        cohort = {}
        for name in ['phreshphish_test', 'etis_grouped_validation']:
            m = c['cohorts'][name]['ordinary']
            baseline = prior['scanner_baseline'][name]['metrics']['fp']
            added = m['fp'] - baseline
            assert added >= 0
            cohort[name] = {'recall': m['recall'], 'tp': m['tp'], 'phishing_n': m['phishing_n'],
                            'total_fp': m['fp'], 'benign_n': m['benign_n'], 'non_model_fp': baseline,
                            'model_added_fp': added, 'model_added_fpr': added / m['benign_n']}
        results.append({'artifact_path': c['artifact_path'], 'artifact_sha256': c['artifact_sha256'],
                        'threshold': c['threshold'], 'representation': c['representation'],
                        'own_model_gate_pass': own_gate(c), 'cohorts': cohort,
                        'passes_v3': own_gate(c) and all(m['model_added_fpr'] <= .005 for m in cohort.values())})
    passing = [c for c in results if c['passes_v3']]
    winner = min(passing, key=selection_key) if passing else None
    result = {'stage': 'initial_legacy_patterns', 'rule_sha256': sha(OUT / 'url_selection_rule_v3.md'),
              'frozen_thresholds_sha256': sha(OUT / 'url_v2_frozen_thresholds.json'),
              'thresholds_added': 0, 'candidates': results, 'passing_candidates': len(passing), 'selected': winner}
    write('url_v3_initial_selection.json', result)
    print(json.dumps({'passing': len(passing), 'winner': winner}), flush=True)


def selection_key(c):
    cc = c['cohorts']
    return (-cc['phreshphish_test']['recall'], cc['etis_grouped_validation']['model_added_fp'],
            cc['phreshphish_test']['model_added_fp'], c['artifact_path'], c['threshold'])


@contextmanager
def accelerated_brands():
    # Exact distance substitution already checked on 7,506 pairs in v2.
    original = brand.calculate_levenshtein_distance
    brand.calculate_levenshtein_distance = Levenshtein.distance
    try:
        yield
    finally:
        brand.calculate_levenshtein_distance = original


def audit():
    data = cache()
    frame = data['tests']['etis_grouped_validation']
    pairs = []
    import ast
    import subprocess
    source = subprocess.check_output(['git', 'show', 'dcfeb02:backend/app/core/egyptian_brands.py'], cwd=ROOT, text=True, encoding='utf-8')
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.AnnAssign) and getattr(n.target, 'id', None) == 'EGYPTIAN_BRAND_DOMAINS')
    original_registry = ast.literal_eval(node.value)
    with accelerated_brands():
        for row in frame[frame.label_binary == 0].itertuples():
            try:
                finding = brand.calculate_domain_typosquatting_score(row.url.strip(), registry=original_registry)
            except InvalidScanInputError:
                continue
            if finding['score'] and not finding['decisive']:
                pairs.append({'row_id': row.row_id, 'benign_domain': row.host,
                              'matched_brand': finding['matched_brand'], 'matched_registry_domain': finding['matched_brand_domain'],
                              'technique': finding['technique'], 'score': finding['score'],
                              'status': 'known limitation pending official-source review'})
    assert len(pairs) == 13
    write('etis_brand_resemblance_pairs_v3.json', {'destination_requests': 0, 'initial_registry_commit': 'dcfeb02',
          'initial_registry': original_registry, 'pairs': pairs, 'count': len(pairs)})
    print(json.dumps({'brand_pair_count': len(pairs), 'destination_requests': 0}), flush=True)


def finalize_brand_review():
    reviewed = read('etis_brand_resemblance_pairs_v3.json')
    amazon = 'https://www.developer.amazon.com/docs/app-submission/distribute-your-app-internationally.html'
    sources = {d: amazon for d in ['amazon.com', 'amazon.de', 'amazon.co.jp', 'amazon.com.mx', 'amazon.se']}
    sources['amazon.co.za'] = 'https://www.aboutamazon.com/news/retail/amazon-south-africa'
    sources['orange.pl'] = 'https://www.orange.com/en/our-websites'
    with accelerated_brands():
        for row in reviewed['pairs']:
            d = row['benign_domain']
            if d in sources:
                finding = brand.calculate_domain_typosquatting_score('https://' + d + '/')
                assert finding['technique'] == 'exact_match' and finding['score'] == 0
                row.update(status='fixed_missing_official_domain', official_source=sources[d],
                           current_registry_brand=finding['matched_brand'])
            else:
                row['status'] = 'known_limitation_no_official_domain_provenance_for_matched_brand'
    reviewed.update(fixed_count=len(sources), remaining_count=len(reviewed['pairs']) - len(sources),
                    review_date='2026-10-17', destination_requests=0)
    write('etis_brand_resemblance_pairs_v3.json', reviewed)
    print(json.dumps({'fixed': reviewed['fixed_count'], 'remaining': reviewed['remaining_count']}))


def evaluate_patterns():
    proposal = read('pattern_training_proposal_v3.json')
    assert proposal['acceptance_rule_sha256'] == sha(OUT / 'url_pattern_acceptance_rule_v3.md')
    chosen = proposal['chosen_proposal'] or 'legacy'
    data = cache()
    result = {'proposal_frozen_before_evaluation': True, 'proposal_sha256': sha(OUT / 'pattern_training_proposal_v3.json'),
              'proposal': chosen, 'test_used_to_choose_proposal': False, 'example_hosts_printed': 0,
              'destination_requests': 0, 'cohorts': {}}
    for name, frame in data['tests'].items():
        bits, valid = pattern_arrays(frame)
        proposed = pattern_alerts(bits, chosen)
        old = bits != 0
        np.savez_compressed(LOCAL / (name + '_patterns.npz'), bits=bits, valid=valid, proposed=proposed,
                            row_id=frame.row_id.to_numpy(dtype=str))
        result['cohorts'][name] = {'benign_flag_counts': flag_counts(frame, bits, valid),
            'benign_flag_counts_are_overlapping': True, 'legacy': metrics(frame, old, valid),
            'proposed': metrics(frame, proposed, valid),
            'pattern_recall_change': metrics(frame, proposed, valid)['recall'] - metrics(frame, old, valid)['recall']}
    result['test_fpr_pass'] = result['cohorts']['phreshphish_test']['proposed']['false_positive_rate'] <= .01
    result['replay_pass'] = None
    result['accepted'] = None
    write('pattern_evaluation_v3.json', result)
    print(json.dumps(result), flush=True)


def baseline_components():
    data = cache()
    for name, frame in data['tests'].items():
        pf = np.load(LOCAL / (name + '_patterns.npz'))
        assert np.array_equal(pf['row_id'], frame.row_id.to_numpy(dtype=str))
        valid, bits = pf['valid'], pf['bits']
        warnings = np.zeros(len(frame), dtype=bool)
        official = np.zeros(len(frame), dtype=bool)
        shared = np.zeros(len(frame), dtype=bool)
        with accelerated_brands():
            for i, row in enumerate(frame.itertuples()):
                if not valid[i]:
                    continue
                finding = brand.calculate_domain_typosquatting_score(row.url.strip())
                warnings[i] = finding['score'] > 0
                official[i] = finding['technique'] == 'exact_match'
                shared[i] = any(row.host == h or row.host.endswith('.' + h) for h in SHARED_HOSTING_DOMAINS)
                if (i + 1) % 40000 == 0:
                    print('BRAND COMPONENTS', name, i + 1, '/', len(frame), flush=True)
        np.savez_compressed(LOCAL / (name + '_components.npz'), brand=warnings, official=official,
                            eligible=valid & ~official & ~shared, valid=valid, bits=bits,
                            row_id=frame.row_id.to_numpy(dtype=str))
    print('Saved matched baseline components; no URL visits', flush=True)


def probabilities(candidate, name, frame):
    key = (candidate['artifact_sha256'], name)
    if key not in PREDICTION_CACHE:
        with np.load(OLD_LOCAL / (candidate['artifact_sha256'] + '_' + name + '.npz')) as pfile:
            assert np.array_equal(pfile['row_id'], frame.row_id.to_numpy(dtype=str))
            PREDICTION_CACHE[key] = pfile['score']
    return PREDICTION_CACHE[key]


def integrated(frame, components, p, threshold, pattern_policy, corroboration=False):
    baseline = components['valid'] & (components['brand'] | pattern_alerts(components['bits'], pattern_policy))
    supported = components['eligible'] & np.isfinite(p) & (p >= threshold)
    if corroboration:
        supported &= baseline
    alerts = baseline | supported
    m = metrics(frame, alerts, components['valid'])
    benign = frame.label_binary.eq(0).to_numpy()
    non_model = int((baseline & benign).sum())
    added = int((alerts & ~baseline & benign).sum())
    assert m['fp'] == non_model + added
    return {'recall': m['recall'], 'tp': m['tp'], 'phishing_n': m['phishing_n'],
            'total_fp': m['fp'], 'benign_n': m['benign_n'], 'total_fpr': m['false_positive_rate'],
            'non_model_fp': non_model, 'model_added_fp': added, 'model_added_fpr': added / m['benign_n'],
            'runtime_abstentions': m['abstentions']}


def select_final():
    data = cache()
    prior = read('url_v2_comparison.json')
    proposal = read('pattern_training_proposal_v3.json')['chosen_proposal']
    evaluation = read('pattern_evaluation_v3.json')
    policies = ['legacy'] + ([proposal] if proposal is not None and evaluation['test_fpr_pass'] else [])
    components = {n: np.load(LOCAL / (n + '_components.npz')) for n in data['tests']}
    for n, f in data['tests'].items():
        assert np.array_equal(components[n]['row_id'], f.row_id.to_numpy(dtype=str))
    outputs = {'rule_sha256': sha(OUT / 'url_selection_rule_v3.md'),
               'frozen_thresholds_sha256': sha(OUT / 'url_v2_frozen_thresholds.json'),
               'pattern_proposal_sha256': sha(OUT / 'pattern_training_proposal_v3.json'),
               'registry': EGYPTIAN_BRAND_DOMAINS, 'thresholds_added': 0, 'stages': {}}
    for policy in policies:
        candidates = []
        for c in prior['candidates']:
            cohort = {n: integrated(f, components[n], probabilities(c, n, f), c['threshold'], policy)
                      for n, f in data['tests'].items()}
            candidates.append({'artifact_path': c['artifact_path'], 'artifact_sha256': c['artifact_sha256'],
                'threshold': c['threshold'], 'representation': c['representation'],
                'own_model_gate_pass': own_gate(c), 'cohorts': cohort,
                'model_metrics': {n: v['model'] for n, v in c['cohorts'].items()},
                'passes_v3': own_gate(c) and all(m['model_added_fpr'] <= .005 for m in cohort.values())})
        passing = [c for c in candidates if c['passes_v3']]
        assert passing, 'No ordinary v3 candidate passed; do not silently deploy fallback'
        chosen = min(passing, key=selection_key)
        comparisons = {}
        for label, c in [*prior['comparators'].items(), ('deployed_v3', chosen), ('corroboration_only', chosen)]:
            comparisons[label] = {n: integrated(f, components[n], probabilities(c, n, f), c['threshold'], policy,
                                               corroboration=label == 'corroboration_only') for n, f in data['tests'].items()}
        outputs['stages'][policy] = {'candidates': candidates, 'passing_candidates': len(passing),
                                    'selected': chosen, 'comparisons': comparisons}
    outputs['proposed_pattern_policy'] = policies[-1]
    outputs['accepted_pattern_policy'] = None
    write('url_v3_final_selection.json', outputs)
    print(json.dumps({p: {'passing': v['passing_candidates'], 'selected': {k: v['selected'][k] for k in ['artifact_path', 'threshold', 'cohorts']}}
                      for p, v in outputs['stages'].items()}), flush=True)


def promote(pattern_policy=None):
    report = read('url_v3_final_selection.json')
    assert report['rule_sha256'] == sha(OUT / 'url_selection_rule_v3.md')
    assert report['frozen_thresholds_sha256'] == sha(OUT / 'url_v2_frozen_thresholds.json')
    policy = pattern_policy or report['proposed_pattern_policy']
    c = report['stages'][policy]['selected']
    assert c['passes_v3'] and c['own_model_gate_pass']
    source = ROOT / c['artifact_path']
    assert sha(source) == c['artifact_sha256']
    record = next(r for r in read('url_v2_frozen_thresholds.json')['models'] if r['sha256'] == c['artifact_sha256'])
    assert any(p['threshold'] == c['threshold'] for p in record['thresholds'])
    artifact = joblib.load(source)
    artifact['thresholds'] = {**artifact.get('thresholds', {}), 'medium': c['threshold']}
    artifact['deployment_schema'] = {'representation': record['representation'], 'phresh_schema': record['phresh_schema']}
    target = ROOT / 'ml/models/url_host_v3.joblib'
    joblib.dump(artifact, target, compress=3)
    import re
    for file, key, value in [('backend/app/engines/risk_scoring.py', 'URL_MODEL_POLICY', 'ordinary'),
                             ('backend/app/engines/rule_based/url_pattern_analyzer.py', 'PATTERN_ALERT_POLICY', policy)]:
        path = ROOT / file
        text, n = re.subn(key + r" = '[a-z_]+'", f"{key} = '{value}'", path.read_text(encoding='utf-8'))
        assert n == 1
        path.write_text(text, encoding='utf-8', newline='\n')
    metadata = {'selected': c['artifact_path'], 'artifact_sha256': sha(target), 'source_artifact_sha256': c['artifact_sha256'],
        'threshold': c['threshold'], 'representation': c['representation'], 'policy': 'ordinary', 'pattern_policy': policy,
        'selection_rule_path': 'evaluation/reports/2026-10-v4/url_selection_rule_v3.md',
        'selection_rule_sha256': report['rule_sha256'], 'frozen_thresholds_sha256': report['frozen_thresholds_sha256'],
        'pattern_acceptance_rule_sha256': sha(OUT / 'url_pattern_acceptance_rule_v3.md'),
        'pattern_training_proposal_sha256': sha(OUT / 'pattern_training_proposal_v3.json'),
        'protocol_sha256': read('url_v2_frozen_thresholds.json')['protocol_sha256'],
        'data_sha256': read('url_v2_frozen_thresholds.json')['data_sha256'],
        'passes_model_v3': True, 'passes_incremental_fp_gate': True,
        'report': 'evaluation/reports/2026-10-v4/url_v3_final_selection.json', 'fallback': False,
        'sealed_test_run': False, 'limitations': 'Exposed selection; matched healthy empty blacklist; no Egyptian SMS validation.'}
    for name in ['deployment.json']:
        write(name, metadata)
    (ROOT / 'ml/models/url_host_deployment.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(metadata), flush=True)


def accept_patterns():
    from evaluation.run_followup import run
    replay = run(OUT / 'pattern_acceptance_replay_v3.json')
    s = replay['summary']
    passed = (s['detection_passed'], s['robustness_passed'], s['followup_passed']) == (23, 7, 15)
    result = read('pattern_evaluation_v3.json')
    result['replay_pass'] = passed
    result['replay_counts'] = s
    result['accepted'] = bool(result['proposal'] != 'legacy' and result['test_fpr_pass'] and passed)
    write('pattern_evaluation_v3.json', result)
    selection = read('url_v3_final_selection.json')
    selection['accepted_pattern_policy'] = result['proposal'] if result['accepted'] else 'legacy'
    write('url_v3_final_selection.json', selection)
    if not result['accepted']:
        promote('legacy')
    print(json.dumps({'accepted': result['accepted'], 'test_fpr_pass': result['test_fpr_pass'], 'replay_pass': passed}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['train_patterns', 'select_initial', 'audit', 'finalize_brand_review', 'evaluate_patterns', 'baseline_components', 'select_final', 'promote', 'accept_patterns'])
    args = parser.parse_args()
    {'train_patterns': training, 'select_initial': select_initial, 'audit': audit, 'finalize_brand_review': finalize_brand_review,
     'evaluate_patterns': evaluate_patterns, 'baseline_components': baseline_components, 'select_final': select_final,
     'promote': promote, 'accept_patterns': accept_patterns}[args.stage]()
