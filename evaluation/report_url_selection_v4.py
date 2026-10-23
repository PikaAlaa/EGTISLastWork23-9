"""Publish the frozen v4 result without bypassing an engineering release blocker."""
from collections import Counter
from datetime import datetime, timezone
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
from evaluation.run_url_selection_v4 import frozen, sha, FROZEN, OUT


def load(name):
    return json.loads((OUT / name).read_text(encoding='utf-8'))


def render_table(rows):
    result = '| Configuration | PhreshPhish recall | PhreshPhish FP / benign | ETIS recall | ETIS FP / benign |\n'
    result += '|---|---:|---:|---:|---:|\n'
    for label, metrics in rows:
        pp, et = metrics['phreshphish_test'], metrics['etis_grouped_validation']
        result += f"| {label} | {pp['tp']:,}/{pp['phishing_n']:,} ({100 * pp['recall']:.3f}%) | {pp['total_fp']:,}/{pp['benign_n']:,} | {et['tp']:,}/{et['phishing_n']:,} ({100 * et['recall']:.3f}%) | {et['total_fp']:,}/{et['benign_n']:,} |\n"
    return result


def main():
    inventory = frozen()
    comparison = load('url_v4_comparison.json')
    engineering = load('url_v4_engineering.json')
    parity = load('url_v4_runtime_parity.json')
    release = load('url_v4_release_checks.json')
    expected = sum(len(r['thresholds']) for r in inventory['models'])
    assert len(comparison['candidates']) == engineering['candidate_count'] == len(parity['candidates']) == expected
    assert parity['complete']
    for result in [comparison, engineering, parity]:
        assert result['rule_sha256'] == inventory['rule_sha256']
        assert result['frozen_thresholds_sha256'] == sha(FROZEN)
    required = {'pytest', 'query_invariance_40', 'replays', 'host_probes', 'query_path_88', 'scanner_parity', 'initialize', 'frontend_build', 'frontend_lint'}
    assert required <= release['commands'].keys()
    assert not any(c['exit_code'] for c in release['commands'].values())
    selection = comparison['selection']
    selected = next((c for c in comparison['candidates'] if c['id'] == selection['selected_id']), None)
    checks = next((c for c in engineering['candidates'] if selected and c['id'] == selected['id']), None)
    selected_parity = next((c for c in parity['candidates'] if selected
        and c['artifact_sha256'] == selected['artifact_sha256'] and c['input_mode'] == selected['input_mode']
        and c['threshold'] == selected['threshold']), None)
    metadata = json.loads((ROOT / 'ml/models/url_host_deployment.json').read_text())
    current = comparison['historical_comparators']['corroboration_only']
    old = comparison['historical_comparators']['deployed_v3']
    candidate_metrics = {n: c['overall']['ordinary'] for n, c in selected['cohorts'].items()} if selected else current
    state = 'blocked_engineering' if selected and (not checks['passes'] or not selected_parity['passes']) else 'ready_for_deployment' if selected else 'completed_corroboration_fallback'
    selection['engineering_run_complete'] = True
    selection['selected_engineering_passes'] = checks['passes'] if checks else True
    selection['engineering_completion_pending'] = state == 'blocked_engineering'
    (OUT / 'url_v4_comparison.json').write_text(json.dumps(comparison, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8', newline='\n')
    if state != 'ready_for_deployment':
        assert metadata['policy'] == 'corroboration_only'
        assert metadata['artifact_sha256'] == sha(ROOT / 'ml/models/url_host_v3.joblib') == '4fb9b6afbb4b356e54b842490e9192628a74db22a6dc88bb60d6c1054ce335f8'
    families = {}
    for mode in ['original', 'host_path']:
        cs = [c for c in comparison['candidates'] if c['input_mode'] == mode]
        families[mode] = dict(candidates=len(cs), passes_v3=sum(c['passes_v3'] for c in cs),
                              passes_query_invariance=sum(c['passes_query_invariance'] for c in cs),
                              primary_eligible=sum(c['primary_eligible'] for c in cs))
    decision = dict(created_at=datetime.now(timezone.utc).isoformat(), rule_sha256=inventory['rule_sha256'],
        base_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        branch=subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip(),
        evaluation_environment={name: importlib.metadata.version(name) for name in
            ['numpy', 'pandas', 'scikit-learn', 'lightgbm', 'joblib', 'tldextract', 'pyarrow', 'rapidfuzz']},
        frozen_thresholds_sha256=sha(FROZEN), status=state, numerical_selection=selection,
        selected_candidate=selected, selected_engineering=checks, families=families,
        active_policy=metadata['policy'], active_artifact_sha256=metadata['artifact_sha256'],
        active_threshold=metadata['threshold'], deployed_new_candidate=False,
        reason='Preserve the unchanged rule: numerical selection is not reranked after engineering failures; existing corroboration containment remains until the release blocker is resolved.' if state == 'blocked_engineering' else state,
        before_after=dict(historical_ordinary=old, session_before=current, session_after=current, selected_candidate_ordinary_projection=candidate_metrics),
        test_files_modified=False, sealed_test_run=False, destination_requests=0, genuine_egyptian_sms_test_count=0,
        push_performed=False, merge_performed=False)
    frozen()
    (OUT / 'url_v4_decision.json').write_text(json.dumps(decision, indent=2) + '\n', encoding='utf-8')
    if state == 'ready_for_deployment':
        raise RuntimeError('Selected candidate is ready; deploy it and verify the actual deployment before publishing current-policy documentation')
    table = render_table([('Historical v3 ordinary', old), ('Before this session: corroboration-only', current),
                          ('After this session: corroboration-only', current), ('Numerical v4 winner, ordinary projection; NOT DEPLOYED', candidate_metrics)])
    winner = f"`{selected['artifact_path']}` with **{selected['input_mode']}**, threshold **{selected['threshold']:.17g}**" if selected else 'No primary or host-only numerical passer'
    failure_count = len(checks['pytest_failed']) if checks else 0
    metrics_block = f"""# V4 frozen evaluation: deployment blocked by unchanged engineering tests

The v4 numerical selection is {winner}. **It is not deployed. Current URL-model policy remains `corroboration_only`**, with the unchanged artifact and threshold. The selected candidate passes every v3 numerical gate and QUERY-INVARIANCE, but its unchanged full backend suite has **{checks['pytest_passed'] if checks else 0} passes / {failure_count} failures**. All candidates were checked; {engineering['passing']}/{expected} pass the entire unchanged engineering bundle.

The rule requires engineering checks to pass before deployment in every tier. It does not authorize reranking numerical winners or choosing a lower fallback tier after an engineering failure. This is a **release blocker**, not a claim that no candidate passes the numerical gates. No tests, replay expectations, frozen inputs, model weights, vectorizers, registry entries or rule bytes were changed to force a result.

## Query finding and calibration freeze

The historical full-URL LightGBM flags **35/52 benign PhreshPhish query URLs (67.308%)**, versus 13/91,208 query-free benign rows. Its fitting pool contains only **3/84,208** benign PhreshPhish query URLs; calibration has 3/21,178. Those 35 query false positives also become ordinary-policy scanner alerts. ETIS validation contains zero benign queries among 2,916 rows. Aggregate v3 gates hid this subgroup failure.

Applied [the unchanged v4 rule](url_selection_rule_v4.md), SHA-256 `{inventory['rule_sha256']}`. The expanded [inventory](url_v4_frozen_thresholds.json) was written and hash-locked **before any v4 evaluation/probe predictions**: `{sha(FROZEN)}`. It contains 202 unchanged original threshold pairs plus 87 calibration-only host+path pairs, from 36 unchanged source artifacts (15 also scored in host+path mode). The six unchanged FPR caps and conservative `threshold_at_fpr` helper were used; thresholds were deduplicated within artifact/input mode. No test, validation or probe result chose a threshold, and no model was fitted. Source schema, original calibration exclusions/membership and transformed-input fingerprints are retained. The existing full-URL weights were not trained anew on stripped inputs.

The rule prints a malformed 63-character coverage-audit digest. The audit matches the committed `a80e790` bytes; its actual SHA-256 is `b248342ee2357e36bfff43059a71d2708f5e17480a682c7edeeedc5fa1370d06`. The discrepancy is recorded in the frozen inventory; neither file was amended.

## Before/after and numerical candidate projection

{table}
These are exposed URL-only development cohorts, with the fixed production registry, four structural pattern families and an isolated healthy empty blacklist. The session's deployed recall and false positives are unchanged. The numerical winner's figures are a measured projection, not current deployment performance. Corroboration-only retains the large historical recall cost: 56.608 PhreshPhish and 15.721 ETIS percentage points versus ordinary v3. Phishing abstentions remain misses; benign abstentions do not alert.

## Complete gate evidence and release blocker

| Input mode | Candidates | Pass v3 | Pass QUERY-INVARIANCE | Pass both |
|---|---:|---:|---:|---:|
"""
    for mode, counts in families.items():
        metrics_block += f"| {mode} | {counts['candidates']} | {counts['passes_v3']} | {counts['passes_query_invariance']} | {counts['primary_eligible']} |\n"
    if selected:
        pp = selected['cohorts']['phreshphish_test']
        et = selected['cohorts']['etis_grouped_validation']
        metrics_block += '\nSelected candidate raw-model gate counts:\n\n| Cohort | Raw FP / benign | Limit |\n|---|---:|---:|\n'
        for name, m, limit in [('PhreshPhish benign subdomains', pp['benign_subdomains']['model'], '1%'),
                               ('PhreshPhish overall', pp['overall']['model'], '0.5%'),
                               ('ETIS validation', et['overall']['model'], '0.5%')]:
            metrics_block += f"| {name} | {m['fp']:,}/{m['benign_n']:,} ({100 * m['false_positive_rate']:.5f}%) | {limit} |\n"
        metrics_block += f"\nModel-added scanner FP are {pp['overall']['ordinary']['model_added_fp']}/{pp['overall']['ordinary']['benign_n']} and {et['overall']['ordinary']['model_added_fp']}/{et['overall']['ordinary']['benign_n']}, respectively (each below the 0.5-point limit). Natural benign-query raw/scanner FP are {pp['query_present']['model']['fp']}/{pp['query_present']['model']['benign_n']} and {pp['query_present']['ordinary']['total_fp']}/{pp['query_present']['ordinary']['benign_n']} on PhreshPhish; ETIS benign-query FPR is not estimable (zero rows).\n"
    metrics_block += f"""
The primary tier has {selection['primary_passing']} numerical passers; the genuine host-only v3 fallback pool has {selection['host_only_v3_passing']}. Selection uses the rule's exact recall/FP/path/threshold/input-mode tie-breakers. The [complete comparison](url_v4_comparison.json) reports every numerical gate, raw-model FP/benign and recall, ordinary/corroboration/no-model scanner outcomes, model-added FP, query/fragment subgroups, domain coverage and abstentions. [Provenance](url_v4_provenance.json) adds fitting/calibration/union coverage, original schema fingerprints and preserved input hashes.

QUERY-INVARIANCE is checked separately on each candidate's original calibration negatives, all 91,260 PhreshPhish benign rows, all 2,916 ETIS benign rows, 88 exposed shape probes and 17 root probes. Each result retains O/S/N counts, abstentions, paired newly/no-longer-alerting counts and all four exact `200 * alert_delta <= n` comparisons. Host+path invariance is measured after applying its declared preprocessor to all three forms. These counterfactuals are synthetic diagnostics, not independently labelled traffic. Natural benign query coverage remains 52 PhreshPhish rows and zero ETIS rows; benign fragment FPR is not estimable on either cohort.

[Every candidate's engineering results](url_v4_engineering.json) and the [per-candidate actual outputs](url-v4-engineering/) retain the unchanged full suite, the 40-query file, all 23/7/15 replays, 17 hosts and 88 shape cases. The selected candidate has {checks['query_invariance_40_passed'] if checks else 0}/40 query-test passes; replay and probe counts are in its retained record. Failures include the existing test that explicitly requires a mocked probability of 1.0 to remain LOW without corroboration, assertions that the historical raw query shortcut remains above threshold, and representation/threshold tests written for original-input v2 deployment. Keeping those assertions unchanged conflicts with deploying an ordinary host+path replacement. They were not deleted, skipped, weakened, or relabelled as passes. See the exact selected failure list in [the decision](url_v4_decision.json).

[Runtime/scanner parity](url_v4_runtime_parity.json) checks boundary/random samples from calibration and evaluation predictions for every frozen threshold with the real production scorer, and checks sampled outcomes under all three scanner policies against the original non-model components. It records probability differences, runtime input abstentions and mismatches. The host+path runtime branch strips only model input; the scanner's blacklist identity, brand/pattern input and displayed evidence retain the complete URL. That branch is available for verification but inactive in the retained deployment.

## CI and retained deployment verification

Moved the optional RapidFuzz import into `accelerated_brands`; importing the historical promotion guard no longer requires the evaluation-only dependency. A fresh venv installed **only `requirements-runtime.txt`**: **383 passed, 5 skipped**, including the historical-promotion test, with RapidFuzz and PyArrow absent. Existing optional PyArrow tests account for the clean-environment skips/collection difference. See [actual output and package inventory](url_v4_runtime_only_checks.json).

For the retained deployment: **392 backend tests**, **40/40 query tests**, **23/23, 7/7, 15/15 replays**, **17/17 hosts avoiding MEDIUM/HIGH**, **88/88 shape probes LOW**, and **1,619 scanner checks with zero mismatches**. Isolated database initialization, frontend build and lint pass. [Actual release outputs](url_v4_release_checks.json). Existing Starlette deprecation and frontend bundle-size warnings remain.

No destination visits, DNS resolution, HTML column access, data upload, sealed final test, push or merge. Genuine Egyptian SMS final-test count remains zero. Row predictions remain ignored/local. Repeated use of exposed development cohorts is not independent validation.
"""
    report_path = OUT / 'REPORT.md'
    existing = report_path.read_text(encoding='utf-8')
    marker = '\n<!-- V4 HISTORICAL REPORT -->\n'
    historical = existing.split(marker, 1)[-1] if marker in existing else existing
    historical = historical.removeprefix('\n## Historical v3 record (superseded deployment)\n\n')
    report_path.write_text(metrics_block + marker + '\n## Historical v3 record (superseded deployment)\n\n' + historical, encoding='utf-8', newline='\n')
    handoff = f"""# V4 handoff: numerical winner found; deployment blocked

Branch `fix/url-subdomains-and-hygiene`. Evaluation complete; **deployment completion is blocked** by the unchanged suite. Current policy stays **corroboration_only**, artifact `{metadata['artifact_sha256']}`, threshold `{metadata['threshold']:.17g}`. Historical ordinary-promotion commands remain blocked. No push or merge.

Numerical selection: {winner}. There are {selection['primary_passing']} primary numerical passers and {selection['host_only_v3_passing']} genuine host-only v3 passers. The winner's suite has {failure_count} failures; every one of the {expected} frozen candidates received the complete unchanged engineering bundle. The rule does not permit reranking or invoking fallback solely to evade this engineering blocker. See [REPORT.md](REPORT.md), [decision](url_v4_decision.json), [comparison](url_v4_comparison.json), [engineering outputs](url_v4_engineering.json) and [runtime parity](url_v4_runtime_parity.json).

The rule and original frozen inputs are unchanged. Inventory freeze SHA-256: `{sha(FROZEN)}`; 202 original pairs plus 87 host+path pairs, chosen only on original calibration pools before any v4 evaluation. The rule's 63-character coverage-hash typo is documented without amending it.

{table}
The query finding remains 35/52 benign PhreshPhish query URLs flagged by the historical full-URL model, with only three benign query URLs in fitting. Natural benign fragments and ETIS benign queries have no coverage. The v4 row is an undeployed projection. Corpus predictions stay local; no HTML, fetching, sealed test or invented real-SMS claims. Genuine Egyptian SMS count 0.

CI fixed by importing RapidFuzz only inside its accelerator. Fresh runtime-only venv: 383 passed, 5 skipped, RapidFuzz absent. Retained deployment: 392 tests; 40 query tests; 23/7/15 replays; 17 hosts; 88 shape probes; 1,619 scanner matches, zero mismatches; isolated initialize, frontend build and lint pass. Actual outputs are linked in the report.

To resolve the release blocker, an explicit instruction is needed on reconciling historical-policy/model-specific tests with an ordinary replacement. No existing assertions were changed. Numerical thresholds and gates must remain frozen. Stop after the local commit; do not push or merge.
"""
    (OUT / 'HANDOFF.md').write_text(handoff, encoding='utf-8', newline='\n')
    pr = f"""# Evaluate query-invariant URL candidates and fix runtime-only CI

The historical full-URL classifier flags 35/52 benign query URLs despite seeing only three in fitting. Execute the unchanged v4 rule with 202 original candidates plus 87 host+path thresholds chosen only on calibration data and frozen before evaluation. Preserve all inputs, weights, registry entries, pattern policy and historical promotion guards.

The numerical winner is {winner}. **Deployment is blocked**: it passes v3 and QUERY-INVARIANCE but fails {failure_count} assertions in the unchanged backend suite. All {expected} candidates receive that suite, the 40-query tests, 23/7/15 replays, 17 hosts and 88 shape cases. Keep corroboration-only active; do not silently rerank the numerical winner or reinterpret the fallback order. Historical-policy assertions and original-input metadata tests require an explicit resolution before ordinary replacement deployment.

{table}
The candidate row is an exposed development projection, not deployed performance. [Complete evidence and limitations](REPORT.md), including the malformed coverage hash in the unchanged rule, sparse natural-query/fragment coverage, every candidate's gates, paired diagnostics and engineering failures.

Move RapidFuzz into the evaluation function that uses it. Fresh venv with only runtime requirements: 383 passed, 5 optional skips; RapidFuzz absent. Current deployment checks: 392 backend tests, 40 query tests, 23/7/15 replays, 17 host probes, 88 shape probes, 1,619 scanner matches, isolated initialization, frontend build and lint pass. Keep the production model-input preprocessor inactive pending deployment clearance.

No rule/test weakening, frozen input changes, new fitting, destination/HTML access, sealed final test, push or merge. Genuine Egyptian SMS final-test count remains zero.
"""
    (OUT / 'PR_DESCRIPTION.md').write_text(pr, encoding='utf-8', newline='\n')
    query_path = OUT / 'query-shortcut/REPORT.md'
    query = query_path.read_text(encoding='utf-8')
    query_marker = '\n<!-- V4 QUERY HISTORY -->\n'
    query_history = query.split(query_marker, 1)[-1] if query_marker in query else query
    query_path.write_text(f"# 22 October v4 evaluation update\n\nCurrent policy remains **corroboration_only**. The unchanged v4 rule produced a numerical winner ({winner}), but its unchanged engineering suite blocks deployment. No fallback tier was invented to bypass that blocker. See [the complete v4 report](../REPORT.md), [decision](../url_v4_decision.json) and [candidate checks](../url_v4_engineering.json). The RapidFuzz CI import failure is fixed and verified in a fresh runtime-only venv.\n\n" + table + '\nThe candidate row is a measured, undeployed projection. Before/after deployment metrics are unchanged. The historical query diagnosis and containment evidence below remain valid; current checks are in the v4 report.\n' + query_marker + query_history, encoding='utf-8', newline='\n')
    frozen()
    print(json.dumps(dict(status=state, selection=selection, families=families)))


if __name__ == '__main__':
    main()
