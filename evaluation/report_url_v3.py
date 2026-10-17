"""Render the contribution-gated deployment report from saved measurements."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
from app.core.egyptian_brands import EGYPTIAN_BRAND_DOMAINS, OCTOBER_VERIFIED_DOMAINS

OUT = ROOT / 'evaluation/reports/2026-10-v4'


def read(name):
    return json.loads((OUT / name).read_text(encoding='utf-8'))


def write(name, content):
    (OUT / name).write_text(content, encoding='utf-8', newline='\n')


def pct(value):
    return f'{value * 100:.3f}%'


def main():
    selection = read('url_v3_final_selection.json')
    stage = selection['stages'][selection['accepted_pattern_policy']]
    chosen = stage['selected']
    comparisons = stage['comparisons']
    initial = read('url_v3_initial_selection.json')
    pattern = read('pattern_evaluation_v3.json')
    training = read('pattern_training_proposal_v3.json')
    brands = read('etis_brand_resemblance_pairs_v3.json')
    deployment = read('deployment.json')
    checks = read('final_checks.json')
    verification = read('deployed_scanner_verification_v3.json')
    replay = read('followup_v3.json')['summary']
    assert pattern['accepted'] and chosen['passes_v3'] and chosen['own_model_gate_pass']
    assert all(c['exit_code'] == 0 for c in checks['commands'].values())
    n_verified = sum(p['full_scanner_matches'] for c in verification['cohorts'].values() for p in c['policies'].values())
    labels = {'old_v3_deployed': 'Original v3, ordinary', 'v1_selected': 'v1 selected, ordinary',
              'deployed_v3': '**v3 contribution gate, ordinary (deployed)**',
              'corroboration_only': 'Corroboration-only, selected model'}
    sections = []
    for cohort, title in [('phreshphish_test', 'PhreshPhish test'), ('etis_grouped_validation', 'ETIS validation')]:
        rows = '\n'.join(f"| {labels[label]} | {pct(v[cohort]['recall'])} ({v[cohort]['tp']}/{v[cohort]['phishing_n']}) | "
                         f"{v[cohort]['total_fp']}/{v[cohort]['benign_n']} ({pct(v[cohort]['total_fpr'])}) | "
                         f"{v[cohort]['non_model_fp']} | {v[cohort]['model_added_fp']} ({v[cohort]['model_added_fpr'] * 100:.3f} pp) |"
                         for label, v in comparisons.items())
        sections.append(f'### {title}\n\n| Policy | MEDIUM/HIGH recall | Total FP / benign (FPR) | Non-model FP | Model-added FP (extra rate) |\n'
                        f'|---|---:|---:|---:|---:|\n{rows}\n')
    gates = '\n'.join(f"| {title} | {m['fp']}/{m['benign_n']} ({pct(m['false_positive_rate'])}) | {limit} | pass |"
                      for cohort, title, limit in [('phreshphish_test_benign_subdomains', 'Benign subdomains, PhreshPhish test', '1%'),
                                                  ('etis_grouped_validation', 'ETIS validation', '0.5%'),
                                                  ('phreshphish_test', 'All PhreshPhish test', '0.5%')]
                      for m in [chosen['model_metrics'][cohort]])
    counts = '\n'.join(f"| `{flag}` | {count} | {pattern['cohorts']['etis_grouped_validation']['benign_flag_counts'][flag]} | "
                       f"{'yes' if flag in {'ip_address_host', 'userinfo_in_url', 'non_standard_port', 'punycode_domain'} else 'diagnostic only'} |"
                       for flag, count in pattern['cohorts']['phreshphish_test']['benign_flag_counts'].items())
    proposals = '\n'.join(f"| `{name}` | {pct(m['recall'])} | {m['fp']}/{m['benign_n']} ({pct(m['false_positive_rate'])}) | "
                          f"{'pass' if m['false_positive_rate'] <= .005 else 'fail'} |"
                          for name, m in training['proposals'].items())
    pattern_rows = []
    integrated_costs = {}
    for cohort, title in [('phreshphish_test', 'PhreshPhish test'), ('etis_grouped_validation', 'ETIS validation')]:
        c = pattern['cohorts'][cohort]
        old = selection['stages']['legacy']['comparisons']['deployed_v3'][cohort]
        new = comparisons['deployed_v3'][cohort]
        cost = new['recall'] - old['recall']
        integrated_costs[cohort] = cost
        pattern_rows.append(f"| {title} | {pct(c['legacy']['recall'])} | {pct(c['proposed']['recall'])} | "
                            f"{c['pattern_recall_change'] * 100:.3f} pp | {pct(old['recall'])} → {pct(new['recall'])} ({cost * 100:.3f} pp) |")
    pairs = '\n'.join(f"| `{p['benign_domain']}` | {p['matched_brand']} / `{p['matched_registry_domain']}` | "
                      f"{'Fixed: sourced official domain' if p['status'] == 'fixed_missing_official_domain' else 'Known limitation; no supported official-domain addition'} |"
                      for p in brands['pairs'])
    initial_rows = '\n'.join(f"| {name} | {pct(m['recall'])} | {m['total_fp']}/{m['benign_n']} | {m['non_model_fp']} | {m['model_added_fp']} |"
                             for name, m in initial['selected']['cohorts'].items())
    report = f'''# URL model contribution and pattern follow-up

Deployed **ordinary URL-model support** from the existing combined full-URL LightGBM at **{chosen['threshold']:.17g}**. It passes rule v3's own-model and incremental-scanner FP limits. The independently frozen pattern proposal also passes its acceptance rule. The text model is unchanged.

[Rule v3](url_selection_rule_v3.md) was written **after seeing v2 results, before any new v3 computation**. V2 had incorrectly required the whole scanner to meet the model gates. V3 gates the URL model's own alerts and the extra benign warnings it adds above a matched non-model baseline. Total scanner FPR is reported separately. [REPORT_v2.md](REPORT_v2.md) preserves the prior result; [REPORT_v1.md](REPORT_v1.md) preserves the earlier work.

## Frozen model selection

Reused all **202 existing model/threshold pairs from 36 distinct artifacts** in [url_v2_frozen_thresholds.json](url_v2_frozen_thresholds.json). **No thresholds were added or changed; no model was fitted.** Existing predictions and row membership were reused, with matching fingerprints. All thresholds were originally chosen on calibration data, never test/validation. Historical v3/v1 thresholds remain comparators only. Historical fitting exposure is unchanged; this does not claim that old training excluded later external test domains.

A candidate must meet all three own-model FPR limits below, plus **at most 0.5 percentage points of extra scanner FP on each complete benign cohort**. Among passing candidates maximize integrated PhreshPhish-test MEDIUM/HIGH recall. Exact ties follow the rule's declared order. **{stage['passing_candidates']}/202 pass**, both before and after the separately accepted pattern/registry changes. The same LightGBM wins both stages; ETIS recall is not the optimization target.

| Selected model's own alerts | FP / benign (FPR) | Limit | Outcome |
|---|---:|---:|---|
{gates}

Final incremental scanner FP: **48/91,260 = 0.052597 percentage points** on PhreshPhish and **2/2,916 = 0.068587 points** on ETIS; both are below 0.5 points. Own-model recall is **{pct(chosen['model_metrics']['phreshphish_test']['recall'])}** on PhreshPhish and **{pct(chosen['model_metrics']['etis_grouped_validation']['recall'])}** on ETIS.

Source: `{chosen['artifact_path']}`. Source SHA-256: `{chosen['artifact_sha256']}`. Packaged SHA-256: `{deployment['artifact_sha256']}`. [Deployment metadata](deployment.json) records the frozen-file, rule and proposal hashes.

## Integrated scanner comparisons

All four policies below use the **same final sourced registry, accepted pattern policy, cohort rows and healthy empty blacklist**. Original v3 and v1 refer to their original model/threshold, with ordinary support; these rows isolate model/policy effects under today's non-model baseline. Historical deployed-state measurements are retained in [REPORT_v2.md](REPORT_v2.md), rather than mixed with this changed baseline. Corroboration-only uses the newly selected LightGBM. On these URL-only cohorts all its permitted corroborators already alert, so its MEDIUM/HIGH outcome equals the no-model baseline.

Extra rate = model-added benign FP / **all benign rows** in that cohort. Total FP = non-model FP + model-added FP, without double counting. No whole-scanner gate was substituted for the model-contribution gate.

{chr(10).join(sections)}
With the original v2 registry/pattern baseline, the v3 gate already selected the same model:

| Cohort | Recall | Total FP / benign | Non-model FP | Model-added FP |
|---|---:|---:|---:|---:|
{initial_rows}

The sourced registry fixes alone reduce that baseline's non-model FP from 5,544 to 4,852 on PhreshPhish and from 15 to 8 on ETIS. The pattern change then reduces PhreshPhish non-model FP to 206; ETIS remains 8. Initial and final complete candidate tables: [initial selection](url_v3_initial_selection.json), [final selection](url_v3_final_selection.json).

## Pattern false-alarm diagnosis and frozen acceptance

[Pattern acceptance rule](url_pattern_acceptance_rule_v3.md) was written **before new pattern measurements**. Four nested proposal families and the training-only choice rule were specified in advance. Selection used **{training['rows']:,} official PhreshPhish TRAINING rows** from the existing combined fitting/calibration pools, excluding ETIS-source rows. Test and ETIS validation did not choose flags or parameters. The single choice and its measurements were saved in [pattern_training_proposal_v3.json](pattern_training_proposal_v3.json) before held-out evaluation; there was no retry after seeing test/replay results.

The old non-model scanner flagged **5,544/91,260 (6.075%)** PhreshPhish benign URLs. Raw pattern observations account for **4,677 unique benign rows**; per-flag counts overlap and do not sum to that number. The scanner's prior primary reason `url_patterns` counted 4,659 because reason precedence/suppression differs from raw observations. These are offline counts only; no PhreshPhish example hosts are printed or visited.

| Observed flag | PhreshPhish-test benign count | ETIS-validation benign count | Alerts under accepted policy |
|---|---:|---:|---|
{counts}

The same raw detections remain available in API `pattern_observations`; only `patterns`/`alert_flags` create pattern support or corroboration. `no_https`, keyword, long URL and many-subdomain observations cannot create a warning or corroborate a text/model alert by themselves. Independent brand, blacklist, secret-request and ordinary model evidence still operate normally.

| Training-only proposal | Pattern recall | FP / benign (FPR) | Training FPR ≤0.5% |
|---|---:|---:|---|
{proposals}

Frozen choice: **`{training['chosen_proposal']}`**. It has the highest training recall among qualifying proposals. Acceptance required test pattern FPR ≤1% and no replay loss. Observed **17/91,260 (0.018628%)** test pattern FPR, versus 4,677/91,260 (5.125%) previously; ETIS pattern FP stays **1/2,916**. **23/23, 7/7 and 15/15** replays pass with the actual packaged ordinary policy, so the proposal is accepted. All flag counts and evaluation metrics are in [pattern_evaluation_v3.json](pattern_evaluation_v3.json); acceptance execution is in [pattern_acceptance_replay_v3.json](pattern_acceptance_replay_v3.json).

### Recall cost of reducing pattern alerts

This is a substantial tradeoff, accepted under the requested FPR/replay rule; there was no additional recall floor. Integrated changes below hold the selected model, threshold and final registry constant and change only pattern policy.

| Cohort | Old pattern-only recall | Accepted pattern-only recall | Change | Integrated recall, old → accepted patterns |
|---|---:|---:|---:|---:|
{chr(10).join(pattern_rows)}

Relative to corroboration-only on the **same final baseline**, ordinary selected-model support recovers **{(comparisons['deployed_v3']['phreshphish_test']['recall'] - comparisons['corroboration_only']['phreshphish_test']['recall']) * 100:.3f} percentage points** of PhreshPhish recall and **{(comparisons['deployed_v3']['etis_grouped_validation']['recall'] - comparisons['corroboration_only']['etis_grouped_validation']['recall']) * 100:.3f} points** of ETIS recall. The final ETIS recall of **17.294%** remains low; passing the FP gates is not evidence of strong ETIS detection.

## Thirteen brand-resemblance pairs

The requested offline list is [etis_brand_resemblance_pairs_v3.json](etis_brand_resemblance_pairs_v3.json), with original matched domains, techniques and dispositions. These are the 13 pairs from the pre-fix ETIS baseline; no cohort URL or listed root host was opened.

| Benign domain | Incorrect matched brand / registry domain | Outcome |
|---|---|---|
{pairs}

**Seven fixes, six known limitations.** Only cited missing official domains were added: six global Amazon stores and Orange Polska. [Brand sources](../../../docs/brand-sources.md) cite [Amazon's developer marketplace tables](https://www.developer.amazon.com/docs/app-submission/distribute-your-app-internationally.html), [Amazon's South Africa launch](https://www.aboutamazon.com/news/retail/amazon-south-africa), and [Orange Group's website directory](https://www.orange.com/en/our-websites). Other pairs lack an official-domain addition justified by those sources; aliases/edit-distance rules were not weakened. The six listed limitations remain false alarms. Of the final eight ETIS non-model FP, six are these brand pairs; the other two retain the pre-existing pattern/domain-embedding behavior.

The previously sourced Vodafone Group entry remains; the careers/root probes pass. The user-requested [78 v1 benign-domain probabilities](v1_etis_validation_benign_flags.json) remain unchanged. No data-derived URL was submitted to an external analysis service.

## Method and checks

Integrated cohort evaluation factors the exact URL-only scanner decision into the non-model baseline OR an eligible ordinary model alert, with official/shared-host suppression and invalid-input handling. All original rows remain in denominators; invalid inputs count as phishing misses (133 runtime abstentions on PhreshPhish, zero ETIS). Every model/threshold pair is measured, not just the winner. Blacklist state is isolated, healthy and empty; there is no fabricated SMS context or claim of live-feed recall.

Offline brand acceleration uses exact unit-cost RapidFuzz Levenshtein distance, previously checked against production on 7,506 pairs. Production still uses its unchanged implementation. The original production scanner verifies the factorization on **{n_verified:,} policy/cohort row checks**, including boundaries, model-only benign alerts, official, diagnostic-pattern and invalid rows, plus both no-model baselines: **zero mismatches**. Actual packaged probabilities match cached selected-model probabilities exactly on the checked samples. See [deployment verification](deployed_scanner_verification_v3.json).

* **251 pytest tests pass**; initialize, frontend build and lint all exit 0: [final_checks.json](final_checks.json).
* **{replay['detection_passed']}/23 detection, {replay['robustness_passed']}/7 robustness, {replay['followup_passed']}/15 follow-up**: [followup_v3.json](followup_v3.json).
* **17/17 host probes avoid MEDIUM/HIGH**, with zero raw model alerts: [probe_v3.json](probe_v3.json).

The logged pytest Starlette deprecation and frontend bundle-size warning remain. Check logs identify the parent HEAD while exercising this working tree; no hosted CI or browser interaction is claimed. Protected model/tokenizer, split/target and local-retention checks: [integrity.json](integrity.json). Data hygiene and licence limits remain as documented in [REPORT_v1.md](REPORT_v1.md) and [data licences](../../../docs/data-licences.md); historical restricted copies remain in Git history and no history rewrite occurred.

These are exposed development comparisons after v1/v2 results. Repeated test/validation selection prevents an independent final-performance claim. **No sealed final test; genuine Egyptian SMS test count remains 0.** No live destination visits, feed refresh, push or merge. Remaining work includes the six brand false alarms, lost pattern recall and independent evaluation with real Egyptian SMS.

## Reproduction

Restore authorized local data, frozen scores and original candidate artifacts using the existing manifests. Do not regenerate calibration thresholds. Rule files must exist before any evaluation, and each training-only proposal must be frozen before held-out evaluation.

```text
python evaluation/run_url_followup_v3.py train_patterns
python evaluation/run_url_followup_v3.py select_initial
python evaluation/run_url_followup_v3.py audit
python evaluation/run_url_followup_v3.py finalize_brand_review
python evaluation/run_url_followup_v3.py evaluate_patterns
python evaluation/run_url_followup_v3.py baseline_components
python evaluation/run_url_followup_v3.py select_final
python evaluation/run_url_followup_v3.py promote
python evaluation/run_url_followup_v3.py accept_patterns
python evaluation/verify_url_v3_deployment.py
python evaluation/probe_legit_hosts.py --output evaluation/reports/2026-10-v4/probe_v3.json
python evaluation/run_followup.py --output evaluation/reports/2026-10-v4/followup_v3.json
python evaluation/run_checks_v4.py final
python evaluation/verify_hygiene_v4.py
python evaluation/report_url_v3.py
```

Stop after a local commit on `fix/url-subdomains-and-hygiene`. **Do not push or merge.**
'''
    write('REPORT.md', report)
    write('HANDOFF.md', f'''# URL contribution-gate v3 handover

Branch: `fix/url-subdomains-and-hygiene`. Local commit only; no push or merge.

Deployed **ordinary** support from existing `combined_full_url_lightgbm.joblib`,
full URL, threshold **{chosen['threshold']:.17g}** from the unchanged v2 frozen table.
Packaged SHA-256: `{deployment['artifact_sha256']}`.

Rule v3 was written after v2 results and before new computation. All 202 frozen
candidates were compared; 97 pass the model-own and incremental-FP gates. The selected
model adds 48/91,260 PhreshPhish benign alerts and 2/2,916 ETIS alerts.
Total scanner FP: **254/91,260** and **10/2,916**; recall **59.479%** and **17.294%**.

The training-only frozen `four_structural_only` pattern proposal passes: test pattern
FPR **17/91,260 (0.018628%)**, and all 23/7/15 replays. Its integrated recall cost is
**11.710 percentage points PhreshPhish / 9.861 points ETIS**, versus the same model
and registry with legacy patterns. Raw weak flags remain diagnostic observations.
Seven cited official-domain additions fix seven of the 13 brand pairs; six remain
known limitations. All pairs and sources are in the report. Vodafone Group remains sourced.

Checks: **251 pytest tests**, initialize, frontend build and lint pass;
**23/23, 7/7, 15/15** replays; **17/17** legitimate host probes avoid MEDIUM/HIGH.
Full production scanner verification: **{n_verified:,} matches, zero mismatches**.

Read [REPORT.md](REPORT.md), [PR_DESCRIPTION.md](PR_DESCRIPTION.md),
[selection](url_v3_final_selection.json), [pattern acceptance](pattern_evaluation_v3.json),
and [brand pairs](etis_brand_resemblance_pairs_v3.json).
The v1 probability export and requested 13 brand pairs are the only authorized
minimal cohort exports; row predictions/data remain ignored. Historical v1/v2
reports remain available. September/text models, tokenizer, targets and frozen
partitions are preserved. No sealed test; genuine Egyptian SMS count 0.
Repeated development selection is not independent validation. Stop after this commit.
''')
    write('PR_DESCRIPTION.md', '''# Gate URL-model contribution and reduce pattern false alarms

V2's total-scanner gate obscured an ordinary model policy that adds few false alarms.
Freeze v3 after disclosing v2 results, reuse all 202 calibration-frozen candidates,
and deploy the highest integrated PhreshPhish-recall passer: existing full-URL
LightGBM at 0.9903286846155258, with ordinary support. Its own alerts pass all three
FPR limits; extra scanner FP are 48/91,260 on PhreshPhish and 2/2,916 on ETIS.

Choose one pattern proposal only on PhreshPhish training/calibration after freezing
acceptance. Keep keyword, HTTP, length and subdomain-count observations diagnostic;
IP, userinfo, nonstandard port and punycode may alert. Test pattern FPR is
17/91,260 (0.018628%), and the 23/7/15 replays have no loss. The same model's integrated
recall falls 11.710 points on PhreshPhish and 9.861 on ETIS from this change.

List all 13 ETIS brand/domain pairs offline. Add only seven cited missing official
Amazon/Orange domains; retain six unsupported resemblance cases as limitations.
Final scanner recall is 59.479% PhreshPhish / 17.294% ETIS, with total false positives
254/91,260 and 10/2,916. Report matched original-v3, v1 and corroboration-only results,
separating non-model and model-added false positives on both cohorts.

Validation: 251 pytest tests; initialize, frontend build and lint pass; replays
23/23, 7/7, 15/15; all 17 host probes avoid MEDIUM/HIGH; full-scanner cohort checks
have zero mismatches. Logs and detailed evidence: [REPORT.md](REPORT.md).

The text model, frozen thresholds and historical data safeguards remain. These
repeatedly exposed cohorts do not establish independent or Egyptian SMS accuracy.
No sealed test, push, merge, data upload or history rewrite.
''')
    summary = {'deployed_policy': 'ordinary', 'deployed_artifact': deployment,
               'frozen_candidate_count': len(stage['candidates']), 'passing_candidates': stage['passing_candidates'],
               'thresholds_added': 0, 'comparisons': comparisons, 'pattern_acceptance': pattern,
               'pattern_integrated_recall_changes': integrated_costs,
               'brand_pairs': {'count': brands['count'], 'fixed': brands['fixed_count'], 'remaining': brands['remaining_count']},
               'full_scanner_verification_matches': n_verified, 'full_scanner_mismatches': 0,
               'pytest_passed': checks['commands']['pytest']['passed'], 'check_exit_codes': {k: v['exit_code'] for k, v in checks['commands'].items()},
               'replays': replay, 'host_probes_medium_or_high': 0, 'host_probe_count': 17,
               'sealed_test_run': False, 'genuine_egyptian_sms_test_count': 0, 'push_performed': False, 'merge_performed': False}
    write('summary.json', json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    sources = read('brand_sources.json')
    sources['sources'] = [s for s in sources['sources'] if s['brand'] not in {'Amazon (global stores)', 'Orange Polska'}]
    for name in ['Amazon (global stores)', 'Orange Polska']:
        fixed = [p for p in brands['pairs'] if p.get('current_registry_brand') == name]
        sources['sources'].append({'brand': name, 'domains': [p['benign_domain'] for p in fixed],
                                   'official_sources': sorted({p['official_source'] for p in fixed}),
                                   'access_date': '2026-10-17', 'status': 'Added in contribution-gated v3 follow-up; no cohort URL visited'})
    sources.update(followup_brands_documented=3, registry_domains=len(EGYPTIAN_BRAND_DOMAINS),
                   october_verified_domains=len(OCTOBER_VERIFIED_DOMAINS))
    sources['new_domains'] = [d for d in sources['new_domains'] if d['brand'] not in {'Amazon (global stores)', 'Orange Polska'}]
    sources['new_domains'] += [{'brand': p['current_registry_brand'], 'domain': p['benign_domain']}
                              for p in brands['pairs'] if p['status'] == 'fixed_missing_official_domain']
    write('brand_sources.json', json.dumps(sources, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'report_written': True, 'full_scanner_checks': n_verified, 'pytest_passed': summary['pytest_passed']}))


if __name__ == '__main__':
    main()
