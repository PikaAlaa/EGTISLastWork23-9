"""Render current handover from measured v2 results, without rerunning selection."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v4'


def read(name):
    return json.loads((OUT / name).read_text(encoding='utf-8'))


def pct(value):
    return 'undefined' if value is None else f'{value * 100:.3f}%'


def main():
    result = read('url_v2_comparison.json')
    selected = result['selection']
    deployed = selected['deployed_candidate']
    policy = selected['deployed_policy']
    best = selected['best_v2_model']
    v1 = result['comparators']['v1_selected']
    v3 = result['comparators']['old_v3_deployed']
    metadata = json.loads((ROOT / 'ml/models/url_host_deployment.json').read_text())
    checks = read('final_checks.json')
    replay = read('followup_v2.json')
    probes = read('probe_v2.json')
    frozen = read('url_v2_frozen_thresholds.json')
    flags = read('v1_etis_validation_benign_flags.json')
    verification = read('deployed_scanner_verification.json')
    names = [('old v3 deployed', v3, 'ordinary'), ('v1 selected', v1, 'ordinary')]
    if best:
        names.append(('best v2 model, ordinary policy', best, 'ordinary'))
    if policy == 'ordinary' and (best is None or (best['artifact_path'], best['threshold']) != (deployed['artifact_path'], deployed['threshold'])):
        names.append(('deployed ordinary policy', deployed, 'ordinary'))
    names.append(('corroboration-only (deployed)' if policy == 'corroboration_only' else 'corroboration-only comparator', deployed, 'corroboration_only'))
    lines = ['# ETIS URL selection v2 follow-up', '',
             f"Deployed **{policy}** with `{deployed['artifact_path']}` at **{deployed['threshold']:.17g}** "
             f"(`{deployed['representation']}`). The deployed text model remains unchanged.", '',
             'The v1 selection was unacceptable on ETIS legitimate main domains: '
             '**78/2,916 false positives (2.675%)**, versus **2/2,916 (0.069%)** for old v3. '
             'The old subdomain-only gate did not protect this cohort. '
             '[Rule v2](url_selection_rule_v2.md) was written **after seeing v1 results and before new v2 computation**. '
             'These are exposed development comparisons, not independent final validation.', '',
             '## Frozen selection and outcome', '',
             'Hard limits: PhreshPhish benign-subdomain FPR ≤1%, ETIS-validation FPR ≤0.5%, '
             'and overall PhreshPhish-test FPR ≤0.5%. Among passing candidates, maximize overall '
             'PhreshPhish-test recall. Ordinary deployment also has to meet these limits in the integrated scanner.', '',
             f"Evaluated **{len(frozen['models'])} distinct existing URL artifacts × six calibration FPR caps** "
             f"(1%, 0.5%, 0.1%, 0.05%, 0.01%, 0%), deduplicated to **{len(result['candidates'])} model/threshold candidates**. "
             'Every candidate was also evaluated under corroboration-only. Text artifacts are excluded. '
             'Byte-identical URL copies are aliases; all historical, time, shortcut, host and full-URL URL models are included. '
             'No model was refitted.', '',
             'The threshold table was saved before evaluation predictions in '
             '[url_v2_frozen_thresholds.json](url_v2_frozen_thresholds.json). '
             'PhreshPhish-protocol artifacts use their original setting-specific calibration partition. '
             'Historical ETIS artifacts use external calibration excluding all ETIS training domains and the entire '
             'archived PY35J Tranco domain list; historical validation-selected thresholds are comparators only. '
             'Frozen fitting/calibration fingerprints and evaluation membership are checked. Historical models retain '
             'their original fitting exposure; this does not claim that old fitting excluded the later external test domains.', '',
             f"Passing model candidates: **{selected['model_passing_candidates']}**; passing ordinary integrated policies: "
             f"**{selected['ordinary_passing_candidates']}**; passing corroboration-only integrated policies: "
             f"**{selected['corroboration_passing_candidates']}**.", '']
    if best:
        lines += [f"The highest-recall v2 model is `{best['artifact_path']}` at **{best['threshold']:.17g}** "
                  f"({pct(best['cohorts']['phreshphish_test']['model']['recall'])} model recall).", '']
    else:
        lines += ['Best v2 candidate: **none**. No calibration-selected candidate satisfies all three model limits; '
                  'its integrated recall and FP counts are therefore undefined.', '']
    if policy == 'corroboration_only':
        lines += ['**No ordinary integrated policy satisfies rule v2. The required fallback is deployed.** '
                  'The URL model never creates MEDIUM alone; it only contributes alongside brand resemblance, '
                  'a pattern flag, a blacklist domain match, or a secret request. Official/shared-host suppression '
                  'and decisive/incomplete precedence remain. A bare model alert also cannot corroborate a high '
                  'text-model score into HIGH.', '']
        if not selected['corroboration_passing_candidates']:
            lines += ['**The fallback itself does not satisfy all three total-scanner FPR limits.** '
                      'Existing non-model signals exceed the limits. This is the explicitly requested fallback, '
                      'not a passing-FPR deployment claim. Their remaining false alarms require separate rule-policy work.', '']
            for cohort, label in [('etis_grouped_validation', 'ETIS validation'), ('phreshphish_test', 'PhreshPhish test')]:
                entry = result['scanner_baseline'][cohort]
                m = entry['metrics']
                reasons = ', '.join(f"`{name}`: {count}" for name, count in entry['benign_alert_reasons'].items())
                lines += [f"{label} without model support: **{m['fp']}/{m['benign_n']} ({pct(m['false_positive_rate'])})**; "
                          f"benign alert reasons: {reasons}.", '']
    lines += ['## Model hard-limit comparison', '',
              '| Model / threshold | Test recall | Test FP / benign (FPR) | ETIS FP / benign (FPR) | Subdomain FP / benign (FPR) | Model gate |',
              '|---|---:|---:|---:|---:|---|']
    for label, c in [('old v3', v3), ('v1 selected', v1)] + ([('best v2', best)] if best else []):
        cc = c['cohorts']
        def fp(name):
            m = cc[name]['model']
            return f"{m['fp']}/{m['benign_n']} ({pct(m['false_positive_rate'])})"
        lines.append(f"| {label}, {c['threshold']:.17g} | {pct(cc['phreshphish_test']['model']['recall'])} | "
                     f"{fp('phreshphish_test')} | {fp('etis_grouped_validation')} | "
                     f"{fp('phreshphish_test_benign_subdomains')} | {'pass' if c['passes_model_v2'] else 'fail'} |")
    lines += ['', '## Integrated scanner: MEDIUM or HIGH', '',
              'Denominators: ETIS validation **5,973 phishing / 2,916 benign**; PhreshPhish test '
              '**76,800 phishing / 91,260 benign**. All original rows are retained.', '',
              '| Policy | ETIS recall | ETIS FP / benign (FPR) | PhreshPhish-test recall | PhreshPhish-test FP / benign (FPR) |',
              '|---|---:|---:|---:|---:|']
    for label, c, kind in names:
        et = c['cohorts']['etis_grouped_validation'][kind]
        ph = c['cohorts']['phreshphish_test'][kind]
        lines.append(f"| {label} | {pct(et['recall'])} | {et['fp']}/{et['benign_n']} ({pct(et['false_positive_rate'])}) | "
                     f"{pct(ph['recall'])} | {ph['fp']}/{ph['benign_n']} ({pct(ph['false_positive_rate'])}) |")
    lines += ['', '| Policy | Integrated benign-subdomain FP / benign (FPR) |', '|---|---:|']
    for label, c, kind in names:
        m = c['cohorts']['phreshphish_test_benign_subdomains'][kind]
        lines.append(f"| {label} | {m['fp']}/{m['benign_n']} ({pct(m['false_positive_rate'])}) |")
    lines += ['', 'All policies use the same final sourced registry, original cohort rows, and isolated healthy empty '
              'blacklist. Thus the comparison isolates model/policy effects; old v3 and v1 names refer to their historical '
              'artifacts and thresholds, not a claim of reproducing all historical feed/registry state. '
              'URLs are submitted in the URL field, with no fabricated SMS or sender context. '
              'Invalid/overlength inputs abstain and count as phishing misses. Outer whitespace is stripped as in the runtime. '
              'No live blacklist recall or SMS-context recall is measured.', '',
              'Every row first goes through the integrated scanner with URL-model support absent. '
              'For URL-only inputs the exact MEDIUM/HIGH result is that baseline OR an unsuppressed model alert. '
              'Under corroboration-only, each authorized corroborator already creates a warning, so the model adds no '
              'new MEDIUM/HIGH detections on these URL-only cohorts. This exact factoring avoids repeating invariant '
              'brand/SQL checks for every threshold. Boundary, model-only, baseline-positive and invalid rows are '
              'rescanned through the complete scanner for **every candidate**, with equivalence asserted. '
              'Per-candidate model, ordinary, corroboration and subdomain results and check counts are in '
              '[url_v2_comparison.json](url_v2_comparison.json).', '', '## Recall cost', '']
    acceleration = result.get('evaluation_acceleration')
    if acceleration:
        lines[-2:-2] = [
            f"Evaluation-only acceleration uses `{acceleration['library']}` for exact unit-cost Levenshtein distance "
            f"(no preprocessing or cutoff), checked against the production dynamic-programming implementation on "
            f"**{acceleration['original_distance_equivalence_pairs']} pairs**. "
            'The production brand implementation is unchanged. '
            '[API semantics](https://rapidfuzz.github.io/RapidFuzz/Usage/distance/Levenshtein.html) and the saved '
            'equivalence counts document this speedup; no matching threshold or rule changed.', '']
    if policy == 'corroboration_only':
        lines += ['All corroboration-only candidates have the same MEDIUM/HIGH outcomes on these URL-only rows. '
                  'The underlying fallback artifact and threshold follow the frozen deterministic tie rule '
                  '(integrated recall, summed cohort FPR, artifact path, threshold). This tie does not establish '
                  'that its model is superior or that its threshold is optimal for SMS with secret requests.', '']
    for cohort, label in [('etis_grouped_validation', 'ETIS validation'), ('phreshphish_test', 'PhreshPhish test')]:
        after = deployed['cohorts'][cohort]['corroboration_only']['recall']
        before = v1['cohorts'][cohort]['ordinary']['recall']
        same = deployed['cohorts'][cohort]['ordinary']['recall']
        best_cost = f", **{100 * (best['cohorts'][cohort]['ordinary']['recall'] - after):.3f} points** versus the best v2 model's ordinary policy" if best else ''
        lines.append(f"* {label}: corroboration-only recall **{pct(after)}**, a loss of "
                     f"**{100 * (before - after):.3f} percentage points** versus v1 ordinary support, and "
                     f"**{100 * (same - after):.3f} points** versus ordinary support from the same underlying model/threshold{best_cost}.")
    lines += ['', 'This cost is the loss of model-only warnings. It does not measure the model’s possible benefit '
              'when genuine message context, secret requests or live threat intelligence are available.', '',
              '## Benign-domain flags and Vodafone', '',
              f"[v1_etis_validation_benign_flags.json](v1_etis_validation_benign_flags.json) lists all **{flags['flagged_rows']} rows / "
              f"{flags['unique_domains']} unique domains**, their registered domains, row IDs, probabilities and the v1 threshold. "
              'These domains were not visited or resolved.', '',
              'Added `vodafone.com` as **Vodafone Group**, separate from Vodafone Egypt and Vodafone Cash. '
              'The [official Group company page](https://www.vodafone.com/our-company/vodafone-at-a-glance) '
              'links directly to `careers.vodafone.com` in its Careers navigation. '
              'See [brand-sources.md](../../../docs/brand-sources.md) for the dated provenance. '
              'The careers subdomain itself was not visited. Generic official-domain handling now covers it.', '',
              f"Final legitimate-host probes: **{probes['summary']['medium_or_high']}/{probes['summary']['hosts']} MEDIUM/HIGH**, "
              f"with {probes['summary']['raw_above_threshold']} raw model flags. "
              'Probe results are exposed regressions, not population FPR estimates. '
              'See [probe_v2.json](probe_v2.json).', '', '## Verification and handover', '']
    for name, entry in checks['commands'].items():
        lines.append(f"* `{name}`: exit **{entry['exit_code']}**" + (f", **{entry['passed']} passed**" if name == 'pytest' else '') + '.')
    s = replay['summary']
    lines += [f"* Replays: **{s['detection_passed']}/{s['detection_total']} detection**, "
              f"**{s['robustness_passed']}/{s['robustness_total']} robustness**, "
              f"**{s['followup_passed']}/{s['followup_total']} follow-up**. The NBE notice remains non-HIGH.", '',
              'Actual logs: [final_checks.json](final_checks.json), [followup_v2.json](followup_v2.json). '
              f"Packaged `score_url` and the original production scanner also match the evaluated decisions on "
              f"**{sum(c['sampled_rows'] for c in verification['cohorts'].values())} selected boundary/regression rows**, "
              'including v1 benign flags and invalid inputs; '
              '[deployment verification](deployed_scanner_verification.json). '
              'The local Python 3.12.10 interpreter was repaired inside the ignored workspace after the prior '
              'venv’s base interpreter was found missing. Dependencies and research data remain local. '
              'Pytest uses a writable local cache. Existing upstream deprecation and frontend bundle-size warnings '
              'are retained in logs; no hosted CI or browser interaction is claimed. '
              'The [initial v2 check attempt](v2_initial_checks.json) exposed an inaccessible optional tldextract disk cache '
              '(four test failures). The parser now disables that cache while retaining the same offline bundled suffix '
              'snapshot and grouping rules. The complete checks and replays were rerun successfully after this fix.', '',
              '## Preserved scope and limits', '',
              'The earlier sender-display feature, registry entries, dependency fix, data untracking and local '
              'release-artifact retention remain. Historical hygiene, licences and the original engineering evidence '
              'are in [REPORT_v1.md](REPORT_v1.md), [data_hygiene.json](data_hygiene.json), '
              '[release_manifest.json](release_manifest.json) and [data licences](../../../docs/data-licences.md). '
              'Removed data remains in Git history and on GitHub; no history rewrite was performed. '
              'September model/tokenizer, the deployed text model, targets and frozen partitions are preserved.', '',
              'Genuine Egyptian SMS test count remains **0**. No sealed final test ran. PhreshPhish test and ETIS '
              'validation have now informed repeated development selection and cannot substantiate independent final '
              'or Egyptian-traffic performance claims. Row-wise uncertainty does not account for repeated domains; '
              'live feed state and message context are not available in the URL cohorts. '
              'Corroboration-only can still warn on benign URLs through existing brand/pattern rules. '
              'No candidate URLs were visited, resolved or sent to external analysis services.', '',
              '## Reproduction', '', '```text',
              'python evaluation/run_url_selection_v2.py calibrate',
              'python evaluation/run_url_selection_v2.py evaluate',
              'python evaluation/promote_url_v2.py',
              'python evaluation/verify_url_v2_deployment.py',
              'python evaluation/probe_legit_hosts.py --output evaluation/reports/2026-10-v4/probe_v2.json',
              'python evaluation/run_followup.py --output evaluation/reports/2026-10-v4/followup_v2.json',
              'python evaluation/run_checks_v4.py final', 'python evaluation/report_url_v2.py', '```', '',
              'Restore authorized local data and research artifacts using the earlier pinned manifests before evaluation. '
              'The packaged scanner and backend checks do not require those corpora. '
              'Stop after committing on `fix/url-subdomains-and-hygiene`; **no push or merge**.', '']
    (OUT / 'REPORT.md').write_text('\n'.join(lines), encoding='utf-8')
    handoff = f"""# URL selection v2 handover

Branch: `fix/url-subdomains-and-hygiene`. This follow-up is committed locally; no push or merge.

Deployed `{policy}` using `{deployed['artifact_path']}` at `{deployed['threshold']:.17g}`,
representation `{deployed['representation']}`. Packaged artifact SHA-256:
`{metadata['artifact_sha256']}`.

Rule v2 was written after v1 results and before new computation. Model-passing candidates:
{selected['model_passing_candidates']}; ordinary integrated passing candidates:
{selected['ordinary_passing_candidates']}; corroboration-only integrated passing candidates:
{selected['corroboration_passing_candidates']}. The report explicitly records any remaining
non-model FPR failures and the recall cost. Do not restore the v1 deployment from its historical report.

Checks: {checks['commands']['pytest']['passed']} pytest tests; initialize, frontend build and lint
all exit 0. Replays: {s['detection_passed']}/{s['detection_total']},
{s['robustness_passed']}/{s['robustness_total']}, {s['followup_passed']}/{s['followup_total']}.
Vodafone Group provenance is in `docs/brand-sources.md`; final legitimate-host warnings:
{probes['summary']['medium_or_high']}/{probes['summary']['hosts']}.

Read [REPORT.md](REPORT.md), [PR_DESCRIPTION.md](PR_DESCRIPTION.md),
[url_v2_comparison.json](url_v2_comparison.json), and
[v1_etis_validation_benign_flags.json](v1_etis_validation_benign_flags.json).
The latter is the explicitly requested minimal benign-domain export; all other row predictions stay ignored.

Research data and historical weights remain local/ignored and hash-verified. No sealed final test,
authentic Egyptian SMS validation, feed refresh, history rewrite, push or merge. Further
scanner-rule FPR work and independent validation remain. Stop after this commit.
"""
    (OUT / 'HANDOFF.md').write_text(handoff, encoding='utf-8')
    pr = f"""# Prevent URL-model-only false alarms under rule v2

The v1 subdomain gate selected a model that raised ETIS-validation benign false positives
from 2/2,916 to 78/2,916. Freeze rule v2 after disclosing those observed results, calibrate
all existing URL models without test/validation threshold tuning, and compare integrated
scanner outcomes under ordinary and corroboration-only support.

Deploy `{policy}` at `{deployed['threshold']:.17g}`. There are
{selected['ordinary_passing_candidates']} ordinary policies satisfying all three integrated
FPR limits; the report quantifies fallback recall cost and residual non-model false positives.
Save the 78 benign-domain model flags and probabilities without visiting them. Source Vodafone
Group's `vodafone.com` from its official company page, fixing the careers/root registry alarms.

Validation: {checks['commands']['pytest']['passed']} pytest tests, database initialization,
frontend build and lint; replay {s['detection_passed']}/{s['detection_total']} detection,
{s['robustness_passed']}/{s['robustness_total']} robustness,
{s['followup_passed']}/{s['followup_total']} follow-up; all
{probes['summary']['hosts']} legitimate host probes produce {probes['summary']['medium_or_high']} MEDIUM/HIGH warnings.

Earlier data hygiene, sender context, dependency and registry changes remain. No sealed final
test or genuine Egyptian SMS accuracy is claimed; the selection cohorts are exposed development
evidence. Historical restricted data remains in Git history. No push, merge, upload or history rewrite.
Detailed model and scanner tables, sources, checks and remaining work: `evaluation/reports/2026-10-v4/REPORT.md`.
"""
    (OUT / 'PR_DESCRIPTION.md').write_text(pr, encoding='utf-8')
    summary = {'deployed_policy': policy, 'deployed_artifact': metadata, 'selection': selected,
               'final_tests_passed': checks['commands']['pytest']['passed'], 'replay': s,
               'probe_after': probes['summary'], 'flagged_v1_benign_rows': flags['flagged_rows'],
               'sealed_test_run': False, 'genuine_egyptian_sms_test_count': 0,
               'push_performed': False, 'merge_performed': False}
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
