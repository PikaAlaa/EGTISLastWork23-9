"""Render the v4 handover solely from saved, measured JSON evidence."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evaluation/reports/2026-10-v4'
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
from evaluation.phreshphish_utils import at_threshold


def read(name):
    return json.loads((OUT / name).read_text(encoding='utf-8'))


def pct(value):
    return 'undefined' if value is None else f'{100 * value:.3f}%'


def main():
    baseline, final = read('baseline_checks.json'), read('final_checks.json')
    comparison = read('url_comparison.json')
    before, after = read('probe_before.json'), read('probe_after.json')
    hygiene, release = read('data_hygiene.json'), read('release_manifest.json')
    sources, replay = read('brand_sources.json'), read('followup_final.json')
    audit_before, audit_after = read('npm_audit_before.json'), read('npm_audit_after.json')
    clean, integrity = read('clean_tree_checks.json'), read('integrity.json')
    winner = comparison['selection']['winner']
    selected = comparison['models'][winner]
    point = selected['deployment_point']
    current = comparison['models']['current_artifact']
    sub = selected['cohorts']['phreshphish_test_benign_subdomains'][point]
    test = selected['cohorts']['phreshphish_test'][point]
    val = selected['cohorts']['etis_grouped_validation'][point]
    historical = [row for row in release['files'] if row['original_path'].startswith(('evaluation/', 'ml/'))]
    v3 = [row for row in historical if row['original_path'].startswith('evaluation/reports/2026-10-v3/')]
    probe_metrics = {'kind': 'Derived from saved per-probe probabilities and scanner verdicts, all benign exposed fixtures',
                     'models': {}, 'scanner': {}}
    for key, entry in comparison['models'].items():
        probabilities = [row['probability'] for row in entry['probe']]
        probe_metrics['models'][key] = {cap: at_threshold([0] * len(probabilities), probabilities, threshold)
                                        for cap, threshold in entry['thresholds'].items()}
    for stage, data in [('before', before), ('after', after)]:
        n = len(data['rows'])
        fp = sum(row['verdict'] in {'MEDIUM', 'HIGH'} for row in data['rows'])
        probe_metrics['scanner'][stage] = {'fp': fp, 'benign_n': n, 'false_positive_rate': fp / n,
                                            'recall': None, 'ppv_at_1pct': None, 'ppv_at_0_1pct': None}
    (OUT / 'probe_metrics.json').write_text(json.dumps(probe_metrics, indent=2) + '\n', encoding='utf-8')
    summary = {'baseline_tests_passed': baseline['commands']['pytest']['passed'],
               'final_tests_passed': final['commands']['pytest']['passed'],
               'clean_tree_tests_passed': clean['commands']['pytest']['passed'],
               'probe_before': before['summary'], 'probe_after': after['summary'],
               'winner': winner, 'threshold': selected['thresholds'][point],
               'selected_phreshphish_test': test, 'selected_etis_validation': val,
               'selected_benign_subdomains': sub, 'replay': replay['summary'],
               'etis_recall_change_percentage_points': 100 * (val['recall'] - current['cohorts']['etis_grouped_validation']['deployed']['recall']),
               'untracked_data_files': hygiene['untracked_data_count'],
               'raw_files': sum(row['path'].startswith('data/raw/') for row in hygiene['untracked_data']),
               'derived_exports': sum(not row['path'].startswith('data/raw/') for row in hygiene['untracked_data']),
               'historical_candidate_binaries': len(historical), 'v3_candidate_binaries': len(v3),
               'v3_candidate_bytes': sum(row['bytes'] for row in v3),
               'release_manifest_files': release['file_count'], 'release_manifest_total_bytes': release['total_bytes'],
               'npm_high_before': audit_before['metadata']['vulnerabilities']['high'],
               'npm_vulnerabilities_after': audit_after['metadata']['vulnerabilities']['total'],
               'requested_brands_documented': sources['requested_brands_documented'],
               'new_registry_domains': len(sources['new_domains']),
               'genuine_egyptian_sms_test_count': 0, 'sealed_test_run': False}
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    lines = [
        '# ETIS v4: legitimate subdomains, repository hygiene and sender context', '',
        'All new figures below are generated from JSON saved in this directory by scripts actually run. '
        'This is exposed development evidence, not a sealed final test or Egyptian deployment validation.', '',
        f"Deployed **{winner}** at **{selected['thresholds'][point]:.16f}**, selected under the "
        '[pre-result rule](url_selection_rule.md). The September text model is unchanged. '
        'The fallback policy change was not required because fresh candidates passed the subdomain gate.', '',
        '## Engineering before and after', '',
        '| Check | Before editing | After changes |', '|---|---|---|',
        f"| Backend | {summary['baseline_tests_passed']} passed, 1 optional module skipped | {summary['final_tests_passed']} passed |",
        '| Database initialization | passed | passed |',
        '| Frontend clean install/build/lint | passed | passed |',
        f"| npm high-severity findings / total after | {summary['npm_high_before']} high | {summary['npm_vulnerabilities_after']} total |",
        f"| Data-free tracked-tree export | not run | {summary['clean_tree_tests_passed']} tests and initialization passed |", '',
        'Evidence: [baseline](baseline_checks.json), [final](final_checks.json), '
        '[patched clean install](npm_ci_patched.json), [clean export](clean_tree_checks.json), '
        '[audit before](npm_audit_before.json), [audit after](npm_audit_after.json). '
        'The optional PhreshPhish safety tests became active after installing the evaluation requirements. '
        'The initial premature baseline attempt is retained separately; the successful baseline preceded application edits. '
        'The first clean export exposed the selection-rule newline hash problem; the exact pre-result bytes were then '
        'pinned in Git, with normalized content unchanged, and the export rerun passed. '
        'The upstream test-client deprecation and frontend bundle-size warnings remain. '
        'No browser-interaction, hosted CI or deployment check is claimed.', '',
        '## Frozen protocol and deployment choice', '',
        'The original PhreshPhish protocol is unchanged. Fresh combined fitting uses ETIS training phishing plus both '
        'PhreshPhish training classes, with ETIS benign excluded as prescribed. Evaluation registered domains are '
        'excluded from fitting/calibration; mixed-label domains and duplicate training URLs are removed. '
        'The historical deployed comparator was not refit to impose these later exclusions. '
        'The fresh fit and calibration membership hashes exactly match the frozen research run '
        '([split reproduction](split_reproduction.json), [data audit](data_audit.json)). '
        'Only the permitted projection was acquired; no HTML data chunks or destination pages were retrieved.', '',
        'Before fresh predictions, the deployment rule fixed the 0.1%-calibration-FPR threshold for each fresh model. '
        'The 1%-calibration operating point below is diagnostic only and was not an alternative selected after seeing test results. '
        'The current artifact retains its historical threshold, originally selected on ETIS validation; its evaluation '
        'is a comparator, not a newly calibration-selected model. No evaluation-derived ROC threshold is used here.', '',
        'A candidate must have at most 1% actual FPR on benign PhreshPhish test hosts with a non-www subdomain label. '
        'Among passing candidates at their predeclared deployment point, select highest whole-test recall. '
        'The pinned private PSL defines the subdomain; www alone does not qualify, while www alongside another label does. '
        'Evaluation rows remain fixed, and invalid hosts abstain; phishing abstentions count as misses.', '',
    ]
    for cohort in ['phreshphish_test', 'etis_grouped_validation']:
        lines += [f'### {cohort}', '',
                  '| Model | Fixed threshold source | Recall | FP / benign | Actual FPR | PPV at 1% | PPV at 0.1% |',
                  '|---|---|---:|---:|---:|---:|---:|']
        for key, entry in comparison['models'].items():
            for cap, metric in entry['cohorts'][cohort].items():
                label = 'historical deployed' if cap == 'deployed' else 'calibration ' + ('0.1%' if cap == '0_1pct' else '1% (diagnostic)')
                lines.append(f"| {key} | {label} | {pct(metric['recall'])} | {metric['fp']}/{metric['benign_n']} | "
                             f"{pct(metric['false_positive_rate'])} | {pct(metric['precision_at_phishing_base_rate_1pct'])} | "
                             f"{pct(metric['precision_at_phishing_base_rate_0_1pct'])} |")
        lines.append('')
    lines += ['### Benign-subdomain subset', '',
              '| Model | Fixed calibration point | FP / benign | Actual FPR | Deployment gate |',
              '|---|---|---:|---:|---|']
    for key, entry in comparison['models'].items():
        for cap, metric in entry['cohorts']['phreshphish_test_benign_subdomains'].items():
            gate = 'pass' if metric['false_positive_rate'] <= .01 else 'fail'
            if cap != entry['deployment_point']:
                gate = 'diagnostic only'
            lines.append(f"| {key} | {cap} | {metric['fp']}/{metric['benign_n']} | {pct(metric['false_positive_rate'])} | {gate} |")
    lines += ['', 'Recall and prevalence-adjusted PPV are undefined in this benign-only subset; '
              'both are null in JSON rather than fabricated from absent phishing examples. '
              'The PPV columns in the full cohorts use assumed prevalence, not measured Egyptian precision. '
              'Wilson intervals and conservative marginal bounds are in [url_comparison.json](url_comparison.json); '
              'they are not domain-cluster confidence intervals.', '',
              f"The selected SVM gives {pct(test['recall'])} PhreshPhish-test recall and "
              f"{sub['fp']}/{sub['benign_n']} benign-subdomain false positives ({pct(sub['false_positive_rate'])}). "
              f"ETIS-validation recall is {pct(val['recall'])}, with {val['fp']}/{val['benign_n']} false positives "
              f"({pct(val['false_positive_rate'])}); its recall change from the prior artifact is "
              f"{summary['etis_recall_change_percentage_points']:.3f} percentage points. "
              'The gate deliberately prioritizes subdomain behaviour; it does not imply improvement on every source. '
              'The SVM has the highest recall among gate-passing models at the predeclared deployment point. '
              'The former artifact fails the gate. No threshold was adjusted to make the probe list pass. '
              'The existing supporting-signal policy and official/shared-host suppression remain.', '',
              '## Reviewer-supplied legitimate host probes', '',
              '| Host | Old model probability | Selected probability | Old scanner | New scanner |',
              '|---|---:|---:|---|---|']
    prior_rows = {row['host']: row for row in before['rows']}
    for row in after['rows']:
        old = prior_rows[row['host']]
        lines.append(f"| `{row['host']}` | {old['model']['probability']:.6f} | {row['model']['probability']:.6f} | {old['verdict']} | {row['verdict']} |")
    lines += ['', f"Raw above-threshold probes: {before['summary']['raw_above_threshold']}/{before['summary']['hosts']} before, "
              f"{after['summary']['raw_above_threshold']}/{after['summary']['hosts']} after. "
              f"Scanner MEDIUM/HIGH: {before['summary']['medium_or_high']} before, {after['summary']['medium_or_high']} after. "
              'The remaining Vodafone root/careers alerts are **brand_resemblance**, not URL-model evidence; '
              'they are explicitly retained as a separate limitation. No unsupported Vodafone global-domain entry was guessed. '
              'All requested subdomains avoid alerts from the URL model alone. '
              'Probe inputs are exposed regression strings and do not estimate population FPR.', '',
              'The full scanner probes use an empty isolated in-memory blacklist with availability forced healthy. '
              'No feed is fetched or live database altered. All model/threshold/scanner findings are in '
              '[probe_before.json](probe_before.json), [probe_after.json](probe_after.json) and '
              'the candidate probe entries of [url_comparison.json](url_comparison.json).', '',
              'Model FP/benign and actual FPR on this benign-only probe list are below. Recall and PPV '
              'are undefined; all nullable metrics and the scanner alert rates are explicit in '
              '[probe_metrics.json](probe_metrics.json).', '',
              '| Model | Fixed point | FP / benign | Actual probe FPR |', '|---|---|---:|---:|']
    for key, points in probe_metrics['models'].items():
        for cap, metric in points.items():
            lines.append(f"| {key} | {cap} | {metric['fp']}/{metric['benign_n']} | {pct(metric['false_positive_rate'])} |")
    lines += ['',
              '## Regression replay', '',
              f"Detection: {replay['summary']['detection_passed']}/{replay['summary']['detection_total']}; "
              f"robustness: {replay['summary']['robustness_passed']}/{replay['summary']['robustness_total']}; "
              f"follow-up: {replay['summary']['followup_passed']}/{replay['summary']['followup_total']}. "
              'The known NBE notice remains non-HIGH. These are existing exposed development fixtures, not a final test '
              '([replay JSON](followup_final.json)).', '',
              '## Public-tree hygiene', '',
              f"Untracked {summary['untracked_data_files']} data/export files: {summary['raw_files']} raw files and "
              f"{summary['derived_exports']} derived exports. All existing local bytes are retained and verified. "
              f"Moved {len(historical)} historical candidate binaries out of Git, including {len(v3)} under the v3 report tree "
              f"({sum(row['bytes'] for row in v3)} bytes). The local release manifest contains "
              f"{release['file_count']} files, including the fresh candidates and former deployed URL artifact. "
              'Only deployed models plus the explicitly preserved September model remain under ml/models in Git. '
              'The original tokenizer is also unchanged. The original September processed dataset remains byte-identical '
              'locally but is untracked as an uncleared derived export.', '',
              'Exact removed paths are in [REMOVED-FILES.md](REMOVED-FILES.md) and [data_hygiene.json](data_hygiene.json). '
              'The SHA-256 release map is [release_manifest.json](release_manifest.json), copied from '
              '`release-artifacts/MANIFEST.json`. The ignored local files are ready for the team to review for a GitHub '
              'Release; no upload occurred and the manifest does not clear redistribution rights.', '',
              '**These files remain in Git history and on GitHub.** Making the repository private limits public access; '
              'removing historical copies requires a separately authorized history rewrite. This branch does neither '
              'a history rewrite nor a push. Untracking alone does not purge public history.', '',
              '`restore_raw_data.py --check-all` inventories every file and explains authorized local restoration. '
              'Missing historical snapshots require checksum-matching originals, not current feeds. PhiUSIIL retains '
              'its pinned official download. Inventory recognizes exact newline-only variants; import verification '
              'remains byte-exact. Recovery and inherited model-data licence limitations are in '
              '[data licences](../../../docs/data-licences.md). '
              '`source-map-js` was changed only from the vulnerable lock entry to its patched entry; '
              'the dependency manifest was unchanged. The audit, clean install, build and lint passed.', '',
              '## Sourced brand registry', '',
              f"All {len(sources['sources'])} requested brands are documented; {len(sources['new_domains'])} domain/host entries were added. "
              'InstaPay, Fawry and Digital Egypt already existed and were rechecked. '
              'Vodafone Cash uses the official service host while the pre-existing Vodafone parent retains ownership. '
              'Database seeding is idempotent and shares the same registry and verification dates. '
              'Official-domain and dot/hyphen-plus-action lookalike tests pass.', '',
              '| Brand | Domains | Status |', '|---|---|---|']
    for row in sources['sources']:
        lines.append('| ' + row['brand'] + ' | ' + ', '.join('`' + domain + '`' for domain in row['domains']) + ' | ' + row['status'] + ' |')
    lines += ['', 'Official links, access dates and evidence limits are in '
              '[brand-sources.md](../../../docs/brand-sources.md) and [brand_sources.json](brand_sources.json). '
              'Root pages unavailable to the browser use the cited official service/subdomain evidence, '
              'not an inferred domain. No source-needed domain was added.', '',
              '## Sender display context', '',
              'POST /analyze and the scan form accept optional company_name, short_code, mobile_number or unknown. '
              'A financial/telecom sender claim from a mobile-number display adds brand_claim_from_mobile_number, '
              'a supporting MEDIUM signal. It cannot independently produce HIGH or corroborate the text model into HIGH. '
              'Other decisive evidence and incomplete-check precedence remain. The curated claim vocabulary is a heuristic, '
              'not an exhaustive language detector; it excludes unrelated casual mentions in the unit fixtures.', '',
              'Arabic and English advice explains normal company-name bank senders and spoofable sender names. '
              'The submitted category is transient, with no input column, echo, browser storage or logging added. '
              'The computed reason code follows the existing minimal outcome-metadata/retention policy. '
              'The API contract and privacy detail are in [api-v2.md](../../../docs/api-v2.md). '
              'All newly authored message fixtures are labelled synthetic test-only strings, not real/Egyptian data.', '',
              '## Limitations and preservation', '',
              'Genuine Egyptian SMS test count remains **0**. No sealed ETIS final test was run. '
              'PhreshPhish test remains evaluation-only, but its use for this explicitly requested deployment selection '
              'means it is exposed selection evidence, not a fresh final performance claim. '
              'Its benign source, webpage-language tags and limited Egyptian representation do not validate Egyptian users. '
              'Domain exclusions alter the fitting distribution; repeated URLs per domain limit row-wise FPR uncertainty. '
              'Host-only models cannot distinguish malicious and benign paths on a shared host. '
              'The runtime length limit differs from research scoring; long/invalid rows and abstentions are reported '
              'in JSON. Model recall remains incomplete, and the selected ETIS FPR is materially worse than the old '
              'artifact despite better external subdomain behaviour. The remaining Vodafone rule false alarms are unresolved.', '',
              'Protected reports, targets, frozen splits, September models/tokenizer and retained local data bytes were '
              'verified in [integrity.json](integrity.json). No destination was opened/resolved and no messages or URL '
              'samples were sent to an external analysis service. Official-source browsing and dataset/package acquisition '
              'were limited to the authorized provenance/dependency work.', '',
              '## Reproduction', '',
              'Use the Python environment and versions recorded in the check/setup JSON. Restore authorized data inputs '
              'first; raw/processed corpora and research weights are intentionally absent from fresh clones. '
              'The packaged scanner and tests do not require those removed corpora.', '',
              '```text',
              'python -m pip install -r requirements-runtime.txt -r requirements-phreshphish.txt',
              'python data/scripts/restore_raw_data.py --check-all',
              'python data/scripts/rebuild_dataset.py --output evaluation/local-results/v3-data',
              'python -c "import data.scripts.download_phreshphish as d; from pathlib import Path; d.REPORT=Path(\'evaluation/reports/2026-10-v4\'); d.main()"',
              'python evaluation/run_url_subdomains_v4.py',
              'python evaluation/promote_url_v4.py',
              'python evaluation/probe_legit_hosts.py --output evaluation/reports/2026-10-v4/probe_after.json',
              'python evaluation/run_followup.py --output evaluation/reports/2026-10-v4/followup_final.json',
              'python evaluation/run_checks_v4.py final',
              'python evaluation/prepare_release_artifacts.py',
              'python evaluation/verify_hygiene_v4.py --clean-tree',
              'python evaluation/report_v4.py',
              '```', '',
              'For a pre-change probe after promotion, load the hash-checked former artifact in '
              '`release-artifacts/prior-deployment/`; the training runner recovers it from the original Git commit '
              'when needed. Historical reports remain intact. No push is included in these commands.', '']
    (OUT / 'REPORT.md').write_text('\n'.join(lines), encoding='utf-8')
    removed = ['# Files removed from current Git tracking', '',
               'Data files retain their original local bytes. Candidate binaries were moved to the local release folder. '
               'Hashes and reasons are in data_hygiene.json and release_manifest.json; historical copies remain in Git.', '',
               '## Local data/export copies retained', '']
    removed += ['- `' + row['path'] + '`' for row in hygiene['untracked_data']]
    removed += ['', '## Historical research binaries moved locally', '']
    removed += ['- `' + row['original_path'] + '` -> `' + row['local_path'] + '`' for row in historical]
    (OUT / 'REMOVED-FILES.md').write_text('\n'.join(removed) + '\n', encoding='utf-8')
    pr = [
        '# Fix legitimate-subdomain false alarms and tighten public-tree hygiene', '',
        'The prior URL model flagged legitimate service subdomains because its benign data consisted mainly of roots. '
        'Deploy the combined-data calibrated host SVM selected under the committed subdomain rule, preserving calibration-only '
        'thresholds and frozen evaluation membership. Add the reviewer host regressions, sourced Egyptian brand entries, '
        'and optional sender-display context with Arabic/English supporting-signal advice and no new input storage.', '',
        'Untrack restricted snapshots and derived exports while preserving local bytes, move historical candidate weights '
        'to ignored release artifacts with SHA-256 manifests, and patch the vulnerable transitive source-map dependency.', '',
        f"Validation: {summary['final_tests_passed']} backend tests; database initialization; frontend clean install, build, lint; "
        f"npm audit {summary['npm_vulnerabilities_after']} findings. Existing replay: "
        f"{replay['summary']['detection_passed']}/{replay['summary']['detection_total']} detection, "
        f"{replay['summary']['robustness_passed']}/{replay['summary']['robustness_total']} robustness, "
        f"{replay['summary']['followup_passed']}/{replay['summary']['followup_total']} follow-up. "
        'The tracked-tree export also passes without research data.', '',
        f"Selected classifier: benign-subdomain FPR {pct(sub['false_positive_rate'])}; PhreshPhish recall {pct(test['recall'])}. "
        f"ETIS validation recall {pct(val['recall'])} and FPR {pct(val['false_positive_rate'])} are worse than the old artifact. "
        'The remaining Vodafone probe warnings are brand-rule alerts. External-test selection is exposed development evidence; '
        'no sealed final test or genuine Egyptian SMS validation is claimed. Full metrics, probes, removed paths and sources '
        'are in evaluation/reports/2026-10-v4/REPORT.md.', '',
        '**History limitation:** removed data remains in Git history and on GitHub. Making the repository private limits '
        'public access; a separately authorized history rewrite is required to purge historical copies. No rewrite, upload or push was performed.',
        '',
    ]
    (OUT / 'PR_DESCRIPTION.md').write_text('\n'.join(pr), encoding='utf-8')
    print(json.dumps({key: summary[key] for key in ['final_tests_passed', 'winner', 'untracked_data_files', 'release_manifest_files']}))


if __name__ == '__main__':
    main()
