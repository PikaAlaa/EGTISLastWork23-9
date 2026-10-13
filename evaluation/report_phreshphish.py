"""Render aggregate, measured results without opening any dataset destination."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.phreshphish_utils import OUT, sha, write


def pct(value):
    return 'undefined' if value is None else f'{100 * value:.3f}%'


def main():
    results = json.loads((OUT / 'model_comparison.json').read_text())
    audit = json.loads((OUT / 'data_audit.json').read_text())
    assert results['status'] == 'COMPLETE' and len(results['models']) == 18
    assert results['protocol_sha256'] == sha(OUT / 'protocol.json')
    for key, model in results['models'].items():
        assert not model['warnings'], (key, model['warnings'])
        assert sha(OUT / 'models' / (key.replace('/', '_') + '.joblib')) == model['model_sha256']
    def fixed(key):
        return results['models'][key]['cohorts']['phreshphish_test']['fixed_calibration_thresholds']['1pct']
    eh = fixed('etis/host_only/lightgbm'); ef = fixed('etis/full_url/lightgbm'); ph = fixed('phreshphish/host_only/lightgbm')
    lines = [
        '# PhreshPhish URL comparison — 13 October 2026',
        '',
        'All 18 fits completed: three source settings, host-only and full-URL representations, and character TF-IDF logistic regression, calibrated linear SVM and engineered-feature LightGBM. These are research artifacts; no model was automatically promoted. The existing host-only application model is unchanged.',
        '',
        f"**Finding:** ETIS-only thresholds transfer poorly to the varied benign URLs in PhreshPhish. At the threshold calibrated for 1% false positives, the ETIS-only host LightGBM flags {pct(eh['false_positive_rate'])} of PhreshPhish benign rows; its full-URL counterpart flags {pct(ef['false_positive_rate'])}. PhreshPhish-only host LightGBM gives {pct(ph['recall'])} recall and {pct(ph['false_positive_rate'])} false positives at its corresponding fixed threshold. These are retrained research models, not a replay of the deployed artifact. The evidence does not support a claim that the deployed scanner is validated on Egyptian traffic.",
        '',
        'Adding licensed benign URLs with paths is now possible: PhreshPhish contains 257,396 such benign training rows and 83,180 test rows (non-root path or query). This supplies the missing research data without a GramBeddings attachment. It does not supply authentic Egyptian SMS.',
        '',
        '## Source, acquisition and limits',
        '',
        '- [Pinned PhreshPhish card](https://huggingface.co/datasets/phreshphish/phreshphish/blob/eabec4b7a66324b79cc8a0ad856d1731dc26fe1a/README.md), version 1.0.1, dated 7 February 2026; downloaded 13 October 2026. Citation: Dalton et al. (2025), arXiv preprint, [10.48550/arxiv.2507.10854](https://doi.org/10.48550/arxiv.2507.10854). CC BY 4.0; the card additionally requests anti-phishing research use only.',
        '- The card does not identify the source of benign URLs. Labels and language tags are supplied by the dataset and were not independently confirmed by visiting websites. No destination was opened.',
        '- The card lists 91,260 benign and 76,876 phishing test rows, which exceed its stated total by 76. Measured files contain **91,260 benign + 76,800 phishing = 168,060**.',
        '- The first web preview of the card included truncated HTML snippets before switching to repository metadata. Local acquisition thereafter used only the five allowed data columns plus structural Parquet metadata. No HTML data chunks were downloaded by the script, decoded or saved.',
        '- Exactly `url`, `label`, `target`, `date`, `lang` were projected from 77 upstream shards. Dataset files and row-level predictions are excluded from Git and delivery archives. `data/phreshphish-lock.json` records upstream-declared whole-file hashes and independently measured selected-range/projection hashes; whole-file hashes were not locally verified because whole-file downloads would include excluded content.',
        '- ETIS uses the existing Tranco files. Their list ID/date remain unrecorded. ETIS benign rows remain heavily biased toward homepages; source differences and feature effects must not be confused with proof of real-world phishing detection.',
        '',
        '## Frozen evaluation design',
        '',
        'The protocol was saved before training and prediction. Official PhreshPhish train/test membership is preserved: all 168,060 test rows remain evaluation-only. Within the official training pool, registered domains are grouped using the pinned private-PSL rules, then deterministically assigned 80/20 to fitting/calibration. Domains seen in either PhreshPhish test or the frozen ETIS validation cohort are excluded from all fitting/calibration pools using input metadata only. Thus this is a stricter filtered training protocol, not training on every official training row. Mixed-label training domains and exact same-label duplicate URLs are excluded with counts below.',
        '',
        '“ETIS current data” means retraining from the eligible current ETIS training pool after these common exclusions; it does not mean the old artifact or its old threshold. “Combined” means ETIS phishing plus both PhreshPhish classes, excluding ETIS benign. Every model is evaluated on the same 168,060 PhreshPhish test rows and 8,889 ETIS grouped validation rows (5,973 phishing; 2,916 benign). ETIS sealed final tests were not evaluated.',
        '',
        '| Setting | Input rows | Evaluation-domain overlap removed | Mixed-domain rows removed | Duplicates removed | Fit rows | Calibration rows |',
        '|---|---:|---:|---:|---:|---:|---:|',
    ]
    for name, item in audit['settings'].items():
        lines.append(f"| {name} | {item['input_pool']['rows']:,} | {item['evaluation_domain_overlap_rows_excluded']:,} | {item['mixed_label_domain_rows_excluded']:,} | {item['same_label_exact_duplicate_rows_removed']:,} | {item['fit']['rows']:,} | {item['calibration']['rows']:,} |")
    lines += [
        '',
        'There are also 261 unparseable-host rows excluded from each PhreshPhish-containing training pool. Official test retains all 122 unparseable-host rows as abstentions: phishing abstentions count as missed detections; benign abstentions do not alert. Coverage is therefore 167,938/168,060. Excluding overlapping/mixed domains changes the training distribution substantially; results are conditional on this protocol. Long URLs remain eligible offline (7 official training rows and 11 test rows exceed 2,048 characters), unlike the application’s length limit.',
        '',
        '## Fixed calibration thresholds — primary transfer evidence',
        '',
        'Each cap sets a threshold using only the setting’s internal calibration negatives. That threshold is then frozen for both evaluation cohorts. **The cap is not a guarantee of the evaluation false-positive rate.** PPV columns apply Bayes’ rule at assumed phishing prevalence of 1% and 0.1%: prior × recall / (prior × recall + (1 − prior) × FPR). They are scenario estimates, not measured Egyptian precision. A point estimate of 100% with zero observed false positives does not establish perfect precision; JSON includes marginal Wilson intervals and conservative bounds, not domain-cluster intervals.',
        '',
    ]
    for cohort in ['phreshphish_test', 'etis_grouped_validation']:
        lines += [f'### {cohort}', '', '| Setting / representation / model | Calibration cap | Recall | FP / benign | Actual FPR | PPV at 1% | PPV at 0.1% |', '|---|---:|---:|---:|---:|---:|---:|']
        for key, m in results['models'].items():
            for cap, v in m['cohorts'][cohort]['fixed_calibration_thresholds'].items():
                lines.append(f"| {key} | {cap} | {pct(v['recall'])} | {v['fp']}/{v['benign_n']} | {pct(v['false_positive_rate'])} | {pct(v['precision_at_phishing_base_rate_1pct'])} | {pct(v['precision_at_phishing_base_rate_0_1pct'])} |")
        lines.append('')
    lines += ['## Recall at evaluation FPR caps — descriptive ROC evidence', '', 'These thresholds are calculated retrospectively from each evaluation cohort’s scores to describe recall at ≤1% and ≤0.1% empirical FPR. They are not deployment thresholds and were not used for fitting, hyperparameter choice or promotion. Ties can make actual FPR lower than the cap.', '']
    for cohort in ['phreshphish_test', 'etis_grouped_validation']:
        lines += [f'### {cohort}', '', '| Setting / representation / model | FPR cap | Recall | Actual FPR | PPV at 1% | PPV at 0.1% |', '|---|---:|---:|---:|---:|---:|']
        for key, m in results['models'].items():
            for cap, v in m['cohorts'][cohort]['retrospective_roc_operating_points'].items():
                lines.append(f"| {key} | {cap} | {pct(v['recall'])} | {pct(v['false_positive_rate'])} | {pct(v['precision_at_phishing_base_rate_1pct'])} | {pct(v['precision_at_phishing_base_rate_0_1pct'])} |")
        lines.append('')
    lines += ['## Full URL versus host-only', '', 'Host-only remains the primary representation. The table gives full minus host results at separately calibrated thresholds. Full URL includes path, query, scheme and their contribution to total length/character statistics. This is an ablation comparison, not a causal percentage of a model’s score attributable to paths; changed representation also changes the learned model and threshold.', '', '| Setting / model | Evaluation | Calibration cap | Recall change (points) | FPR change (points) |', '|---|---|---:|---:|---:|']
    ablations = []
    for setting in audit['settings']:
        for model in ['char_logistic', 'char_calibrated_svm', 'lightgbm']:
            host = results['models'][f'{setting}/host_only/{model}']
            full = results['models'][f'{setting}/full_url/{model}']
            for cohort in host['cohorts']:
                for cap in ['1pct', '0_1pct']:
                    h = host['cohorts'][cohort]['fixed_calibration_thresholds'][cap]
                    f = full['cohorts'][cohort]['fixed_calibration_thresholds'][cap]
                    dr = 100 * (f['recall'] - h['recall']); df = 100 * (f['false_positive_rate'] - h['false_positive_rate'])
                    lines.append(f'| {setting}/{model} | {cohort} | {cap} | {dr:+.3f} | {df:+.3f} |')
                    ablations.append({'setting':setting, 'model':model, 'cohort':cohort, 'cap':cap, 'recall_difference_points':dr, 'fpr_difference_points':df})
    lines += ['', 'The earlier [A–C review](../review-2026-10-13/REPORT.md) preserves the legacy 17.18% recall replay and its path/scheme ablations. Those figures use a different artifact/protocol and must not be silently substituted for these retrained comparisons.', '', '## Arabic and Egyptian registry target subsets', '', 'Official training has 164 Arabic-tagged rows (102 phishing, 62 benign); official test has **46 (32 phishing, 14 benign; 40 registered domains)**. Language tags describe webpages, not SMS dialect or the recipient’s location. Strict Egyptian-registry target matches are **0 training, 1 test**: `qnb_al_ahli`, a phishing row. Generic international brand families are separately counted as ambiguous in `data_audit.json`; they are not evidence of Egyptian targeting. The one matched row has no benign comparator: FPR, FPR-constrained ROC and prevalence-adjusted precision are undefined. These subset sizes cannot establish Egyptian performance.', '', '| Setting / representation / model | Calibration cap | Arabic detected / 32 | Arabic FP / 14 | Egyptian target detected / 1 |', '|---|---:|---:|---:|---:|']
    for key, m in results['models'].items():
        cohort=m['cohorts']['phreshphish_test']
        for cap in ['1pct', '0_1pct']:
            ar=cohort['arabic']['fixed_calibration_thresholds'][cap]
            eg=cohort['egyptian_registry_target']['fixed_calibration_thresholds'][cap]
            lines.append(f"| {key} | {cap} | {ar['tp']}/32 | {ar['fp']}/14 | {eg['tp']}/1 |")
    lines += ['', 'All subgroup recalls, actual FPRs, prior-adjusted precision and uncertainty intervals are in `model_comparison.json`; Arabic ROC points are also supplied there, but 14 benign examples cannot resolve a 0.1% or 1% false-positive rate reliably.', '', '## Reproducibility and verification', '', f"Dataset projection-set SHA-256: `{results['data_sha256']}`. Frozen protocol SHA-256: `{results['protocol_sha256']}`. Model SHA-256 values, exact thresholds, CPU batch-one latency, fit time, library versions and cohort counts are recorded in `model_comparison.json`. All 18 fits completed without convergence warnings.", '', 'Run the commands in [docs/phreshphish.md](../../../../docs/phreshphish.md). `verification.json` records actual local test/build outcomes; `integrity.json` checks preserved artifacts, split membership and model hashes. These are local Windows checks, not a claim that a hosted GitHub CI job ran. Project code licence remains the team’s decision; existing unresolved raw-data redistribution rights remain listed in `docs/data-licences.md`.', '']
    checks_path=OUT/'verification.json'
    if checks_path.exists():
        checks=json.loads(checks_path.read_text())
        assert all(v['exit_code']==0 for v in checks['commands'].values())
        lines += [f"Local verification passed: **{checks['commands']['backend_tests']['passed']} tests**, database initialization, frontend clean install, build and lint. The install output still reports one existing high-severity dependency vulnerability; no dependency upgrade is included in this research change.", '']
    (OUT/'REPORT.md').write_text('\n'.join(lines), encoding='utf-8')
    write('ablation.json', {'data_sha256':results['data_sha256'], 'protocol_sha256':results['protocol_sha256'], 'comparisons':ablations})
    print('Wrote measured report and 36 host/full comparisons')


if __name__ == '__main__':
    main()
