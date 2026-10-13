"""Render the October review report from measured artifacts; never invent missing results."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from evaluation.review_common import OUT,PREVIOUS,PROVENANCE,sha,write

def get(name):return json.loads((OUT/name).read_text(encoding='utf-8'))
def pct(x):return f'{100*x:.2f}%'

def main():
    u=get('url_review_metrics.json');t=get('text_review_metrics.json');old=get('legacy_url_replay.json')
    temporal=get('url_time_review.json');policy=get('url_policy_replay.json');decision=get('decision_metrics.json')
    checks=get('verification.json');follow=get('followup-replay.json');audit=get('raw_inventory_audit.json')
    assert t['status']=='COMPLETE'
    lines=['# ETIS review implementation — 13 October 2026','',
      'This report supersedes the 9–10 October URL experiment and text selection. ETIS is a six-member AAST graduation project. The deployed URL model uses host-only features from the original repository data. The deployed September text model is unchanged; the revised comparison has a different provisional winner. No sealed final evaluation ran and authentic Egyptian SMS benchmark count remains **0**.', '',
      '**Pending:** legitimate URLs with genuine paths could not be imported. PhiUSIIL was downloaded and inspected, but all 134,850 legitimate entries have no non-root path or query. The GramBeddings authors provide academic access through a personal-details form. Attach `grambeddings_dataset_main.zip` and its accompanying terms to finish this step. No paths were generated and no form was submitted.', '',
      '## A. URL shortcuts and current host model','',
      'Only existing `data/raw/tranco_raw.csv` and `tranco_final_approved.csv` identify the current legitimate Tranco pool. The original list ID and retrieval date are **not recorded**. The earlier PY35J file remains as historical evidence, but is not used by the current model. Existing manual legitimate URLs are also roots, so they do not remedy the missing-path problem.', '',
      'The old 9,496-row aggregate confusion was reproduced exactly on reconstructed development rows. Because the old report lacks row IDs, matching confusion counts alone cannot prove identical membership. The following are paired replays of the same reconstructed cohort with the pristine baseline engine and training-only frozen blacklist:', '',
      '| Baseline input | Phishing recall | TP / 6,531 | FP / 2,965 | FPR |', '|---|---:|---:|---:|---:|']
    for name,key in [('Full URL','full_url_legacy'),('Remove path/query; preserve scheme','pathless_preserving_scheme_legacy'),('Host-only input; fixed HTTPS scheme','host_only_input_legacy')]:
        m=old[key]['medium_or_high'];c=m['confusion']
        lines.append(f"| {name} | {pct(m['recall']['value'])} | {c['tp']} | {c['fp']} | {pct(m['false_positive_rate']['value'])} |")
    lines += ['', 'Path removal and scheme standardization are separate diagnostics. The host-only replay is a transformed input to the old rules, not the learned host classifier. No transformed URL is presented as a newly collected legitimate URL.', '',
      f"The new paired classifier comparison uses {u['train_rows']:,} training rows and {u['validation_rows']:,} validation rows after excluding cross-class domains and any overlapping train/validation registered domains. A pinned offline PSL includes private entries. The retained PSL groups refine the frozen original groups, checked without reading sealed records. All variants use identical rows; full-URL models are diagnostic only.", '',
      '| Representation / model | Recall ≤1% FPR | Actual FP / 2,916 | Recall ≤0.1% FPR | Actual FP / 2,916 | PR-AUC | ECE | CPU p95 ms |',
      '|---|---:|---:|---:|---:|---:|---:|---:|']
    for variant,models in u['variants'].items():
        for name,m in models.items():
            lines.append(f"| {variant} / {name} | {pct(m['at_1pct']['recall'])} | {m['at_1pct']['fp']} | {pct(m['at_0_1pct']['recall'])} | {m['at_0_1pct']['fp']} | {m['pr_auc']:.4f} | {m['ece_15_bins']:.4f} | {m['cpu_latency']['p95_ms']:.2f} |")
    dep=u['deployment'];dm=u['variants']['host_only'][dep['model']]
    lines += ['', f"Selected host-only model: **{dep['model']}**, threshold **{dep['threshold']:.15f}**. At that validation operating point: {pct(dm['at_0_1pct']['recall'])} recall, {dm['at_0_1pct']['fp']}/2,916 false positives ({pct(dm['at_0_1pct']['false_positive_rate'])}). This is classifier recall, not a comparison against the old policy on an identical cohort.", '',
      'The shortcut-only model sees total length, path/query length, path/query presence and HTTPS, without host identity or lexical n-grams. Its high score demonstrates severe dataset separability from collection artifacts; it is not a deployed detector. Host length can still encode popularity/source differences even after removing paths.', '',
      '| Full model, fixed ≤0.1% threshold | Recall with paths | Recall after path/query removal | Recall drop (points) | Mean phishing probability drop | FP before / after |', '|---|---:|---:|---:|---:|---:|']
    for name,m in u['variants']['full_url'].items():
        a=m['at_0_1pct'];s=m['same_model_paths_removed'];b=s['fixed_0_1pct_threshold']
        lines.append(f"| {name} | {pct(a['recall'])} | {pct(b['recall'])} | {100*(a['recall']-b['recall']):.2f} | {s['mean_probability_delta_full_minus_stripped_phishing']:.4f} | {a['fp']} / {b['fp']} |")
    pc=policy['result']['medium_or_high']
    lines += ['', 'These paired changes measure sensitivity to path/query removal, not a causal percentage of model quality. Legitimate strings are already roots, so their scores do not change. This dataset cannot estimate false alarms on genuine legitimate paths. Bootstrap intervals (300 registered-domain resamples) and the corresponding 1% ablation are in `url_review_metrics.json`; thresholds are reselected per bootstrap sample, so intervals are not independent deployment guarantees.', '',
      f"The integrated current scanner, including existing rules and host-model suppression on official/shared hosts, obtains {pct(pc['recall']['value'])} MEDIUM-or-HIGH recall with {pc['confusion']['fp']}/2,916 false positives ({pct(pc['false_positive_rate']['value'])}) on the cleaned validation cohort. See `url_policy_replay.json`.", '',
      f"The updated character-logistic domain-recency stress test uses the repository Tranco pool: recall {pct(temporal['metrics']['recall_at_fpr_le_1pct'])} at ≤1% FPR and {pct(temporal['metrics']['recall_at_fpr_le_0_1pct'])} at ≤0.1%. Whole domains are assigned by their latest source timestamp, so validation can contain earlier URLs from those domains. Negative-list date is unknown. This is not a strictly forward-time evaluation or a temporal measurement of the selected LightGBM.", '',
      '## B. Text selection and provenance','',
      'The revised rule was saved before new comparisons; it was informed by previous exposed results, not independently preregistered. Primary loss averages three equally weighted quantities: source-mean false-negative rate, source-mean false-positive rate, and MEDIUM-or-HIGH rate on the 12 existing invented everyday probes. CPU p95 must be ≤300 ms. Validation macro-F1 is only a tie-breaker. Equal weighting is a project decision, not an estimate of population prevalence.', '',
      'The original 282-row validation is small and saturated. Excluding the 55 dialectal validation rows leaves 227 rows (53 phishing / 174 legitimate), all from translated sources. Frozen rows/groups/splits are unchanged. Dialectal validation rows are not moved into training. Only its existing 234 training rows remain available; 54 pre-existing synthetic-brand training rows also remain, labelled synthetic. No new SMS was generated.', '',
      '| Candidate | Source-mean FNR, translated sources | Source-mean FPR, translated sources | Alerts / 12 invented probes | HIGH / 12 invented probes | Primary loss | Tie-break F1, translated validation |', '|---|---:|---:|---:|---:|---:|---:|']
    for name,m in t['models'].items():
        c=m['primary_loss_components'];p=m['everyday']
        lines.append(f"| {name} | {pct(c['source_mean_fnr'])} | {pct(c['source_mean_fpr'])} | {p['medium_or_high_n']} | {p['high_n']} | {m['primary_loss']:.6f} | {m['validation']['metrics']['macro_f1_at_recall_95']:.4f} |")
    lines += ['', f"Provisional winner: **{t['provisional_winner']}**. It trades lower everyday-fixture alerting for worse source-held-out phishing recall than the character models. Its lower validation F1 does not override the frozen primary rule. The original deployed text model remains unchanged. Final selection requires transformer source-held-out and everyday-probe evidence; six validation-only prediction files are insufficient.", '',
      '| Candidate | Held source and provenance | Phishing / legitimate rows | Held-source recall | Held-source FPR | Held-source macro-F1 |', '|---|---|---:|---:|---:|---:|']
    for name,m in t['models'].items():
        for source,r in m['loso'].items():
            h=r['held_source'];label='Kaggle fully: translated fraud letters / UCI ham, not Egyptian SMS' if source.startswith('kaggle') else 'Salloum/Gaber: translated parallel emails, not Egyptian SMS'
            lines.append(f"| {name} | {label} | {h['phishing_n']} / {h['legitimate_n']} | {pct(h['phishing_recall'])} | {pct(h['legitimate_fpr'])} | {h['macro_f1']:.4f} |")
    lines += ['', 'For each held source, training uses only other-source training rows, with any shared near-duplicate group removed. Threshold selection and BiLSTM early stopping use other-source eligible validation only. All development rows from the excluded source are scored. The 12 invented fixtures are exposed selection diagnostics and must never become a final test. Raw fold thresholds, confusion counts, model hashes and per-probe verdicts are retained in `text_review_metrics.json`.', '',
      'The dialectal raw file is 500 rows (250 phishing / 250 safe), 333 unique text-label pairs. It has Moroccan/Levantine markers and template-like repetitions, but also Egyptian-associated wording such as `النهارده` and `متتأخرش` in safe rows. The requested claim “no Egyptian markers found” is contradicted by the actual file. Collection origin and licence remain unverified; training-only usage and no Egyptian-performance claim are retained.', '',
      'Language correction: 43 of the 55 dialectal validation rows are Arabic-script-only (`ar`); 12 contain Arabic plus Latin letters (`mixed`). The overlay also identifies 171 Arabic-only and 63 mixed training rows. This changes reporting metadata only, not split membership or content hashes. The Decision-v2 demotion total remains 82 phishing development rows: corrected language counts are 74 Arabic and 8 mixed; source counts are 30 translated Kaggle, 18 translated Salloum and 34 apparently templated mixed-regional dialectal diagnostics.', '',
      '## C. Documentation and data hygiene','',
      f"`docs/data-licences.md` inventories all {audit['raw_file_count']} raw files, with source, quoted terms or 'not stated', and public redistribution status. `data/raw-sources-manifest.json` pins every file hash. `restore_raw_data.py` verifies existing files, imports authorised originals, and downloads the pinned PhiUSIIL archive when absent. Both ZIP and CSV hashes were verified by an actual second download into an isolated directory. Unknown historical snapshots require an authorised attachment; current feeds are never silently substituted.", '',
      'No raw data was deleted. The team should resolve permissions or replace the identified raw and derived data in its future public distribution. OpenPhish current terms restrict third-party distribution; several other sources have unestablished redistribution permission. The delivered archive preserves the user-provided data and is a local review package, not a declaration that all contents are cleared for public publication.', '',
      'The historical September guide is in `docs/history/claude-guide-2026-09.md`; current `CLAUDE.md` describes the six-member AAST team and current constraints. `LICENSE` is explicitly a placeholder. The team must choose the project-code licence and copyright holders; no licence was selected for it.', '',
      '## Verification and reproduction','',
      f"Backend: **{checks['commands']['backend_tests']['passed']} tests passed**. Initialization, frontend installation, build and lint exit codes: " + ', '.join(f"{n}={checks['commands'][n]['exit_code']}" for n in ['initialize','frontend_install','frontend_build','frontend_lint']) + '.', '',
      f"Regression replay: {follow['summary']['detection_passed']}/23 detection, {follow['summary']['robustness_passed']}/7 robustness, {follow['summary']['followup_passed']}/15 follow-up; NBE remains non-HIGH. Deployed text policy on the invented everyday probes remains 0 HIGH, 8 MEDIUM, 4 LOW. Candidate comparison results above do not replace deployment behavior.", '',
      'Checks ran locally on Windows; GitHub Linux/Python 3.12/Node 24 CI itself was not run. `npm ci` reports one high-severity dependency finding; dependencies were not upgraded in this change. The original September data/model/tokenizer, reviewed 8 October reports, targets and frozen text split are verified unchanged. No phishing destination was fetched or resolved, and no SMS/URL data was sent to an external analysis service.', '',
      'With the existing local development files and candidate artifacts, run from the repository root:', '',
      '```text','python evaluation/run_url_review.py','python evaluation/run_url_review_followup.py','python evaluation/run_text_review.py','python evaluation/finalize_text_review.py','python evaluation/run_decision_metrics_v3.py','python evaluation/run_followup.py','python evaluation/audit_raw_sources.py','python data/scripts/restore_raw_data.py --check-all','python evaluation/run_checks_v3.py','python evaluation/summarize_review.py','```','',
      'For a clean reproduction, first use the original-data rebuild described in the historical report (without synthetic augmentation), and train local candidates with `run_text_v3.py`; it now delegates selection to the revised rule. The pristine baseline replay additionally needs a separate extraction of the supplied original ZIP via `replay_legacy_url_review.py --baseline <pristine-root>`. Do not run sealed final evaluation commands.', '',
      'Sources: [PhiUSIIL/UCI](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset); [GramBeddings authors](https://web.cs.hacettepe.edu.tr/~selman/grambeddings-dataset/); [GramBeddings academic access form](https://docs.google.com/forms/d/e/1FAIpQLScuwosnH9JIJYKUeTeR26xxiG6bWXhxYoHjoNSketW5MrCUxQ/viewform). Detailed licence sources are linked beside their claims in `docs/data-licences.md`.']
    report='\n'.join(lines)+'\n'
    (OUT/'REPORT.md').write_text(report,encoding='utf-8')
    historical=PREVIOUS/'REPORT-2026-10-10.md'
    if not historical.exists():historical.write_bytes((PREVIOUS/'REPORT.md').read_bytes())
    (PREVIOUS/'REPORT.md').write_text('# Current ETIS v3 report\n\nThe [13 October review report](review-2026-10-13/REPORT.md) is authoritative for current URL training, source/probe-based text selection, corrected language tags and licences.\n\nThe [9–10 October report](REPORT-2026-10-10.md) is historical. Its PY35J URL experiment, text winner, blanket dialect language tags and validation-first selection are superseded. Its original JSON files remain historical records. The reviewed 8 October baseline is unchanged.\n',encoding='utf-8')
    original=json.loads((PREVIOUS/'integrity.json').read_text())
    files=[]
    for row in original['protected_files']:
        current=sha(ROOT/row['path']);assert current==row['sha256'],row['path']
        files.append({**row,'unchanged':True})
    overlay=get('language_overlay.json');assert sha(PREVIOUS/'text_split.json')==overlay['frozen_manifest_file_sha256']
    write('integrity.json',{'model_sha256':sha(ROOT/'ml/models/url_host_v3.joblib'),'protected_files':files,'frozen_text_manifest_file_sha256':sha(PREVIOUS/'text_split.json'),'all_protected_files_byte_identical':True,'raw_files_deleted':False})
    print('Report written; original data, models, tokenizer, targets, baseline reports and frozen text manifest unchanged.')

if __name__=='__main__':main()
