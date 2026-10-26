"""Render the new text-selection report from aggregate evidence and check logs."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.transformer_contract import MODELS, read_json, sha

OUT = ROOT / 'evaluation/reports/2026-10-v5'
SOURCES = ['kaggle_arabic_phishing_fully_dataset', 'salloum_gaber_bilingual_corpus']


def f(value):
    return f'{value:.6f}'


def main():
    o = read_json(OUT / 'comparison.json')
    checks = read_json(OUT / 'verification.json')
    winner = o['selected_model']
    m = o['models'][winner]
    lines = ['# ETIS Phase 2 text model selection — 26 October 2026', '',
             f'Selected **{winner}**, primary loss **{f(m["mean_primary_loss"])}**, '
             f'new common-protocol CPU p95 **{f(m["local_latency"]["p95_ms"])} ms**.', '',
             'This is exposed development selection under the unchanged 13 October rule. '
             'It is not an independent final evaluation or a claim of Egyptian SMS accuracy. '
             '**Genuine Egyptian SMS test count: 0. No sealed final test ran.**', '',
             '## Rule, import and retrospective amendment', '',
             'Starting branch `feat/text-model-selection`, HEAD `b13501a`, clean working tree. '
             'The strict importer accepted all six returned runs, including hashes, row/group membership, '
             'source identity, validation-only thresholds and Decision-v2 probe replay. '
             'No model was fitted or threshold retuned during Phase 2.', '',
             'Frozen rule: [13 October model_selection_rule.md](../2026-10-v3/review-2026-10-13/model_selection_rule.md). '
             'The [latency amendment](latency_amendment.md) was initially written after seeing Colab timings '
             'and before importing seed means; the owner-authorized all-seven common protocol was recorded '
             'before any new timing. An incomplete eager-BiLSTM attempt was subsequently preserved and excluded; '
             'the compiled-executor correction was disclosed before re-timing all seven from scratch. '
             'This timing amendment is retrospective, not prospective preregistration.', '',
             '`loss = (mean_source(FN/phishing_n) + mean_source(FP/legitimate_n) + everyday_MEDIUM_or_HIGH/12) / 3`.', '',
             'Each source has equal weight, regardless of size. All twelve existing invented probes use '
             'the existing Decision-v2 policy, candidate eligible-validation high threshold, low threshold 0.2 '
             'and the unchanged deployed URL model. Text-only HIGH still requires corroboration. '
             'Seed aggregation was declared before computation: arithmetic mean of the three seed losses; '
             'per-seed values and their min/max are retained. Seeds are not pooled and none is cherry-picked. '
             'Local candidates retain their single frozen seed-42 fit. Reject p95 >300 ms using only new timings; '
             'within loss tolerance 0.000001, use eligible-validation macro-F1 then frozen simplicity order.', '',
             '## Complete comparison', '',
             'All rates are fractions, not percentages. Transformer rows average three seeds; '
             'their probe counts below are listed in seed order 42/43/44. Lower loss is better.', '',
             '| Candidate | Mean LOSO FNR | Mean LOSO FPR | Everyday M/H rate | M/H counts /12 | HIGH counts /12 | Primary loss | Min–max loss | Eligible val macro-F1 | New p95 ms | Gate |',
             '| --- | ---: | ---: | ---: | --- | --- | ---: | --- | ---: | ---: | --- |']
    for name, model in o['models'].items():
        c = model['mean_primary_loss_components']
        counts = '/'.join(str(r['everyday']['medium_or_high_n']) for r in model['runs'])
        highs = '/'.join(str(r['everyday']['high_n']) for r in model['runs'])
        lines.append(f'| {name} | {f(c["source_mean_fnr"])} | {f(c["source_mean_fpr"])} | '
                     f'{f(c["everyday_medium_or_high_rate"])} | {counts} | {highs} | '
                     f'{f(model["mean_primary_loss"])} | {f(model["min_primary_loss"])}–{f(model["max_primary_loss"])} | '
                     f'{f(model["mean_validation_macro_f1"])} | {f(model["local_latency"]["p95_ms"])} | '
                     f'{"PASS" if model["latency_gate_passes"] else "REJECT"} |')
    lines += ['', f'The minimum eligible loss selects **{winner}**. '
              f'Loss-tied candidates: `{o["selection"]["loss_ties"]}`; '
              'no tie-breaker changes the winner in this comparison. LightGBM also has the lowest loss '
              'before applying the latency gate. Its mean LOSO miss rate is higher than the transformers\' '
              '(18.09% versus 10.62% and 9.29%); the project\'s equal-weight objective favors its lower '
              'source-held-out false-positive and everyday-alarm rates. This is an explicit tradeoff.', '',
              '### Per-seed loss components', '',
              '| Candidate | Seed | Source-mean FNR | Source-mean FPR | Everyday M/H /12 | HIGH /12 | Primary loss |',
              '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for name, model in o['models'].items():
        for r in model['runs']:
            c = r['primary_loss_components']
            lines.append(f'| {name} | {r["seed"]} | {f(c["source_mean_fnr"])} | {f(c["source_mean_fpr"])} | '
                         f'{r["everyday"]["medium_or_high_n"]}/12 | {r["everyday"]["high_n"]}/12 | {f(r["primary_loss"])} |')
    lines += ['', '### Source counts at the frozen LOSO thresholds', '',
              'K = `kaggle_arabic_phishing_fully_dataset` (1,025 rows: 203 phishing, 822 legitimate). '
              'S = `salloum_gaber_bilingual_corpus` (261 rows: 131 phishing, 130 legitimate). '
              'Counts are per fitted fold/seed, never summed across repeated seeds to imply independent data.', '',
              '| Candidate | Seed | Source | TP | FN / phishing | FP / legitimate | TN | Fold high threshold |',
              '| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |']
    for name, model in o['models'].items():
        for r in model['runs']:
            for source, short in zip(SOURCES, ['K', 'S']):
                held = r['loso'][source]['held_source']
                c = held['confusion']
                threshold = held.get('threshold_95', held.get('threshold_from_id_validation'))
                lines.append(f'| {name} | {r["seed"]} | {short} | {c["tp"]} | {c["fn"]}/{held["phishing_n"]} | '
                             f'{c["fp"]}/{held["legitimate_n"]} | {c["tn"]} | {threshold:.12g} |')
    lines += ['', '## Provenance and frozen membership', '',
              '| Source | Provenance / use |', '| --- | --- |']
    for source, provenance in o['provenance'].items():
        lines.append(f'| {source} | {provenance} |')
    lines += ['', 'The full fit uses the same 1,347 frozen training rows and 227 eligible validation rows '
              '(53 phishing, 174 legitimate). The 55 dialectal-source validation rows remain excluded; '
              'its 234 training rows remain training-only. Held-source folds exclude every held-source group '
              'from fitting and threshold validation: K-excluded fit has 501 training / 48 threshold-validation rows; '
              'S-excluded fit has 1,134 / 179. No split, target, row identity, source label or frozen rule changed.', '',
              '## CPU latency: new common protocol', '',
              f'CPU: **{m["local_latency"]["cpu_description"]}**; '
              f'{m["local_latency"]["logical_cpu_count"]} logical processors reported by the OS. '
              '**Two threads** for every candidate. Each runs sequentially in a fresh process; '
              'Torch intra/inter-op, TensorFlow intra/inter-op and BLAS/OpenMP pools use two; '
              'LightGBM prediction uses two; tokenizer parallelism is disabled. '
              'Raw samples and effective thread-pool settings remain in ignored `evaluation/local-results/text-transformers/`.', '',
              'Every candidate sees the same ordered 227 eligible validation messages, one complete message '
              'per call, three warmups on the first message. The timer includes normalization, 150-word '
              'windows with stride 75, tokenization/vectorization, all-window inference and max probability. '
              'Transformer windows retain the Colab scorer\'s cap of eight per internal batch and 256-token '
              'truncation; BiLSTM uses the frozen 200-token padding/truncation and compiled `tf.function` inference, '
              'traced during its first warmup with a dynamic window-batch signature. '
              'Complete-message batch size is one throughout. Loading and warmups are outside timing. '
              'This is model-path latency, not end-to-end API latency.', '',
              'Transformers use the exact public pretrained revisions below plus explicitly untrained two-class '
              'heads, without fitting. Architecture, tokenizer and windowing drive inference cost; the proxy '
              'does not measure the unavailable fine-tuned artifacts. PyTorch is CPU-only and stays outside '
              'the runtime `.venv`. Scheduling, power state and other laptop load were not experimentally controlled.', '',
              '| Candidate | New p50 ms | New p95 ms | p95 ≤300 ms |',
              '| --- | ---: | ---: | --- |']
    for name, model in o['models'].items():
        t = model['local_latency']
        lines.append(f'| {name} | {f(t["p50_ms"])} | {f(t["p95_ms"])} | {model["latency_gate_passes"]} |')
    lines += ['', '### Historical timings — descriptive only, excluded from the new gate', '',
              'Historical local timings used 282 validation messages and a different warmup/preprocessing path. '
              'These are retained from the reviewed report, not replaced or combined with the new measurements.', '',
              '| Local candidate | Historical p50 ms | Historical p95 ms |', '| --- | ---: | ---: |']
    for name, model in o['models'].items():
        if name not in MODELS:
            t = model['runs'][0]['historical_local_latency']
            lines.append(f'| {name} | {f(t["p50_ms"])} | {f(t["p95_ms"])} |')
    lines += ['', 'Colab recorded Intel Xeon CPU at 2.00 GHz, two Torch threads, 227 eligible messages, '
              'three warmups, full preprocessing. The owner described it as a two-core Colab CPU; '
              'the returned contract records CPU description and Torch threads, not a physical-core inventory.', '',
              'The five local candidates were not timed on Colab; no such measurements are inferred.', '',
              '| Transformer | Seed | Colab p50 ms | Colab p95 ms |', '| --- | ---: | ---: | ---: |']
    for name, model in o['models'].items():
        if name in MODELS:
            for r in model['runs']:
                t = r['historical_colab_latency']
                lines.append(f'| {name} | {r["seed"]} | {f(t["p50_ms"])} | {f(t["p95_ms"])} |')
    lines += ['', '### Public pretrained snapshots and versions', '',
              '| Model | Exact pretrained commit |', '| --- | --- |']
    for name, snap in o['pretrained_manifest']['models'].items():
        lines.append(f'| {snap["model_id"]} | `{snap["pretrained_commit"]}` |')
    lines += ['', 'Snapshot file hashes are in [comparison.json](comparison.json). Only model/tokenizer files '
              'were downloaded; no project text or message URL was sent to Hugging Face. '
              'Package downloads used the authorized package indexes; inference was offline.', '',
              '| Package | Isolated latency environment |', '| --- | --- |']
    for package, version in m['local_latency']['libraries'].items():
        lines.append(f'| {package} | {version} |')
    lines += ['', 'Colab recorded Torch 2.11.0+cu130, Transformers 4.45.2, safetensors 0.8.0, NumPy 2.1.3 '
              'and Accelerate 0.34.2. Local CPU Torch keeps the same base version; Accelerate is unnecessary '
              'for this inference-only pass. The runtime `.venv` package inventory was checked unchanged.', '',
              '## Deployment and everyday probes', '']
    if winner in MODELS:
        lines += ['The transformer winner is **not deployed**. Returned predictions do not include fine-tuned '
                  'weights. Deployment requires obtaining the exact selected full-fit checkpoint and tokenizer '
                  'with verified hashes and provenance, explicitly choosing a seed or specifying an ensemble, '
                  'packaging its frozen high threshold and 0.2 low threshold, adding pinned CPU PyTorch/Transformers '
                  'and runtime loading/inference support, reproducing normalization/windowing/tokenization, '
                  'checking memory/startup/concurrency and actual trained-artifact CPU latency, replaying the '
                  'probes and safety regressions, and recording an artifact hash/deployment receipt. '
                  'No transformer runtime dependency was added to `.venv`.', '']
    else:
        d = read_json(OUT / 'deployment.json')
        before, after = d['before_probes'], d['after_probes']
        lines += [f'Deployed the frozen **{winner}** pipeline at its existing eligible-validation high threshold '
                  f'`{d["high_threshold"]}` and low threshold `0.2`. '
                  'No weights were fitted or thresholds retuned. The legacy `deployed_char.joblib` path '
                  'is retained for configuration compatibility; the artifact and runtime result identify the '
                  'actual model. LightGBM was already a runtime dependency; no PyTorch was added.', '',
                  f'Artifact SHA-256: `{d["artifact_sha256"]}`.', '',
                  f'Source artifact SHA-256: `{d["source_artifact_sha256"]}`.', '',
                  'Metadata: [deployment.json](deployment.json) and '
                  '[runtime deployment receipt](../../../ml/models/deployment_model.json).', '',
                  'The packaged pipeline fingerprint matches its frozen source pipeline. The managed backend '
                  'was restarted to clear its previous model cache; local health is ready and the text model '
                  'is available. The existing web process and feed worker were preserved.', '',
                  f'Before: **{before["high_n"]} HIGH, {before["medium_or_high_n"]-before["high_n"]} MEDIUM, '
                  f'{12-before["medium_or_high_n"]} LOW**. After: **{after["high_n"]} HIGH, '
                  f'{after["medium_or_high_n"]-after["high_n"]} MEDIUM, {12-after["medium_or_high_n"]} LOW**. '
                  'These twelve existing invented fixtures are exposed selection diagnostics.', '',
                  '| Existing probe index | Before | After |', '| ---: | --- | --- |']
        for b, a in zip(before['rows'], after['rows']):
            lines.append(f'| {b["probe_index"]} | {b["verdict"]} | {a["verdict"]} |')
        lines += ['']
    lines += ['## Verification', '', '| Check | Result | Evidence |', '| --- | --- | --- |']
    for name, check in checks['checks'].items():
        lines.append(f'| {name} | {check["summary"]} (exit {check["exit_code"]}) | [{check["log"]}]({check["log"]}) |')
    lines += ['', f'Protected-file hash comparison: **{checks["protected_files_checked"]} files unchanged**. '
              'Frozen inputs/rules/splits/targets, September artifacts, reviewed reports and the URL deployment '
              'are preserved. Tests and initialization use isolated SQLite databases. No push, merge, history '
              'rewrite, data-URL fetch/resolution or sealed final test was performed.', '',
              '## Reproduction', '', '```powershell',
              '.venv-latency/Scripts/python.exe evaluation/download_latency_models.py',
              '.venv-latency/Scripts/python.exe evaluation/time_text_candidates.py',
              '.venv/Scripts/python.exe evaluation/select_text_v5.py',
              '```', '',
              'The input bundle and returned predictions remain ignored/private; the download command fetches '
              'only the two public pretrained snapshots. The original deployment command is intentionally '
              'one-shot and refuses a changed baseline. Aggregate selection evidence is in '
              '[comparison.json](comparison.json); local raw timings, returned predictions, package freeze '
              'and rollback copies stay ignored.', '',
              'The strict importer ran before deployment on the Phase 1 source. The later runtime change '
              'only makes the API model identifier read the packaged model name. Its file now differs from '
              'the input bundle\'s frozen replay-source hash: repeat strict import in a Phase 1 checkout '
              'at `b13501a`, preserving the bundle manifest, rather than weakening that guard. '
              'Decision-v2 verdict logic and all frozen inputs are unchanged.', '',
              '## Limitations', '',
              '**Threshold ordering.** The deployed high threshold `0.10124534067817578` '
              '(about `0.1012`) is below the low threshold `0.2`. The high check runs first, '
              'so the text MEDIUM band is empty: any probability at or above the high threshold '
              'is text-high. Text-high becomes HIGH with corroboration; without it, it produces '
              'MEDIUM via `text_model_high_uncorroborated`, not `text_medium`. Existing invented '
              'probe 3 illustrates this at probability `0.144231`. This is exactly the behavior '
              'used to measure the selection loss. A legitimate message with a recognized phone '
              'number or short link plus urgent-action wording would therefore be HIGH if its '
              'probability reaches the deployed high threshold (about `0.10`; the exact cutoff '
              'above applies). Any threshold change must be declared in a new dated rule before '
              'measurement, never retuned on these results.', '',
              '- Translated fraud letters/UCI ham and translated/parallel emails dominate held-source evidence; '
              'they do not establish authentic Egyptian SMS performance.',
              '- The dialectal source is non-Egyptian/templated with unverified collection/licence, and remains '
              'training-only. Existing synthetic training material retains its original identity.',
              '- The twelve probes are invented and already exposed. Their use in selection prevents treating '
              'their false-alarm rate as an independent population estimate.',
              '- Equal component and source weights are explicit project choices, not deployment prevalence. '
              'The rule was informed by earlier v3 results; the hardware amendment was made after Colab timing '
              'was visible. Three seeds describe training variability on the same data, not independent cohorts.',
              '- Transformer prediction hashes/contracts detect corruption or stale/mismatched evidence; '
              'they cannot prove that an external runtime honestly performed training. Fine-tuned weights '
              'were not returned, and local transformer latency uses an architecture proxy.',
              '- Latency reflects the declared inference implementations and library builds as well as '
              'hardware, tokenizer and windowing. The local CPU-only and Colab CUDA-enabled Torch builds '
              'share base version 2.11.0; their recorded CPU timings do not establish speed on other '
              'hardware or under other deployment optimizations.',
              '- No genuine Egyptian SMS test messages are available (**count 0**); no sealed final test ran. '
              'English, real traffic generalization and final acceptance remain unestablished.', '']
    (OUT / 'REPORT.md').write_text('\n'.join(lines), encoding='utf-8')
    print('Wrote', OUT / 'REPORT.md')


if __name__ == '__main__':
    main()
