"""Apply the frozen text rule to validated evidence and common-protocol latency.

Writes new aggregate development evidence only. Does not fit or deploy a model,
read sealed data, or rewrite a reviewed report.
"""
import math
from pathlib import Path
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.transformer_contract import MODELS, SEEDS, load_bundle, partitions, read_json, require, sha, write_json

WORK = ROOT / 'evaluation/local-results/text-transformers'
REVIEW = ROOT / 'evaluation/reports/2026-10-v3/review-2026-10-13'
OUT = ROOT / 'evaluation/reports/2026-10-v5'


def loss_components(loso, everyday, sources):
    fnrs, fprs = [], []
    for source in sources:
        held = loso[source]['held_source']
        c = held['confusion']
        require(c['tp'] + c['fn'] == held['phishing_n'] and c['fp'] + c['tn'] == held['legitimate_n'],
                'Source confusion denominator mismatch')
        fnrs.append(c['fn'] / held['phishing_n'])
        fprs.append(c['fp'] / held['legitimate_n'])
    require(everyday['n'] == 12 and everyday['incomplete_n'] == 0, 'All twelve complete probes required')
    return dict(source_mean_fnr=statistics.mean(fnrs), source_mean_fpr=statistics.mean(fprs),
                everyday_medium_or_high_rate=everyday['medium_or_high_n'] / 12)


def percentile95(values):
    ordered = sorted(values)
    offset = (len(ordered) - 1) * .95
    low = int(offset)
    return ordered[low] + (ordered[min(low + 1, len(ordered)-1)] - ordered[low]) * (offset-low)


def choose_candidate(models, rule):
    eligible = [n for n,m in models.items() if m['latency_gate_passes']]
    require(bool(eligible), 'No candidate passes latency')
    best = min(models[n]['mean_primary_loss'] for n in eligible)
    tied = [n for n in eligible if models[n]['mean_primary_loss'] <= best + rule['tie_tolerance']]
    best_f1 = max(models[n]['mean_validation_macro_f1'] for n in tied)
    f1_tied = [n for n in tied if models[n]['mean_validation_macro_f1'] == best_f1]
    if len(f1_tied) == 1:
        winner = f1_tied[0]
    else:
        require(all(n in rule['simplicity_order'] for n in f1_tied),
                'Frozen simplicity order cannot resolve this transformer tie')
        winner = min(f1_tied, key=rule['simplicity_order'].index)
    return winner, dict(eligible=eligible, loss_ties=tied, f1_ties=f1_tied,
                        cpu_p95_limit_ms=rule['max_p95_cpu_ms'], tie_tolerance=rule['tie_tolerance'])


def main():
    manifest, rows, rule, _ = load_bundle(ROOT / 'colab-bundle/payload')
    _, valid, _ = partitions(rows)
    local = read_json(REVIEW / 'text_review_metrics.json')
    imported = read_json(WORK / 'imported.json')
    timings = read_json(WORK / 'local_latency.json')
    require(local['rule_sha256'] == sha(REVIEW / 'model_selection_rule.json'), 'Frozen rule mismatch')
    require(imported['bundle_manifest_sha256'] == sha(ROOT / 'colab-bundle/payload/manifest.json'), 'Bundle mismatch')
    receipt = read_json(WORK / 'returned/results_manifest.json')
    require(imported['input_prediction_files'] == receipt['files'], 'Imported prediction manifest mismatch')
    for file, digest in receipt['files'].items():
        require(sha((WORK / 'returned').joinpath(*re.split(r'[\\/]', file))) == digest, 'Prediction hash changed since import')
    names = [*rule['simplicity_order'], *MODELS]
    require(set(timings['models']) == set(names), 'All seven new timings required')
    models = {}
    for name in names:
        timing = timings['models'][name]
        require(timing['row_ids'] == [r['row_id'] for r in valid] and len(timing['durations_ms']) == 227,
                'Latency must cover the same ordered 227 messages')
        require(timing['amendment_sha256'] == sha(OUT / 'latency_amendment.md'), 'Amendment changed after timing')
        require(timing['timing_script_sha256'] == sha(ROOT / 'evaluation/time_text_candidates.py')
                and timing['text_utils_sha256'] == sha(ROOT / 'backend/app/core/text_utils.py'),
                'Timing or preprocessing code changed after measurement')
        require(timing['fixed_threads'] == 2 and timing['warmup_n'] == 3 and timing['batch_size'] == 1
                and timing['includes_preprocessing'] is True, 'Common timing protocol mismatch')
        require(all(p['num_threads'] <= 2 for p in timing['metadata']['threadpools']), 'Thread-pool cap mismatch')
        for key in ('torch_threads', 'torch_interop_threads', 'tf_intra_threads', 'tf_inter_threads'):
            require(key not in timing['metadata'] or timing['metadata'][key] == 2, 'Framework thread-count mismatch')
        require(math.isclose(timing['p95_ms'], percentile95(timing['durations_ms']), rel_tol=1e-9), 'Invalid p95')
        runs = []
        if name in MODELS:
            evidence = imported['models'][name]['seeds']
            require([r['seed'] for r in evidence] == list(SEEDS), 'All three seeds required')
            for run in evidence:
                comp = loss_components(run['loso'], run['everyday'], rule['primary_sources'])
                value = statistics.mean(comp.values())
                require(math.isclose(value, run['primary_loss'], abs_tol=1e-12), 'Imported loss mismatch')
                runs.append(dict(seed=run['seed'], primary_loss_components=comp, primary_loss=value,
                                 validation=run['validation'], loso=run['loso'], everyday=run['everyday'],
                                 historical_colab_latency={k:v for k,v in run['cpu_latency'].items()
                                                           if k not in ('row_ids', 'durations_ms')},
                                 model_sha256=run['model_sha256']))
        else:
            m = local['models'][name]
            path = ROOT / 'release-artifacts/evaluation/reports/2026-10-v3/models' / (
                'bilstm_candidate.keras' if name == 'bilstm' else name + '.joblib')
            require(sha(path) == m['model_sha256'] == timing['metadata']['model_sha256'], 'Local artifact mismatch')
            comp = loss_components(m['loso'], timing['everyday'], rule['primary_sources'])
            runs.append(dict(seed=42, primary_loss_components=comp, primary_loss=statistics.mean(comp.values()),
                             validation=m['validation']['metrics'], loso=m['loso'], everyday=timing['everyday'],
                             historical_local_latency=m['latency'], model_sha256=m['model_sha256']))
        values = [r['primary_loss'] for r in runs]
        models[name] = dict(runs=runs, mean_primary_loss=statistics.mean(values),
                            min_primary_loss=min(values), max_primary_loss=max(values),
                            mean_primary_loss_components={k: statistics.mean(r['primary_loss_components'][k] for r in runs)
                                                          for k in runs[0]['primary_loss_components']},
                            mean_validation_macro_f1=statistics.mean(
                                r['validation'].get('macro_f1', r['validation'].get('macro_f1_at_recall_95')) for r in runs),
                            local_latency={k:v for k,v in timing.items() if k not in ('row_ids','durations_ms','everyday')},
                            latency_gate_passes=timing['p95_ms'] <= rule['max_p95_cpu_ms'])
    winner, selection = choose_candidate(models, rule)
    result = dict(stage='exposed-development-text-selection', selected_model=winner,
                  transformer_winner=winner in MODELS, selection_only=True,
                  deployment_performed_by_this_script=False, final_test_run=False,
                  rule_path=(REVIEW / 'model_selection_rule.md').relative_to(ROOT).as_posix(),
                  rule_json_sha256=sha(REVIEW / 'model_selection_rule.json'),
                  rule_md_sha256=sha(REVIEW / 'model_selection_rule.md'),
                  amendment_sha256=sha(OUT / 'latency_amendment.md'),
                  frozen_split_sha256=sha(ROOT / 'evaluation/reports/2026-10-v3/text_split.json'),
                  data_sha256=manifest['data_sha256'], imported_sha256=sha(WORK / 'imported.json'),
                  local_latency_sha256=sha(WORK / 'local_latency.json'),
                  pretrained_manifest=read_json(WORK / 'pretrained_manifest.json'),
                  selection=selection,
                  models=models, provenance=rule['provenance'],
                  genuine_egyptian_sms_test_count=0,
                  limitations=['Translated/non-Egyptian sources; not authentic Egyptian SMS performance.',
                               'Twelve invented exposed probes are selection diagnostics, not an independent test.',
                               'Retrospective hardware amendment after seeing Colab latency.',
                               'Transformer local timing uses pretrained weights with an untrained head; no trained weights returned.'])
    write_json(OUT / 'comparison.json', result)
    for name, m in models.items():
        print(name, f'loss={m["mean_primary_loss"]:.9f}', f'p95={m["local_latency"]["p95_ms"]:.6f}',
              'PASS' if m['latency_gate_passes'] else 'REJECT')
    print('SELECTED', winner)


if __name__ == '__main__':
    main()
