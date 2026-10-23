"""Import complete transformer development evidence; never select or deploy a model."""
import argparse
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
from evaluation.transformer_contract import (MODELS, SCHEMA, SEEDS, load_bundle, read_json,
                                            require, sha, validate_run, write_json)

REPORT = ROOT / 'evaluation/reports/2026-10-v3'
DEFAULT_RESULTS = ROOT / 'evaluation/local-results/text-transformers'


def metrics(rows, threshold):
    tp = sum(r['label'] == 1 and r['score'] >= threshold for r in rows)
    fn = sum(r['label'] == 1 and r['score'] < threshold for r in rows)
    fp = sum(r['label'] == 0 and r['score'] >= threshold for r in rows)
    tn = sum(r['label'] == 0 and r['score'] < threshold for r in rows)
    return dict(n=len(rows), phishing_n=tp + fn, legitimate_n=fp + tn,
                threshold_95=threshold, confusion=dict(tp=tp, fn=fn, fp=fp, tn=tn),
                phishing_recall=tp / (tp + fn) if tp + fn else None,
                legitimate_fpr=fp / (fp + tn) if fp + tn else None,
                macro_f1=(2 * tp / max(2 * tp + fp + fn, 1) + 2 * tn / max(2 * tn + fp + fn, 1)) / 2)


def replay_probes(obj, probes):
    # Use the existing review's exact policy replay and its 0.2 low threshold.
    # The adapter serves returned probabilities, never loads or trains a model.
    import numpy as np
    from app.core.text_utils import normalize_arabic_text, text_windows
    from evaluation.run_text_review import probe_results
    scores = {p['probe_index']: p['score'] for p in obj['probes']}
    lookup = {}
    for probe in probes:
        for window in text_windows(probe['text']):
            key = normalize_arabic_text(window)
            require(key not in lookup or lookup[key] == scores[probe['probe_index']], 'Conflicting probe-window scores')
            lookup[key] = scores[probe['probe_index']]

    class ReturnedScores:
        def predict_proba(self, texts):
            return np.array([[1 - lookup[t], lookup[t]] for t in texts])

    result = probe_results(ReturnedScores(), obj['folds']['full']['threshold_95'], [p['text'] for p in probes])
    # The adapter's lookup time is not model latency. Use the separate CPU pass only.
    result.pop('cpu_p95_ms', None)
    require(result['incomplete_n'] == 0, 'Incomplete Decision-v2 probe replay')
    return result


def import_results(bundle, predictions):
    bundle, predictions = Path(bundle), Path(predictions)
    manifest, _, rule, probes = load_bundle(bundle)
    require(sha(REPORT / 'text_split.json') == manifest['files']['text_split.json'], 'Current frozen split hash mismatch')
    for ext in ('json', 'md'):
        require(sha(REPORT / f'review-2026-10-13/model_selection_rule.{ext}') == manifest['files'][f'rule.{ext}'],
                'Current frozen rule hash mismatch')
    for name, digest in manifest['local_replay_sha256'].items():
        require(sha(ROOT / name) == digest, f'Local policy/probe source hash mismatch: {name}')
    from evaluation.build_transformer_colab_bundle import existing_probes
    require([p['text'] for p in probes] == existing_probes(), 'Existing everyday probes differ')
    receipt = read_json(predictions / 'results_manifest.json')
    require(receipt.get('schema') == SCHEMA and receipt.get('final_test_run') is False, 'Result manifest schema/test mismatch')
    require(receipt.get('bundle_manifest_sha256') == sha(bundle / 'manifest.json'), 'Result input manifest hash mismatch')
    expected_files = {f'{name}_seed{seed}.json' for name in MODELS for seed in SEEDS}
    require(set(receipt['files']) == expected_files and receipt.get('complete') is True, 'Six complete result files required')
    require({p.name for p in predictions.iterdir()} == expected_files | {'results_manifest.json'}, 'Unexpected returned files')
    # Validate the complete return before replay or writing any merged evidence.
    objects = {}
    for name in MODELS:
        for seed in SEEDS:
            filename = f'{name}_seed{seed}.json'
            require(sha(predictions / filename) == receipt['files'][filename], f'Returned SHA-256 mismatch: {filename}')
            objects[name, seed] = validate_run(read_json(predictions / filename), bundle, name, seed)
    models = {}
    for name in MODELS:
        runs = []
        for seed in SEEDS:
            obj = objects[name, seed]
            full = obj['folds']['full']
            loso = {}
            for source in rule['primary_sources']:
                fold = obj['folds'][source]
                loso[source] = dict(provenance=rule['provenance'][source],
                                    threshold_validation=metrics(fold['validation'], fold['threshold_95']),
                                    held_source=metrics(fold['held'], fold['threshold_95']),
                                    training_n=len(fold['training_row_ids']), model_sha256=fold['model_sha256'])
            everyday = replay_probes(obj, probes)
            components = dict(source_mean_fnr=statistics.mean(1 - x['held_source']['phishing_recall'] for x in loso.values()),
                              source_mean_fpr=statistics.mean(x['held_source']['legitimate_fpr'] for x in loso.values()),
                              everyday_medium_or_high_rate=float(everyday['medium_or_high_rate']))
            runs.append(dict(seed=seed, validation=metrics(full['validation'], full['threshold_95']),
                             loso=loso, everyday=everyday, primary_loss_components=components,
                             primary_loss=statistics.mean(components.values()), cpu_latency=obj['cpu_latency'],
                             cpu_gate_passes=obj['cpu_latency']['p95_ms'] <= rule['max_p95_cpu_ms'],
                             model_sha256=full['model_sha256'], libraries=obj['libraries']))
        models[name] = dict(seeds=runs, mean_primary_loss=statistics.mean(r['primary_loss'] for r in runs),
                            mean_cpu_p95_ms=statistics.mean(r['cpu_latency']['p95_ms'] for r in runs))
    return dict(schema=SCHEMA, stage='phase1_validated_development_evidence', final_test_run=False,
                final_choice=False, deployed_text_model_changed=False, selection_performed=False,
                data_sha256=manifest['data_sha256'], bundle_manifest_sha256=sha(bundle / 'manifest.json'),
                input_prediction_files=receipt['files'], models=models, provenance=rule['provenance'],
                aggregation='Unweighted means across three seeds; no ranking or selection performed.',
                limitations=['Colab CPU timing describes the recorded hardware, not the deployment machine.',
                             'File hashes and row contracts detect mismatched files, not proof of honest training.',
                             'Translated sources and invented probes are not an authentic Egyptian SMS benchmark.'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=ROOT / 'colab-bundle/payload')
    parser.add_argument('--predictions', type=Path, default=DEFAULT_RESULTS / 'returned')
    parser.add_argument('--output', type=Path, default=DEFAULT_RESULTS / 'imported.json')
    args = parser.parse_args(argv)
    require(args.output.resolve().is_relative_to((ROOT / 'evaluation/local-results').resolve()),
            'Output must stay under ignored evaluation/local-results; reviewed reports are read-only')
    result = import_results(args.bundle, args.predictions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, result)
    print(f'Validated six runs: {args.output}. No model selected or deployed.')


if __name__ == '__main__':
    main()
