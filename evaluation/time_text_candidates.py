"""Time all seven frozen text candidates under the amended common CPU protocol.

Use .venv-latency. Downloads are a separate explicit step; inference is offline.
Each candidate runs sequentially in a fresh subprocess with two CPU threads.
"""
import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]
from evaluation.transformer_contract import MODELS, load_bundle, partitions, read_json, require, sha, write_json

WORK = ROOT / 'evaluation/local-results/text-transformers'
REVIEW = ROOT / 'evaluation/reports/2026-10-v3/review-2026-10-13'
AMENDMENT = ROOT / 'evaluation/reports/2026-10-v5/latency_amendment.md'
THREADS = 2


def environment():
    return {**os.environ, **{k: str(THREADS) for k in (
        'OMP_NUM_THREADS', 'MKL_NUM_THREADS', 'OPENBLAS_NUM_THREADS',
        'NUMEXPR_NUM_THREADS', 'VECLIB_MAXIMUM_THREADS',
        'TF_NUM_INTRAOP_THREADS', 'TF_NUM_INTEROP_THREADS')},
        'TOKENIZERS_PARALLELISM': 'false', 'CUDA_VISIBLE_DEVICES': '-1',
        'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1',
        'HF_HOME': str(WORK / 'hf-cache'), 'USE_TF': '0',
        'HF_HUB_DISABLE_TELEMETRY': '1', 'TF_CPP_MIN_LOG_LEVEL': '2'}


def worker(name):
    import numpy as np
    from threadpoolctl import threadpool_limits, threadpool_info
    from app.core.text_utils import normalize_arabic_text, text_windows
    manifest, rows, _, _ = load_bundle(ROOT / 'colab-bundle/payload')
    _, valid, _ = partitions(rows)
    require(len(valid) == 227, 'Expected exactly 227 eligible validation messages')
    meta = {}
    if name in MODELS:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, set_seed
        torch.set_num_threads(THREADS)
        torch.set_num_interop_threads(THREADS)
        set_seed(42)
        snap = read_json(WORK / 'pretrained_manifest.json')['models'][name]
        path = ROOT.joinpath(*re.split(r'[\\/]', snap['folder']))
        for file, digest in snap['files_sha256'].items():
            require(sha(path.joinpath(*re.split(r'[\\/]', file))) == digest, 'Pretrained snapshot hash mismatch')
        tokenizer = AutoTokenizer.from_pretrained(str(path), local_files_only=True, trust_remote_code=False)
        model = AutoModelForSequenceClassification.from_pretrained(
            str(path), num_labels=2, local_files_only=True, trust_remote_code=False).to('cpu')
        require(isinstance(model.classifier, torch.nn.Linear) and model.classifier.out_features == 2,
                'Expected an untrained two-class BERT head')
        model.classifier.reset_parameters()
        model.eval()

        def score(text):
            parts = [normalize_arabic_text(w) for w in text_windows(text)]
            scores = []
            for start in range(0, len(parts), 8):
                batch = tokenizer(parts[start:start + 8], return_tensors='pt', padding=True,
                                  truncation=True, max_length=256)
                with torch.inference_mode():
                    scores.extend(torch.softmax(model(**batch).logits, dim=-1)[:, 1].float().tolist())
            return float(max(scores))

        meta.update(kind='pretrained-with-untrained-two-class-head', pretrained=snap,
                    torch_threads=torch.get_num_threads(), torch_interop_threads=torch.get_num_interop_threads(),
                    window_batch_size=8, max_tokens=256)
    else:
        previous = read_json(REVIEW / 'text_review_metrics.json')['models'][name]
        path = ROOT / 'release-artifacts/evaluation/reports/2026-10-v3/models' / (
            'bilstm_candidate.keras' if name == 'bilstm' else name + '.joblib')
        require(sha(path) == previous['model_sha256'], 'Frozen local model hash mismatch')
        meta.update(kind='frozen-fitted-local-candidate', model_sha256=sha(path))
        if name == 'bilstm':
            import pickle
            import tensorflow as tf
            from tensorflow.keras.preprocessing.sequence import pad_sequences
            tf.config.threading.set_intra_op_parallelism_threads(THREADS)
            tf.config.threading.set_inter_op_parallelism_threads(THREADS)
            model = tf.keras.models.load_model(path, compile=False)
            tp = path.with_suffix('.tokenizer.pkl')
            tokenizer = pickle.loads(tp.read_bytes())
            expected = read_json(ROOT / 'evaluation/reports/2026-10-v3/text_local_metrics.json')['models'][name]
            require(sha(tp) == expected['tokenizer_sha256'], 'Frozen tokenizer hash mismatch')
            @tf.function(input_signature=[tf.TensorSpec([None, 200], tf.int32)])
            def infer(x):
                return model(x, training=False)

            def score(text):
                parts = [normalize_arabic_text(w) for w in text_windows(text)]
                x = pad_sequences(tokenizer.texts_to_sequences(parts), maxlen=200,
                                  padding='post', truncating='post')
                return float(np.max(infer(x).numpy()))

            meta.update(tokenizer_sha256=sha(tp), tf_intra_threads=tf.config.threading.get_intra_op_parallelism_threads(),
                        tf_inter_threads=tf.config.threading.get_inter_op_parallelism_threads(),
                        execution='compiled tf.function; dynamic window batch; tracing in first warmup')
        else:
            import joblib
            from sklearn.pipeline import FeatureUnion
            model = joblib.load(path)['pipeline']
            for step in model.steps:
                if 'n_jobs' in step[1].get_params(deep=False):
                    # Avoid process-level fan-out on top of the two-thread
                    # numerical pools. Complete messages remain sequential.
                    step[1].set_params(n_jobs=1 if isinstance(step[1], FeatureUnion) else THREADS)

            def score(text):
                parts = [normalize_arabic_text(w) for w in text_windows(text)]
                return float(model.predict_proba(parts)[:, 1].max())

            meta['estimator_n_jobs'] = {n: s.get_params(deep=False)['n_jobs']
                                        for n, s in model.steps if 'n_jobs' in s.get_params(deep=False)}
    with threadpool_limits(limits=THREADS):
        require(all(p['num_threads'] <= THREADS for p in threadpool_info()), 'Numerical thread pool exceeds fixed cap')
        for _ in range(3):
            score(valid[0]['text'])
        durations = []
        for row in valid:
            start = time.perf_counter()
            score(row['text'])
            durations.append((time.perf_counter() - start) * 1000)
        meta['threadpools'] = threadpool_info()
    everyday = None
    if name not in MODELS:
        # Replay outside the timing samples using the current unchanged policy.
        from evaluation.run_text_review import probe_results
        if name == 'bilstm':
            class Adapter:
                def predict_proba(self, texts):
                    x = pad_sequences(tokenizer.texts_to_sequences(texts), maxlen=200,
                                      padding='post', truncating='post')
                    p = infer(x).numpy().ravel()
                    return np.c_[1-p, p]
            adapter = Adapter()
        else:
            adapter = model
        probes = read_json(ROOT / 'colab-bundle/payload/probes.json')
        everyday = probe_results(adapter, previous['validation']['metrics']['threshold_at_recall_95'],
                                [p['text'] for p in probes])
        everyday.pop('cpu_p95_ms', None)
    libraries = {}
    for package in ('torch', 'transformers', 'safetensors', 'numpy', 'scipy', 'scikit-learn',
                    'joblib', 'lightgbm', 'tensorflow-cpu', 'keras', 'threadpoolctl'):
        try:
            libraries[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            pass
    result = dict(model=name, measured_at_utc=datetime.now(timezone.utc).isoformat(), final_test_run=False, trained=False,
                  amendment_sha256=sha(AMENDMENT), data_sha256=manifest['data_sha256'],
                  timing_script_sha256=sha(Path(__file__)),
                  text_utils_sha256=sha(ROOT / 'backend/app/core/text_utils.py'),
                  bundle_manifest_sha256=sha(ROOT / 'colab-bundle/payload/manifest.json'),
                  cpu_description=cpu_description(), platform=platform.platform(),
                  logical_cpu_count=os.cpu_count(), fixed_threads=THREADS, libraries=libraries,
                  cpu_only=True, batch_size=1, warmup_n=3, includes_preprocessing=True,
                  window_words=150, stride_words=75, metadata=meta,
                  everyday=everyday,
                  row_ids=[r['row_id'] for r in valid], durations_ms=durations,
                  p50_ms=float(np.percentile(durations, 50)), p95_ms=float(np.percentile(durations, 95)))
    write_json(WORK / f'latency_{name}.json', result)
    print(name, f'p50={result["p50_ms"]:.6f} ms p95={result["p95_ms"]:.6f} ms', flush=True)


def cpu_description():
    if os.name == 'nt':
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
            return winreg.QueryValueEx(key, 'ProcessorNameString')[0].strip()
    return platform.processor() or platform.machine()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', choices=[*read_json(REVIEW / 'model_selection_rule.json')['simplicity_order'], *MODELS])
    args = parser.parse_args()
    require(AMENDMENT.is_file(), 'Write amendment before measurement')
    if args.worker:
        worker(args.worker)
        return
    models = [*read_json(REVIEW / 'model_selection_rule.json')['simplicity_order'], *MODELS]
    for name in models:
        subprocess.run([sys.executable, str(Path(__file__).resolve()), '--worker', name],
                       cwd=ROOT, env=environment(), check=True)
    results = {n: read_json(WORK / f'latency_{n}.json') for n in models}
    first = results[models[0]]
    for result in results.values():
        require(result['row_ids'] == first['row_ids'] and result['amendment_sha256'] == first['amendment_sha256'],
                'Common protocol inputs changed between candidates')
    write_json(WORK / 'local_latency.json', dict(protocol='common-227-three-warmups-two-threads-v1',
                                               models=results, final_test_run=False))


if __name__ == '__main__':
    main()
