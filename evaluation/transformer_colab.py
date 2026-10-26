"""GPU fine-tuning and prediction, followed by an independent CPU timing pass.

Only the hash-verified private bundle is read. No message or embedded URL is fetched.
The notebook installs dependencies and calls run(); importing this file never trains.
"""
import gc
import importlib.metadata
import os
from pathlib import Path
import platform
import tempfile
import time
import zipfile

import numpy as np
import torch
from torch.utils.data import Dataset
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          DataCollatorWithPadding, Trainer, TrainingArguments, set_seed)

from transformer_contract import (MODELS, SCHEMA, SEEDS, load_bundle, partitions, read_json,
                                  require, row_identity, sha, threshold95, validate_run, write_json)
from text_utils import normalize_arabic_text, text_windows

INPUT_POLICY = 'normalized-150-word-windows-stride75-maxprob-256tokens'


def windows(text):
    return [normalize_arabic_text(w) for w in text_windows(text)]


class TrainingRows(Dataset):
    def __init__(self, rows, tokenizer):
        texts, labels = [], []
        for row in rows:
            parts = windows(row['text'])
            texts.extend(parts)
            labels.extend([row['label']] * len(parts))
        self.tokens = tokenizer(texts, truncation=True, max_length=256)
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, i):
        return {**{k: v[i] for k, v in self.tokens.items()}, 'labels': self.labels[i]}


def score_text(model, tokenizer, text, device):
    """Bound memory for long emails; return max phishing score over all windows."""
    parts = windows(text)
    scores = []
    for start in range(0, len(parts), 8):
        batch = tokenizer(parts[start:start + 8], return_tensors='pt', padding=True,
                          truncation=True, max_length=256).to(device)
        with torch.inference_mode():
            scores.extend(torch.softmax(model(**batch).logits, dim=-1)[:, 1].float().cpu().tolist())
    return float(max(scores))


def predict(model, tokenizer, rows):
    return [dict(row_identity(r), score=score_text(model, tokenizer, r['text'], 'cuda')) for r in rows]


def train_fold(model_id, seed, train, valid, held, model_dir):
    # Fixed three epochs; no checkpoint or hyperparameter selection sees held rows/probes.
    set_seed(seed)
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(model_id, num_labels=2, trust_remote_code=False)
    args = TrainingArguments(
        output_dir=str(model_dir / 'trainer'), seed=seed, data_seed=seed,
        num_train_epochs=3, learning_rate=2e-5, weight_decay=.01,
        per_device_train_batch_size=8, gradient_accumulation_steps=2,
        gradient_checkpointing=True, fp16=True, save_strategy='no',
        logging_strategy='epoch', report_to=[], dataloader_num_workers=0,
    )
    trainer = Trainer(model=model, args=args, train_dataset=TrainingRows(train, tokenizer),
                      data_collator=DataCollatorWithPadding(tokenizer, pad_to_multiple_of=8))
    trainer.train()
    model.eval()
    model.save_pretrained(model_dir, safe_serialization=True)
    tokenizer.save_pretrained(model_dir)
    weight_files = sorted(model_dir.glob('*.safetensors'))
    require(len(weight_files) == 1, 'Expected one safetensors weight file')
    validation = predict(model, tokenizer, valid)
    result = dict(training_row_ids=[r['row_id'] for r in train],
                  training_group_ids=sorted({r['group_id'] for r in train}),
                  validation=validation, held=predict(model, tokenizer, held),
                  threshold_95=threshold95(validation), model_sha256=sha(weight_files[0]),
                  model_size_bytes=sum(p.stat().st_size for p in model_dir.iterdir() if p.is_file()),
                  pretrained_commit=getattr(model.config, '_commit_hash', None))
    del trainer
    return result, model, tokenizer


def cpu_latency(model_dir, valid):
    # Reload on CPU after GPU inference and GPU object disposal, then warm up.
    torch.set_num_threads(2)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True).to('cpu').eval()
    tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
    for _ in range(3):
        score_text(model, tokenizer, valid[0]['text'], 'cpu')
    times = []
    for row in valid:
        start = time.perf_counter()
        # One complete message, including normalization, tokenization and all windows.
        score_text(model, tokenizer, row['text'], 'cpu')
        times.append((time.perf_counter() - start) * 1000)
    description = platform.processor() or platform.machine()
    if Path('/proc/cpuinfo').is_file():
        description = next((s.split(':', 1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines()
                            if s.startswith('model name')), description)
    del model
    return dict(cpu_only=True, batch_size=1, warmup_n=3, includes_tokenization_and_windows=True,
                separate_from_gpu_inference=True, row_ids=[r['row_id'] for r in valid],
                durations_ms=times, p50_ms=float(np.percentile(times, 50)), p95_ms=float(np.percentile(times, 95)),
                cpu_description=description, torch_threads=torch.get_num_threads())


def package_results(out, bundle):
    files = {p.name: sha(p) for p in sorted(out.glob('*_seed*.json'))}
    manifest = dict(schema=SCHEMA, bundle_manifest_sha256=sha(bundle / 'manifest.json'),
                    files=files, complete=len(files) == 6, final_test_run=False)
    write_json(out / 'results_manifest.json', manifest)
    archive = out.parent / 'etis-text-results.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in [*files, 'results_manifest.json']:
            z.write(out / name, name)
    return archive


def run(bundle, out, models=None, seeds=None):
    bundle, out = Path(bundle), Path(out)
    _, rows, rule, probes = load_bundle(bundle)
    require(torch.cuda.is_available(), 'Select a Colab GPU runtime before training')
    os.environ['WANDB_DISABLED'] = 'true'
    os.environ['HF_HUB_DISABLE_TELEMETRY'] = '1'
    out.mkdir(parents=True, exist_ok=True)
    for name in models or MODELS:
        require(name in MODELS, 'Unknown model')
        for seed in seeds or SEEDS:
            require(seed in SEEDS, 'Unknown seed')
            target = out / f'{name}_seed{seed}.json'
            if target.exists():
                validate_run(read_json(target), bundle, name, seed)
                print('Verified completed run; skipping', target.name, flush=True)
                continue
            obj = dict(schema=SCHEMA, model=name, model_id=MODELS[name], seed=seed,
                       bundle_manifest_sha256=sha(bundle / 'manifest.json'), final_test_run=False,
                       runtime='colab' if 'COLAB_RELEASE_TAG' in os.environ else 'local',
                       input_policy=INPUT_POLICY, folds={},
                       training=dict(epochs=3, learning_rate=2e-5, effective_batch_size=16,
                                     max_length=256, early_stopping=False),
                       libraries={n: importlib.metadata.version(n) for n in
                                  ('torch', 'transformers', 'accelerate', 'numpy', 'safetensors')},
                       gpu=torch.cuda.get_device_name(0))
            with tempfile.TemporaryDirectory(prefix='etis-model-') as scratch:
                full_dir = Path(scratch) / 'full'
                for key in ['full', *rule['primary_sources']]:
                    print(name, seed, key, flush=True)
                    train, valid, held = partitions(rows, None if key == 'full' else key)
                    model_dir = Path(scratch) / key
                    result, model, tokenizer = train_fold(MODELS[name], seed, train, valid, held, model_dir)
                    obj['folds'][key] = result
                    if key == 'full':
                        obj['probes'] = [dict(probe_index=p['probe_index'], content_sha256=p['content_sha256'],
                                             score=score_text(model, tokenizer, p['text'], 'cuda')) for p in probes]
                    del model, tokenizer
                    gc.collect()
                    torch.cuda.empty_cache()
                _, valid, _ = partitions(rows)
                obj['cpu_latency'] = cpu_latency(full_dir, valid)
            validate_run(obj, bundle, name, seed)
            write_json(target, obj)
            package_results(out, bundle)
            print('Completed', target.name, 'CPU p95 ms:', obj['cpu_latency']['p95_ms'], flush=True)
    return package_results(out, bundle)
