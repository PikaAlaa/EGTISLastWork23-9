"""Download only the two owner-authorized public pretrained snapshots.

No data text or data URL is passed to the hub. Use the revisions recorded in
the validated Colab runs, not the repositories' mutable default branches.
"""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.transformer_contract import MODELS, SEEDS, read_json, require, sha, write_json


def main():
    work = ROOT / 'evaluation/local-results/text-transformers'
    os.environ['HF_HUB_DISABLE_TELEMETRY'] = '1'
    os.environ['HF_HUB_DISABLE_XET'] = '1'
    os.environ['HF_HOME'] = str(work / 'hf-cache')
    from huggingface_hub import HfApi, snapshot_download, constants
    constants.DOWNLOAD_CHUNK_SIZE = 1024 * 1024
    receipt = read_json(work / 'returned/results_manifest.json')
    models = {}
    for name, model_id in MODELS.items():
        revisions = set()
        for seed in SEEDS:
            file = work / f'returned/{name}_seed{seed}.json'
            require(sha(file) == receipt['files'][file.name], 'Returned prediction file hash mismatch')
            revisions.add(read_json(file)['folds']['full']['pretrained_commit'])
        require(len(revisions) == 1, 'Pretrained revision differs between seeds')
        revision = revisions.pop()
        require(isinstance(revision, str) and len(revision) == 40, 'Missing pretrained commit')
        folder = work / 'pretrained' / name
        info = HfApi().model_info(model_id, revision=revision, files_metadata=True)
        require(info.sha == revision, 'Resolved pretrained commit mismatch')
        available = {f.rfilename: f for f in info.siblings}
        weight = 'model.safetensors' if 'model.safetensors' in available else 'pytorch_model.bin'
        require(weight in available, 'No supported public PyTorch weight file')
        lfs = available[weight].lfs
        expected_sha = lfs.get('sha256') if isinstance(lfs, dict) else getattr(lfs, 'sha256', None)
        print('Downloading', name, revision, weight, 'bytes', available[weight].size, flush=True)
        snapshot_download(repo_id=model_id, revision=revision, local_dir=str(folder),
                          cache_dir=str(work / 'hf-cache/hub'), max_workers=2,
                          allow_patterns=['config.json', 'tokenizer.json', 'tokenizer_config.json',
                                          'special_tokens_map.json', 'vocab.txt', 'added_tokens.json',
                                          weight])
        require((folder / 'model.safetensors').is_file() or (folder / 'pytorch_model.bin').is_file(),
                'Snapshot has no PyTorch weights')
        files = {str(p.relative_to(folder)): sha(p) for p in sorted(folder.rglob('*'))
                 if p.is_file() and '.cache' not in p.relative_to(folder).parts}
        require(expected_sha is None or files[weight] == expected_sha, 'Public model LFS SHA-256 mismatch')
        models[name] = dict(model_id=model_id, pretrained_commit=revision,
                            folder=str(folder.relative_to(ROOT)), files_sha256=files,
                            public_weight_sha256=expected_sha, weight_bytes=available[weight].size)
        print(name, revision, flush=True)
    write_json(work / 'pretrained_manifest.json', dict(models=models, data_sent=False))


if __name__ == '__main__':
    main()
