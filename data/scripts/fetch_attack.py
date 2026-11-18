"""Download the two pinned MITRE ATT&CK STIX files and verify their SHA-256 (design core-v1 §4.1).

Run manually, once: `python data/scripts/fetch_attack.py`. The app never runs this.
It downloads only the URLs pinned in data/attack-lock.json (both under
raw.githubusercontent.com/mitre-attack/), sends no ETIS data anywhere, writes to
a temporary file and keeps the result only when size and SHA-256 match the lock.
An existing file that already matches is not downloaded again.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'data' / 'attack-lock.json'
ALLOWED_PREFIX = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/'
MAX_BYTES = 100_000_000


def load_lock(path: Path = LOCK) -> dict:
    lock = json.loads(path.read_text(encoding='utf-8'))
    if len(lock['files']) != 2 or {f['collection'] for f in lock['files']} != {'enterprise', 'mobile'}:
        raise ValueError('lock_must_pin_exactly_enterprise_and_mobile')
    for entry in lock['files']:
        if not entry['url'].startswith(ALLOWED_PREFIX) or Path(entry['file']).name != entry['file']:
            raise ValueError('unexpected_pinned_location')
        if len(entry['sha256']) != 64:
            raise ValueError('invalid_pinned_sha256')
    return lock


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, entry: dict) -> bool:
    return path.is_file() and path.stat().st_size == entry['size'] and file_sha256(path) == entry['sha256']


def download(entry: dict, destination: Path, session=requests) -> str:
    target = destination / entry['file']
    if verify(target, entry):
        return 'already_verified'
    partial = target.with_suffix(target.suffix + '.part')
    digest, size = hashlib.sha256(), 0
    try:
        with session.get(entry['url'], headers={'User-Agent': 'ETIS-Local-Research/0.2'}, timeout=(10, 120),
                         stream=True) as response:
            response.raise_for_status()
            with partial.open('wb') as handle:
                for chunk in response.iter_content(1 << 20):
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise ValueError('download_too_large')
                    digest.update(chunk)
                    handle.write(chunk)
        if size != entry['size'] or digest.hexdigest() != entry['sha256']:
            raise ValueError(f"sha256_mismatch:{entry['file']}")
        os.replace(partial, target)
        return 'downloaded_and_verified'
    finally:
        if partial.exists():
            partial.unlink()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--verify-only', action='store_true', help='check existing files; download nothing')
    args = parser.parse_args(argv)
    lock = load_lock()
    destination = ROOT / lock['destination']
    destination.mkdir(parents=True, exist_ok=True)
    results = {}
    for entry in lock['files']:
        if args.verify_only:
            results[entry['file']] = 'verified' if verify(destination / entry['file'], entry) else 'missing_or_mismatch'
        else:
            results[entry['file']] = download(entry, destination)
    print(json.dumps(results))
    return 0 if all(v in ('verified', 'already_verified', 'downloaded_and_verified') for v in results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
