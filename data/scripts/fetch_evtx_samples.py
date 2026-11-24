"""Download EVTX-ATTACK-SAMPLES at one pinned commit and verify every kept file (design host-engine-v1 §3.2).

Run manually, once: `python data/scripts/fetch_evtx_samples.py`. The app never runs this.
It downloads only the GitHub archive of the commit pinned in
data/evtx-attack-samples-lock.json, sends no ETIS data anywhere, and keeps only the `.evtx`
files, `LICENSE.GPL` and `README.md`. GitHub-generated archives are not guaranteed to be
byte-stable, so the authority is the lock's per-file SHA-256: the extraction is kept only
when exactly the pinned files are present and every one matches. The archive is deleted
afterwards. Samples are never parsed, opened as logs, or executed here; scripts and other
files in the repository are skipped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile
from pathlib import Path, PurePosixPath

import requests

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'data' / 'evtx-attack-samples-lock.json'
ALLOWED_PREFIX = 'https://codeload.github.com/sbousseaden/EVTX-ATTACK-SAMPLES/zip/'
MAX_ARCHIVE_BYTES = 200_000_000
MAX_MEMBER_BYTES = 50_000_000
MAX_TOTAL_BYTES = 500_000_000
KEEP_SUFFIXES = ('.evtx',)
KEEP_NAMES = {'LICENSE.GPL', 'README.md'}
_COMMIT = re.compile(r'^[0-9a-f]{40}$')


def _safe_relative(text: str) -> PurePosixPath:
    if '\\' in text or text.startswith('/') or ':' in text:
        raise ValueError('unsafe_member')
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in ('..', '', '.') for part in path.parts):
        raise ValueError('unsafe_member')
    return path


def load_lock(path: Path = LOCK) -> dict:
    lock = json.loads(Path(path).read_text(encoding='utf-8'))
    if not _COMMIT.match(lock['commit']) or lock['archive']['url'] != ALLOWED_PREFIX + lock['commit']:
        raise ValueError('unexpected_pinned_location')
    if Path(lock['directory']).name != lock['directory']:
        raise ValueError('unexpected_pinned_location')
    for entry in lock['files']:
        _safe_relative(entry['path'])
        if len(entry['sha256']) != 64:
            raise ValueError('invalid_pinned_sha256')
    return lock


def long_path(path: Path) -> Path:
    """Windows extended-length form for deeply nested paths."""
    text = str(Path(path).resolve())
    if os.name == 'nt' and not text.startswith('\\\\?\\'):
        text = '\\\\?\\' + text
    return Path(text)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with long_path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _kept(relative: PurePosixPath) -> bool:
    return relative.suffix.lower() in KEEP_SUFFIXES or (len(relative.parts) == 1 and relative.name in KEEP_NAMES)


def verify_tree(root: Path, lock: dict) -> str | None:
    """None when exactly the pinned files are present with matching hashes, else a reason code."""
    pinned = {entry['path']: entry for entry in lock['files']}
    base = long_path(root)
    present = {p.relative_to(base).as_posix() for p in base.rglob('*') if p.is_file()}
    if present != set(pinned):
        return 'file_set_mismatch'
    for name, entry in pinned.items():
        path = base / name
        if path.stat().st_size != entry['size'] or file_sha256(path) != entry['sha256']:
            return 'file_sha256_mismatch'
    return None


def _download(url: str, target: Path, session) -> str:
    partial = target.with_suffix(target.suffix + '.part')
    digest, size = hashlib.sha256(), 0
    try:
        with session.get(url, headers={'User-Agent': 'ETIS-Local-Research/0.2'}, timeout=(10, 300),
                         stream=True) as response:
            response.raise_for_status()
            with partial.open('wb') as handle:
                for chunk in response.iter_content(1 << 20):
                    size += len(chunk)
                    if size > MAX_ARCHIVE_BYTES:
                        raise ValueError('download_too_large')
                    digest.update(chunk)
                    handle.write(chunk)
        os.replace(partial, target)
        return digest.hexdigest()
    finally:
        if partial.exists():
            partial.unlink()


def extract(archive: Path, destination: Path, top_level: str) -> None:
    """Extract kept files from the archive's single top-level folder into a new `destination`."""
    destination.mkdir(parents=True, exist_ok=False)
    prefix, total = top_level + '/', 0
    with zipfile.ZipFile(archive) as handle:
        for info in handle.infolist():
            if not info.filename.startswith(prefix):
                raise ValueError('unsafe_member')
            if info.is_dir():
                continue
            relative = _safe_relative(info.filename[len(prefix):])
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('unsafe_member')
            if not _kept(relative):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValueError('member_too_large')
            body = handle.read(info)
            if len(body) > MAX_MEMBER_BYTES:
                raise ValueError('member_too_large')
            total += len(body)
            if total > MAX_TOTAL_BYTES:
                raise ValueError('archive_too_large')
            target = long_path(destination).joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)


def fetch(lock: dict, destination: Path, session=requests) -> str:
    destination.mkdir(parents=True, exist_ok=True)
    final = destination / lock['directory']
    if final.is_dir() and verify_tree(final, lock) is None:
        return 'already_verified'
    archive = destination / f"{lock['directory']}.zip"
    staging = destination / f"{lock['directory']}.partial"
    for leftover in (staging, final):
        if leftover.exists():
            shutil.rmtree(long_path(leftover))
    try:
        observed = _download(lock['archive']['url'], archive, session)
        extract(archive, staging, lock['archive']['top_level'])
        problem = verify_tree(staging, lock)
        if problem:
            raise ValueError(problem)
        os.replace(staging, final)
    except Exception:
        if staging.exists():
            shutil.rmtree(long_path(staging), ignore_errors=True)
        raise
    finally:
        if archive.exists():
            archive.unlink()
    expected = lock['archive'].get('observed_sha256')
    return 'downloaded_and_verified' if not expected or expected == observed else 'downloaded_and_verified_new_archive_bytes'


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--verify-only', action='store_true', help='check existing files; download nothing')
    args = parser.parse_args(argv)
    lock = load_lock()
    destination = ROOT / lock['destination']
    if args.verify_only:
        final = destination / lock['directory']
        status = 'verified' if final.is_dir() and verify_tree(final, lock) is None else 'missing_or_mismatch'
    else:
        status = fetch(lock, destination)
    print(json.dumps({lock['commit']: status}))
    return 0 if status in ('verified', 'already_verified', 'downloaded_and_verified',
                           'downloaded_and_verified_new_archive_bytes') else 1


if __name__ == '__main__':
    sys.exit(main())
