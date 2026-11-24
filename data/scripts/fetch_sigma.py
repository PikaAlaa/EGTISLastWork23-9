"""Download the pinned SigmaHQ release package, verify it and extract its rule files (design host-engine-v1 §2.2).

Run manually, once: `python data/scripts/fetch_sigma.py`. The app never runs this.
It downloads only the package pinned in data/sigma-lock.json (a SigmaHQ GitHub release
asset), sends no ETIS data anywhere, writes to a temporary file and keeps the package only
when size and SHA-256 match the lock. It then extracts only `.yml` rule files and
`version.txt` into a new directory, refusing unsafe paths and oversized members, and keeps
the extraction only when the tree hash (SHA-256 over sorted "path<TAB>sha256" lines of the
`.yml` files) matches the lock. Rule files are never modified. Nothing is executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path, PurePosixPath

import requests

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'data' / 'sigma-lock.json'
ALLOWED_PREFIX = 'https://github.com/SigmaHQ/sigma/releases/download/'
MAX_PACKAGE_BYTES = 50_000_000
MAX_MEMBER_BYTES = 2_000_000
MAX_TOTAL_BYTES = 100_000_000
MAX_MEMBERS = 20_000
KEEP_FILES = {'version.txt'}


def load_lock(path: Path = LOCK) -> dict:
    lock = json.loads(Path(path).read_text(encoding='utf-8'))
    package, extracted = lock['package'], lock['extracted']
    if not package['url'].startswith(ALLOWED_PREFIX) or Path(package['file']).name != package['file']:
        raise ValueError('unexpected_pinned_location')
    if not package['url'].endswith(f"/{lock['release']}/{package['file']}"):
        raise ValueError('unexpected_pinned_location')
    if len(package['sha256']) != 64 or len(extracted['tree_sha256']) != 64:
        raise ValueError('invalid_pinned_sha256')
    if Path(extracted['directory']).name != extracted['directory']:
        raise ValueError('unexpected_pinned_location')
    return lock


def long_path(path: Path) -> Path:
    """Windows extended-length form, so deeply nested rule paths do not hit the 260-character limit."""
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


def tree_sha256(root: Path) -> tuple[str, int]:
    """SHA-256 over sorted 'relative/path<TAB>sha256' lines of every .yml file under root."""
    base = long_path(root)
    lines = sorted(f'{p.relative_to(base).as_posix()}\t{file_sha256(p)}' for p in base.rglob('*.yml') if p.is_file())
    return hashlib.sha256(('\n'.join(lines) + '\n').encode('utf-8')).hexdigest(), len(lines)


def _verified_package(path: Path, entry: dict) -> bool:
    return path.is_file() and path.stat().st_size == entry['size'] and file_sha256(path) == entry['sha256']


def _download(entry: dict, target: Path, session) -> None:
    partial = target.with_suffix(target.suffix + '.part')
    digest, size = hashlib.sha256(), 0
    try:
        with session.get(entry['url'], headers={'User-Agent': 'ETIS-Local-Research/0.2'}, timeout=(10, 120),
                         stream=True) as response:
            response.raise_for_status()
            with partial.open('wb') as handle:
                for chunk in response.iter_content(1 << 20):
                    size += len(chunk)
                    if size > MAX_PACKAGE_BYTES:
                        raise ValueError('download_too_large')
                    digest.update(chunk)
                    handle.write(chunk)
        if size != entry['size'] or digest.hexdigest() != entry['sha256']:
            raise ValueError(f"sha256_mismatch:{entry['file']}")
        os.replace(partial, target)
    finally:
        if partial.exists():
            partial.unlink()


def _safe_name(name: str) -> PurePosixPath:
    if '\\' in name or name.startswith('/') or ':' in name:
        raise ValueError('unsafe_member')
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ('..', '') for part in path.parts):
        raise ValueError('unsafe_member')
    return path


def extract(package: Path, destination: Path) -> None:
    """Extract .yml rules and version.txt into a new, empty `destination`."""
    destination.mkdir(parents=True, exist_ok=False)
    total = 0
    with zipfile.ZipFile(package) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError('too_many_members')
        for info in members:
            if info.is_dir():
                continue
            path = _safe_name(info.filename)
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('unsafe_member')
            if not (path.suffix == '.yml' or (len(path.parts) == 1 and path.name in KEEP_FILES)):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                raise ValueError('member_too_large')
            body = archive.read(info)
            if len(body) > MAX_MEMBER_BYTES:
                raise ValueError('member_too_large')
            total += len(body)
            if total > MAX_TOTAL_BYTES:
                raise ValueError('package_too_large')
            target = long_path(destination).joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)


def fetch(lock: dict, destination: Path, session=requests) -> str:
    """Download (if needed), verify, extract and verify the tree; returns a status code."""
    entry, expected = lock['package'], lock['extracted']
    destination.mkdir(parents=True, exist_ok=True)
    package, rules = destination / entry['file'], destination / expected['directory']
    if _verified_package(package, entry) and rules.is_dir() and tree_sha256(rules) == (
            expected['tree_sha256'], expected['rule_files']):
        return 'already_verified'
    if not _verified_package(package, entry):
        _download(entry, package, session)
    if rules.exists():
        shutil.rmtree(long_path(rules))
    try:
        extract(package, rules)
        tree, count = tree_sha256(rules)
        if (tree, count) != (expected['tree_sha256'], expected['rule_files']):
            raise ValueError('tree_sha256_mismatch')
    except Exception:
        shutil.rmtree(long_path(rules), ignore_errors=True)
        raise
    return 'downloaded_and_verified'


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--verify-only', action='store_true', help='check existing files; download nothing')
    args = parser.parse_args(argv)
    lock = load_lock()
    destination = ROOT / lock['destination']
    if args.verify_only:
        entry, expected = lock['package'], lock['extracted']
        rules = destination / expected['directory']
        ok = _verified_package(destination / entry['file'], entry) and rules.is_dir() and \
            tree_sha256(rules) == (expected['tree_sha256'], expected['rule_files'])
        status = 'verified' if ok else 'missing_or_mismatch'
    else:
        status = fetch(lock, destination)
    print(json.dumps({lock['release']: status}))
    return 0 if status in ('verified', 'already_verified', 'downloaded_and_verified') else 1


if __name__ == '__main__':
    sys.exit(main())
