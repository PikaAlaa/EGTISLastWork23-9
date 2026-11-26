"""Download the three pinned EMBER2024 PE train zips, verify them and inspect their central directories
(design malware-engine-v1 §3.7, §4.2 download rule of 26 November 2026, §9 step 7).

Run manually; the app never runs this.
  python data/scripts/fetch_ember2024.py --file Dot_Net_train.zip   download, resume, verify one file
  python data/scripts/fetch_ember2024.py --verify-only               check every downloaded file
  python data/scripts/fetch_ember2024.py --inspect                   central-directory report

- Only Dot_Net_train.zip, Win64_train.zip and Win32_train.zip of joyce8/EMBER2024 at the pinned
  revision are ever requested; test zips, challenge.zip and other file types are refused. thrember's
  download_dataset and download_models are never used.
- Plain HTTPS streaming from huggingface.co/datasets/.../resolve/<revision>/<file>. Redirects are
  followed only to huggingface.co or *.hf.co hosts; anything else stops the run. Nothing is uploaded.
- Writes go to `<file>.part` with resume (HTTP Range). The file gets its final name only after its size
  and SHA-256 equal Hugging Face's LFS metadata for that revision. A mismatch stops the run and keeps
  the .part file for review.
- At least 30 GB must stay free on the download drive; a file that would go below that is not started.
- Inspection reads only each zip's central directory (zipfile infolist). No member is opened,
  extracted, decompressed or loaded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import time
import zipfile
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'data' / 'ember2024-lock.json'
DEFAULT_DESTINATION = ROOT / 'data' / 'external' / 'ember2024'
REPORT = ROOT / 'evaluation' / 'reports' / '2026-11-malware-v1' / 'ember2024_zip_inspection.json'
DATASET = 'joyce8/EMBER2024'
USER_AGENT = 'ETIS-Local-Research/0.2'
MIN_FREE_BYTES = 30 * 1024 ** 3
CHUNK = 8 * 1024 * 1024
MAX_ATTEMPTS = 30
GIB = 1024 ** 3

# Pinned from the Hugging Face API on 2026-11-26: the newest revision (2025-08-22), more than two weeks
# old. Sizes and SHA-256 are the LFS metadata Hugging Face publishes for each file at that revision.
REVISION = '3d23efef7c0f0b702c5024400cfff4c3744a3832'
REVISION_DATE = '2025-08-22T20:14:18Z'
FILES = {
    'Dot_Net_train.zip': {'size': 937108923, 'card_gb': 0.94,
                          'sha256': 'b9f6e90ab75293a7ceb9339700586dd033a03d19766282755ee31dfa0836e625'},
    'Win64_train.zip': {'size': 5853142901, 'card_gb': 5.85,
                        'sha256': '7b050100ce7bd87149bbfca442de3e02d4bf97d51251566caec2581eebe799fd'},
    'Win32_train.zip': {'size': 12321281336, 'card_gb': 12.3,
                        'sha256': '6cf9dea847960115f65d405d38b6b09d38c87225c8288dafedf00fed2512b1d4'},
}
ORDER = ('Dot_Net_train.zip', 'Win64_train.zip', 'Win32_train.zip')

PICKLE_EXTENSIONS = {'.pkl', '.pickle', '.pt', '.pth', '.joblib', '.npy', '.npz', '.dill', '.sav', '.ckpt'}
EXECUTABLE_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.bin', '.com', '.cpl', '.ocx', '.msi', '.bat', '.cmd',
                         '.ps1', '.vbs', '.js', '.jse', '.wsf', '.hta', '.lnk', '.jar', '.apk', '.elf', '.so',
                         '.dylib', '.py', '.pyc', '.sh', '.zip', '.7z', '.rar', '.gz', '.tar', '.xz', '.bz2'}


class FetchStop(RuntimeError):
    """A fixed reason code; the run stops and nothing is worked around."""


def destination() -> Path:
    value = os.getenv('ETIS_EMBER_DIR', '').strip()
    if not value:
        env = ROOT / '.env'
        if env.is_file():
            from dotenv import dotenv_values
            value = (dotenv_values(env).get('ETIS_EMBER_DIR') or '').strip()
    return Path(value) if value else DEFAULT_DESTINATION


def resolve_url(name: str) -> str:
    if name not in FILES:
        raise FetchStop('file_not_allowed')
    return f'https://huggingface.co/datasets/{DATASET}/resolve/{REVISION}/{name}'


def allowed_host(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or '').lower()
    return parsed.scheme == 'https' and (host == 'huggingface.co' or host.endswith('.huggingface.co')
                                         or host.endswith('.hf.co'))


def open_stream(session, name: str, start: int):
    """GET with Range from `start`, following redirects only to Hugging Face hosts."""
    url = resolve_url(name)
    headers = {'User-Agent': USER_AGENT}
    if start:
        headers['Range'] = f'bytes={start}-'
    for _ in range(6):
        if not allowed_host(url):
            raise FetchStop('unexpected_redirect_host:' + (urlparse(url).hostname or ''))
        response = session.get(url, headers=headers, stream=True, allow_redirects=False, timeout=(30, 120))
        if response.status_code in (301, 302, 303, 307, 308):
            linked = response.headers.get('X-Linked-Etag', '').strip('"')
            if linked and len(linked) == 64 and linked != FILES[name]['sha256']:
                raise FetchStop('linked_etag_mismatch')
            url = urljoin(url, response.headers['Location'])
            response.close()
            continue
        return response
    raise FetchStop('too_many_redirects')


def sha256_of(path: Path, limit: int | None = None):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        remaining = limit
        while True:
            block = handle.read(CHUNK if remaining is None else min(CHUNK, remaining))
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
                if remaining <= 0:
                    break
    return digest


def check_free_space(folder: Path, still_needed: int) -> None:
    free = shutil.disk_usage(folder).free
    if free - still_needed < MIN_FREE_BYTES:
        raise FetchStop('insufficient_free_space')


def log(message: str) -> None:
    print(f'{datetime.now().strftime("%H:%M:%S")} {message}', flush=True)


def download(name: str, folder: Path, session) -> dict:
    pin = FILES[name]
    final, part = folder / name, folder / (name + '.part')
    if final.exists():
        if final.stat().st_size == pin['size'] and sha256_of(final).hexdigest() == pin['sha256']:
            log(f'{name}: already present and verified')
            return {'status': 'already_verified'}
        raise FetchStop('existing_file_mismatch')
    have = part.stat().st_size if part.exists() else 0
    if have > pin['size']:
        raise FetchStop('part_larger_than_pinned_size')
    check_free_space(folder, pin['size'] - have)
    digest = sha256_of(part) if have else hashlib.sha256()
    attempts = 0
    next_report = have + GIB
    while have < pin['size']:
        attempts += 1
        if attempts > MAX_ATTEMPTS:
            raise FetchStop('too_many_attempts')
        try:
            response = open_stream(session, name, have)
            if have and response.status_code == 200:
                raise FetchStop('server_ignored_range')
            if response.status_code not in (200, 206):
                response.close()
                raise ConnectionError(f'http_{response.status_code}')
            with open(part, 'ab') as handle:
                for block in response.iter_content(CHUNK):
                    if not block:
                        continue
                    if have + len(block) > pin['size']:
                        raise FetchStop('download_larger_than_pinned_size')
                    handle.write(block)
                    digest.update(block)
                    have += len(block)
                    if have >= next_report:
                        log(f'{name}: {have / GIB:.2f} / {pin["size"] / GIB:.2f} GiB')
                        next_report += GIB
                        check_free_space(folder, pin['size'] - have)
            response.close()
        except FetchStop:
            raise
        except Exception as exc:  # network errors: resume from what is on disk
            wait = min(60, 5 * attempts)
            log(f'{name}: attempt {attempts} interrupted ({type(exc).__name__}); resuming in {wait}s')
            time.sleep(wait)
            have = part.stat().st_size if part.exists() else 0
            digest = sha256_of(part) if have else hashlib.sha256()
            continue
    size = part.stat().st_size
    if size != pin['size']:
        raise FetchStop('size_mismatch')
    measured = digest.hexdigest()
    if measured != pin['sha256']:
        raise FetchStop('sha256_mismatch')
    os.replace(part, final)
    time.sleep(2)
    if not final.exists() or final.stat().st_size != pin['size']:
        raise FetchStop('removed_after_write')
    log(f'{name}: downloaded and verified')
    return {'status': 'downloaded_and_verified', 'sha256_measured': measured}


def write_lock(results: dict, folder: Path) -> dict:
    lock = json.loads(LOCK.read_text(encoding='utf-8')) if LOCK.exists() else {}
    lock.update({
        'description': 'Pinned EMBER2024 PE train zips for the malware engine (docs/design/malware-engine-v1.md '
                       '§3.7, §4.2, §9 step 7). Fetched and verified by data/scripts/fetch_ember2024.py.',
        'dataset': DATASET,
        'dataset_url': f'https://huggingface.co/datasets/{DATASET}',
        'revision': REVISION,
        'revision_date': REVISION_DATE,
        'pinned_on': '2026-11-26',
        'pin_reason': 'Newest dataset revision on 2026-11-26 (2025-08-22), more than two weeks old. Only the '
                      'Win32, Win64 and Dot_Net train zips were approved by the owner on 2026-11-26.',
        'license': 'Apache-2.0',
        'license_source': 'dataset card metadata (license: apache-2.0) and the EMBER2024 code repository',
        'citation': 'Joyce et al., "EMBER2024 - A Benchmark Dataset for Holistic Evaluation of Malware '
                    'Classifiers", KDD 2025, DOI 10.1145/3711896.3737431',
        'destination': 'data/external/ember2024/' if folder == DEFAULT_DESTINATION else 'ETIS_EMBER_DIR',
        'sha256_source': 'Hugging Face LFS oid (SHA-256) and size for each file at the pinned revision, from '
                         '/api/datasets/joyce8/EMBER2024/tree/<revision>; each file is hashed locally on '
                         'download and must match',
        'not_downloaded': 'Every other file of the repository, including the test zips, challenge.zip and the '
                          'APK, ELF and PDF zips. thrember download_dataset and download_models are never used.',
    })
    entries = {e['file']: e for e in lock.get('files', [])}
    for name in ORDER:
        pin = FILES[name]
        entry = entries.get(name, {'file': name})
        entry.update({'url': resolve_url(name), 'size': pin['size'], 'card_size_gb': pin['card_gb'],
                      'sha256': pin['sha256']})
        result = results.get(name)
        if result and result['status'] == 'downloaded_and_verified':
            entry['downloaded_on'] = date.today().isoformat()
            entry['sha256_measured'] = result['sha256_measured']
            entry['verified'] = True
        entries[name] = entry
    lock['files'] = [entries[name] for name in ORDER]
    LOCK.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')
    return lock


def verify_all(folder: Path) -> dict:
    out = {}
    for name in ORDER:
        path = folder / name
        if not path.exists():
            out[name] = 'missing'
        elif path.stat().st_size != FILES[name]['size']:
            out[name] = 'size_mismatch'
        else:
            out[name] = 'verified' if sha256_of(path).hexdigest() == FILES[name]['sha256'] else 'sha256_mismatch'
    return out


def _unsafe(name: str) -> list[str]:
    reasons = []
    posix = name.replace('\\', '/')
    if posix.startswith('/') or posix.startswith('//'):
        reasons.append('absolute')
    if len(posix) > 1 and posix[1] == ':':
        reasons.append('drive_letter')
    if '..' in PurePosixPath(posix).parts:
        reasons.append('parent_reference')
    if '\\' in name:
        reasons.append('backslash')
    return reasons


def inspect_zip(path: Path) -> dict:
    """Central directory only: names, sizes, compression and mode bits. No member is opened."""
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        comment = len(archive.comment)
    by_ext, compression, flagged = {}, Counter(), {'pickle': [], 'executable_or_archive': [], 'unsafe_path': [],
                                                     'symlink': [], 'encrypted': [], 'directories': 0}
    names = Counter(info.filename for info in infos)
    total = 0
    for info in infos:
        if info.is_dir():
            flagged['directories'] += 1
            continue
        name = info.filename
        ext = PurePosixPath(name.replace('\\', '/')).suffix.lower() or '(none)'
        stats = by_ext.setdefault(ext, {'count': 0, 'uncompressed_bytes': 0, 'compressed_bytes': 0})
        stats['count'] += 1
        stats['uncompressed_bytes'] += info.file_size
        stats['compressed_bytes'] += info.compress_size
        total += info.file_size
        compression[{0: 'stored', 8: 'deflate', 12: 'bzip2', 14: 'lzma', 93: 'zstd'}.get(info.compress_type,
                                                                                        str(info.compress_type))] += 1
        if ext in PICKLE_EXTENSIONS:
            flagged['pickle'].append(name)
        if ext in EXECUTABLE_EXTENSIONS:
            flagged['executable_or_archive'].append(name)
        reasons = _unsafe(name)
        if reasons:
            flagged['unsafe_path'].append({'name': name, 'reasons': reasons})
        mode = info.external_attr >> 16
        if mode and stat.S_ISLNK(mode):
            flagged['symlink'].append(name)
        if info.flag_bits & 0x1:
            flagged['encrypted'].append(name)
    return {
        'file': path.name,
        'members': len(infos),
        'files': len(infos) - flagged['directories'],
        'directories': flagged['directories'],
        'duplicate_names': sorted(n for n, c in names.items() if c > 1),
        'first_10_members': [info.filename for info in infos[:10]],
        'extensions': dict(sorted(by_ext.items())),
        'compression_methods': dict(sorted(compression.items())),
        'total_uncompressed_bytes': total,
        'total_uncompressed_gib': round(total / GIB, 3),
        'pickle_members': flagged['pickle'],
        'npy_note': '.npy and .npz are listed as pickle risks; their dtype is not checked because that would '
                    'mean reading member data.',
        'executable_or_archive_members': flagged['executable_or_archive'],
        'unsafe_path_members': flagged['unsafe_path'],
        'symlink_members': flagged['symlink'],
        'encrypted_members': flagged['encrypted'],
        'archive_comment_bytes': comment,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--file', choices=ORDER, help='download, resume and verify this one file')
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--inspect', action='store_true', help='central-directory report of downloaded zips')
    args = parser.parse_args(argv)
    folder = destination()
    folder.mkdir(parents=True, exist_ok=True)
    try:
        if args.file:
            import requests
            with requests.Session() as session:
                result = download(args.file, folder, session)
            write_lock({args.file: result}, folder)
            print(json.dumps({'file': args.file, 'status': result['status']}))
            return 0
        if args.verify_only:
            status = verify_all(folder)
            print(json.dumps(status))
            return 0 if all(v == 'verified' for v in status.values()) else 1
        if args.inspect:
            reports = [inspect_zip(folder / name) for name in ORDER if (folder / name).exists()]
            document = {'description': 'Central-directory inspection of the pinned EMBER2024 PE train zips '
                                       '(member names, sizes and counts only). No member was opened, extracted, '
                                       'decompressed or loaded.',
                        'revision': REVISION, 'inspected_on': date.today().isoformat(), 'zips': reports}
            REPORT.parent.mkdir(parents=True, exist_ok=True)
            REPORT.write_text(json.dumps(document, indent=2, ensure_ascii=False) + '\n', encoding='utf-8',
                              newline='\n')
            print(json.dumps({'report': REPORT.relative_to(ROOT).as_posix(), 'zips': [r['file'] for r in reports]}))
            return 0
    except FetchStop as exc:
        print(json.dumps({'status': 'stopped', 'reason': str(exc)}), flush=True)
        return 2
    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
