"""Vectorize the three pinned EMBER2024 PE train zips into float32 memory-mapped files
(design malware-engine-v1 §3.7, §9 step 7 phase 2).

Run manually; the app never runs this. No network is used: sockets are blocked in every process.
  python data/scripts/vectorize_ember2024.py                 verify, plan, vectorize, resume, summarize
  python data/scripts/vectorize_ember2024.py --workers 8     cap the worker processes

- The zips are checked against data/ember2024-lock.json (size and SHA-256) first; any difference stops.
- Each zip must hold exactly the 52 weekly `<start>_<end>_<Type>_train.jsonl` members that the committed
  central-directory report lists (count, first names, total size). Anything else stops the run.
- Members are streamed line by line from the zip in memory; nothing is extracted to disk. Each line is
  parsed with json only; no other deserializer is ever used.
- Each record becomes the 2568-dim float32 vector of app.engines.malware.features.vector_from_raw, the
  same module object and extractor the runtime uses, written to vectors/<Type>.f32 (C order, shape in
  vectors/<Type>.f32.json). Row i of the vectors is row i of vectors/<Type>_meta.parquet (sha256, label,
  label_raw, file_type, first_submission_date, member, line, status). A line that cannot be parsed or
  vectorized keeps its row: the vector is NaN and `status` holds the reason code. Nothing is dropped.
- No training, splitting, label filtering or scoring happens here (step 8 decides weeks and splits).
- Repeated sha256 values are counted (per type and week, with whether each repeat's label and vector
  equal the first row's) but never removed; step 8 deduplicates before numbering weeks or splitting.
- Work is resumable per member: a member is done only when its vectors are flushed and its part files
  and counts are written; an interrupted member is redone from its first row.
- Workers leave at least 4 cores and 8 GiB of RAM free; new members are not started while less than
  8 GiB is available. At least 30 GiB of disk stays free.
- The committed summary (evaluation/reports/2026-11-malware-v1/ember2024_vectorize_summary.json) holds
  counts only: no row-level data, no hashes, no sample names.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import multiprocessing
import os
import re
import shutil
import stat
import sys
import time
import zipfile
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / 'backend'
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

LOCK = ROOT / 'data' / 'ember2024-lock.json'
INSPECTION = ROOT / 'evaluation' / 'reports' / '2026-11-malware-v1' / 'ember2024_zip_inspection.json'
SUMMARY = ROOT / 'evaluation' / 'reports' / '2026-11-malware-v1' / 'ember2024_vectorize_summary.json'
DEFAULT_DESTINATION = ROOT / 'data' / 'external' / 'ember2024'
FEATURES_FILE = BACKEND / 'app' / 'engines' / 'malware' / 'features.py'
PLAN_VERSION = 1
TYPES = {'Win32': 'Win32_train.zip', 'Win64': 'Win64_train.zip', 'Dot_Net': 'Dot_Net_train.zip'}
WEEKS_PER_ZIP = 52
MEMBER_RE = re.compile(r'^(\d{4}-\d{2}-\d{2})_(\d{4}-\d{2}-\d{2})_(Win32|Win64|Dot_Net)_train\.jsonl$')
EXPECTED_FIELDS = frozenset({
    'md5', 'sha1', 'sha256', 'tlsh', 'first_submission_date', 'last_analysis_date', 'detection_ratio', 'label',
    'file_type', 'family', 'family_confidence', 'behavior', 'file_property', 'packer', 'exploit', 'group',
    'histogram', 'byteentropy', 'strings', 'general', 'header', 'section', 'imports', 'exports',
    'datadirectories', 'richheader', 'authenticode', 'pefilewarnings', 'week_id', 'caps', 'ttps', 'mbc'})
GIB = 1024 ** 3
MIN_FREE_DISK = 30 * GIB
MIN_FREE_RAM = 8 * GIB
RESERVED_CORES = 4
RAM_PER_WORKER = GIB  # conservative: thrember import, one decompressor and one json line per worker
BLOCK_ROWS = 512
STATUS_OK = 'ok'


class VectorizeStop(RuntimeError):
    """A fixed reason code; the run stops and nothing is worked around."""


# ---------------------------------------------------------------- environment and checks

def destination() -> Path:
    value = os.getenv('ETIS_EMBER_DIR', '').strip()
    if not value:
        env = ROOT / '.env'
        if env.is_file():
            from dotenv import dotenv_values
            value = (dotenv_values(env).get('ETIS_EMBER_DIR') or '').strip()
    return Path(value) if value else DEFAULT_DESTINATION


def block_network() -> None:
    """No process of this script may open a connection (the same guard as the feature worker)."""
    import socket

    def blocked(*args, **kwargs):
        raise OSError('network_blocked_in_vectorizer')
    for name in ('connect', 'connect_ex', 'sendto'):
        setattr(socket.socket, name, blocked)
    socket.create_connection = blocked
    socket.getaddrinfo = blocked


def load_features():
    """The runtime module object; refuses if it is another copy or thrember is not the pinned one."""
    from app.engines.malware import features
    thrember_features = sys.modules.get('thrember.features')
    if (sys.modules.get('app.engines.malware.features') is not features or thrember_features is None
            or features._PEFeatureExtractor is not thrember_features.PEFeatureExtractor
            or type(features.EXTRACTOR) is not thrember_features.PEFeatureExtractor
            or Path(features.__file__).resolve() != FEATURES_FILE.resolve()
            or features.EXTRACTOR.dim != features.FEATURE_DIM):
        raise VectorizeStop('feature_module_mismatch')
    return features


def available_memory() -> int | None:
    if sys.platform == 'win32':
        class MemoryStatus(ctypes.Structure):
            _fields_ = [('dwLength', ctypes.c_ulong), ('dwMemoryLoad', ctypes.c_ulong),
                        ('ullTotalPhys', ctypes.c_ulonglong), ('ullAvailPhys', ctypes.c_ulonglong),
                        ('ullTotalPageFile', ctypes.c_ulonglong), ('ullAvailPageFile', ctypes.c_ulonglong),
                        ('ullTotalVirtual', ctypes.c_ulonglong), ('ullAvailVirtual', ctypes.c_ulonglong),
                        ('ullAvailExtendedVirtual', ctypes.c_ulonglong)]
        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullAvailPhys)
        return None
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def worker_count(requested: int | None = None) -> int:
    by_cpu = max(1, (os.cpu_count() or 1) - RESERVED_CORES)
    memory = available_memory()
    by_ram = by_cpu if memory is None else max(1, (memory - MIN_FREE_RAM) // RAM_PER_WORKER)
    count = min(by_cpu, by_ram)
    return max(1, min(count, requested)) if requested else count


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        while chunk := handle.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_zips(folder: Path, lock: dict) -> dict:
    """Every zip must exist with the lock's size and SHA-256; returns {type: path}."""
    entries = {entry['file']: entry for entry in lock.get('files', [])}
    paths = {}
    for kind, name in TYPES.items():
        entry = entries.get(name)
        if entry is None or not entry.get('verified'):
            raise VectorizeStop(f'not_in_lock:{name}')
        path = folder / name
        if not path.is_file():
            raise VectorizeStop(f'zip_missing:{name}')
        if path.stat().st_size != entry['size']:
            raise VectorizeStop(f'size_mismatch:{name}')
        if sha256_of(path) != entry['sha256']:
            raise VectorizeStop(f'sha256_mismatch:{name}')
        paths[kind] = path
    return paths


def check_members(path: Path, kind: str, inspection: dict) -> list[str]:
    """The 52 weekly jsonl members the inspection report lists, sorted; anything else stops."""
    expected = inspection.get(TYPES[kind])
    if expected is None:
        raise VectorizeStop(f'not_inspected:{TYPES[kind]}')
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
    names = [info.filename for info in infos]
    for info in infos:
        mode = info.external_attr >> 16
        if info.is_dir() or stat.S_ISLNK(mode):
            raise VectorizeStop(f'unexpected_member:{TYPES[kind]}')
        if info.flag_bits & 0x1:
            raise VectorizeStop(f'encrypted_member:{TYPES[kind]}')
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise VectorizeStop(f'unexpected_compression:{TYPES[kind]}')
        match = MEMBER_RE.match(info.filename)
        if not match or match.group(3) != kind:
            raise VectorizeStop(f'unexpected_member:{TYPES[kind]}')
    if len(names) != len(set(names)):
        raise VectorizeStop(f'duplicate_member:{TYPES[kind]}')
    if len(names) != WEEKS_PER_ZIP or len(names) != expected['members']:
        raise VectorizeStop(f'member_count_mismatch:{TYPES[kind]}')
    if names[:len(expected['first_10_members'])] != expected['first_10_members']:
        raise VectorizeStop(f'member_names_mismatch:{TYPES[kind]}')
    if sum(info.file_size for info in infos) != expected['total_uncompressed_bytes']:
        raise VectorizeStop(f'uncompressed_size_mismatch:{TYPES[kind]}')
    return sorted(names)


def week_of(member: str) -> str:
    match = MEMBER_RE.match(member)
    return f'{match.group(1)}_{match.group(2)}'


def free_disk(folder: Path) -> int:
    return shutil.disk_usage(folder).free


def log(message: str) -> None:
    print(time.strftime('%H:%M:%S'), message, flush=True)


# ---------------------------------------------------------------- worker side

def _init_worker() -> None:
    block_network()
    load_features()


def count_lines(zip_path: str, member: str) -> tuple[str, int]:
    rows = 0
    with zipfile.ZipFile(zip_path) as archive, archive.open(member) as stream:
        for _ in stream:
            rows += 1
    return member, rows


def _label_key(value) -> str:
    if value is None or isinstance(value, (bool, int, str)):
        return json.dumps(value)[:64]
    if isinstance(value, float):
        return json.dumps(value) if math.isfinite(value) else 'float:nonfinite'
    return f'type:{type(value).__name__}'


def vectorize_member(task: dict) -> dict:
    """Vectorize one member into its row range; writes the part table and the done record last."""
    import numpy as np
    import polars as pl
    features = load_features()
    dim = features.FEATURE_DIM
    kind, member, offset, rows = task['kind'], task['member'], task['offset'], task['rows']
    vectors = (np.memmap(task['vectors'], dtype=np.float32, mode='r+', offset=offset * dim * 4, shape=(rows, dim))
               if rows else np.empty((0, dim), dtype=np.float32))
    block = np.empty((BLOCK_ROWS, dim), dtype=np.float32)
    meta = {'row': [], 'line': [], 'sha256': [], 'label': [], 'label_raw': [], 'file_type': [],
            'first_submission_date': [], 'status': []}
    status_counts, label_counts, file_types = Counter(), Counter(), Counter()
    missing, extra = Counter(), Counter()
    nonfinite = 0
    line_no = start = 0
    with zipfile.ZipFile(task['zip']) as archive, archive.open(member) as stream:
        for raw_line in stream:
            if line_no >= rows:
                raise VectorizeStop('row_count_changed')
            status, record = STATUS_OK, None
            if not raw_line.strip():
                status = 'empty_line'
            else:
                try:
                    record = json.loads(raw_line)
                except (ValueError, RecursionError):
                    status = 'json_error'
                else:
                    if not isinstance(record, dict):
                        status, record = 'not_object', None
            vector = None
            if record is not None:
                keys = set(record)
                missing.update(EXPECTED_FIELDS - keys)
                extra.update(str(key)[:64] for key in keys - EXPECTED_FIELDS)
                try:
                    vector = features.vector_from_raw(record)
                except Exception as exc:
                    status = f'vectorize_error:{type(exc).__name__}'
                else:
                    if not np.isfinite(vector).all():
                        nonfinite += 1
            if vector is None:
                block[line_no - start] = np.nan
            else:
                block[line_no - start] = vector
            parsed = record is not None
            record = record if parsed else {}
            label = record.get('label')
            file_type = record.get('file_type')
            if parsed:
                label_counts[_label_key(label) if 'label' in record else 'missing'] += 1
                file_types[_label_key(file_type) if 'file_type' in record else 'missing'] += 1
            else:
                label_counts['unparsed'] += 1
                file_types['unparsed'] += 1
            date_value = record.get('first_submission_date')
            sha = record.get('sha256')
            meta['row'].append(offset + line_no)
            meta['line'].append(line_no)
            meta['sha256'].append(sha if isinstance(sha, str) else None)
            meta['label'].append(label if isinstance(label, int) and not isinstance(label, bool) else None)
            meta['label_raw'].append(_label_key(label) if 'label' in record else None)
            meta['file_type'].append(file_type if isinstance(file_type, str) else None)
            meta['first_submission_date'].append(
                date_value if isinstance(date_value, int) and not isinstance(date_value, bool) else None)
            meta['status'].append(status)
            status_counts[status] += 1
            line_no += 1
            if line_no - start == BLOCK_ROWS:
                vectors[start:line_no] = block
                start = line_no
    if line_no != rows:
        raise VectorizeStop('row_count_changed')
    if line_no > start:
        vectors[start:line_no] = block[:line_no - start]
    if isinstance(vectors, np.memmap):
        vectors.flush()
    del vectors
    table = pl.DataFrame(meta, schema={'row': pl.Int64, 'line': pl.Int64, 'sha256': pl.Utf8, 'label': pl.Int64,
                                       'label_raw': pl.Utf8, 'file_type': pl.Utf8,
                                       'first_submission_date': pl.Int64, 'status': pl.Utf8})
    table = table.with_columns(pl.lit(member).alias('member'))
    part = Path(task['part'])
    tmp = part.with_suffix('.parquet.tmp')
    table.write_parquet(tmp)
    os.replace(tmp, part)
    done = {'kind': kind, 'member': member, 'week': week_of(member), 'rows': rows, 'offset': offset,
            'status': dict(status_counts), 'labels': dict(label_counts), 'file_types': dict(file_types),
            'missing_fields': dict(missing), 'extra_fields': dict(extra), 'nonfinite_rows': nonfinite}
    done_path = Path(task['done'])
    tmp = done_path.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(done, sort_keys=True), encoding='utf-8')
    os.replace(tmp, done_path)
    return done


# ---------------------------------------------------------------- main side

def _map(function, items, workers: int, *, pause_check=None):
    """Yields results; workers=0 runs in this process. pause_check() -> reason stops new submissions."""
    items = list(items)
    if workers == 0:
        for item in items:
            if pause_check and (reason := pause_check()):
                raise VectorizeStop(reason)
            yield function(item)
        return
    context = multiprocessing.get_context('spawn')
    with context.Pool(workers, initializer=_init_worker) as pool:
        pending, queue = [], list(items)
        stop_reason = None
        while queue or pending:
            while queue and len(pending) < workers and stop_reason is None:
                if pause_check and (reason := pause_check()):
                    stop_reason = reason
                    break
                pending.append(pool.apply_async(function, (queue.pop(0),)))
            if not pending:
                break
            ready = next((p for p in pending if p.ready()), None)
            if ready is None:
                pending[0].wait(1)
                continue
            pending.remove(ready)
            yield ready.get()
        pool.close()
        pool.join()
        if stop_reason:
            raise VectorizeStop(stop_reason)


def _count_task(args):
    return count_lines(*args)


def make_plan(paths: dict, members: dict, lock: dict, workers: int, out: Path) -> dict:
    plan_path = out / 'plan.json'
    zips = {kind: {'file': TYPES[kind], 'sha256': next(e['sha256'] for e in lock['files'] if e['file'] == TYPES[kind])}
            for kind in TYPES}
    if plan_path.is_file():
        plan = json.loads(plan_path.read_text(encoding='utf-8'))
        if plan.get('version') != PLAN_VERSION or plan.get('zips') != zips or any(
                [m['member'] for m in plan['types'][kind]['members']] != members[kind] for kind in TYPES):
            raise VectorizeStop('existing_plan_mismatch')
        return plan
    log('counting rows per member (pass 1)')
    tasks = [(str(paths[kind]), member) for kind in TYPES for member in members[kind]]
    counts = dict(_map(_count_task, tasks, workers))
    plan = {'version': PLAN_VERSION, 'dim': None, 'zips': zips, 'types': {}}
    for kind in TYPES:
        offset, entries = 0, []
        for member in members[kind]:
            entries.append({'member': member, 'rows': counts[member], 'offset': offset})
            offset += counts[member]
        plan['types'][kind] = {'rows': offset, 'members': entries}
    tmp = plan_path.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(plan, indent=1), encoding='utf-8')
    os.replace(tmp, plan_path)
    return plan


def allocate(plan: dict, out: Path, dim: int) -> dict:
    import numpy as np
    needed = 0
    files = {}
    for kind in TYPES:
        rows = plan['types'][kind]['rows']
        path = out / f'{kind}.f32'
        size = rows * dim * 4
        files[kind] = path
        if path.exists():
            if path.stat().st_size != size:
                raise VectorizeStop(f'vector_file_size_mismatch:{kind}')
        else:
            needed += size
    if free_disk(out) - needed < MIN_FREE_DISK:
        raise VectorizeStop('insufficient_free_space')
    for kind, path in files.items():
        rows = plan['types'][kind]['rows']
        if not path.exists() and rows:
            np.memmap(path, dtype=np.float32, mode='w+', shape=(rows, dim)).flush()
        elif not path.exists():
            path.write_bytes(b'')
        header = {'dtype': 'float32', 'order': 'C', 'shape': [rows, dim], 'meta': f'{kind}_meta.parquet'}
        (out / f'{kind}.f32.json').write_text(json.dumps(header), encoding='utf-8')
    return files


def run(folder: Path, lock: dict, inspection: dict, workers: int) -> dict:
    block_network()
    features = load_features()
    dim = features.FEATURE_DIM
    paths = verify_zips(folder, lock)
    log('zips verified against the lock')
    members = {kind: check_members(paths[kind], kind, inspection) for kind in TYPES}
    out = folder / 'vectors'
    (out / 'parts').mkdir(parents=True, exist_ok=True)
    plan = make_plan(paths, members, lock, workers, out)
    files = allocate(plan, out, dim)
    tasks = []
    for kind in TYPES:
        for entry in plan['types'][kind]['members']:
            week = week_of(entry['member'])
            done = out / 'parts' / f'{kind}_{week}.done.json'
            if done.is_file():
                continue
            tasks.append({'kind': kind, 'member': entry['member'], 'zip': str(paths[kind]), 'offset': entry['offset'],
                          'rows': entry['rows'], 'vectors': str(files[kind]),
                          'part': str(out / 'parts' / f'{kind}_{week}.parquet'), 'done': str(done)})
    tasks.sort(key=lambda t: -t['rows'])
    total = sum(plan['types'][k]['rows'] for k in TYPES)
    left = sum(t['rows'] for t in tasks)
    log(f'{len(tasks)} members to vectorize ({left} of {total} rows) with {workers} workers')

    def pause_check():
        memory = available_memory()
        if memory is not None and memory < MIN_FREE_RAM:
            return 'low_memory_paused'
        if free_disk(out) < MIN_FREE_DISK:
            return 'insufficient_free_space'
        return None
    finished, finished_rows = 0, 0
    for done in _map(vectorize_member, tasks, workers, pause_check=pause_check):
        finished += 1
        finished_rows += done['rows']
        if finished % 8 == 0 or finished == len(tasks):
            log(f'{finished}/{len(tasks)} members, {finished_rows}/{left} rows')
    return finalize(plan, out, dim)


def finalize(plan: dict, out: Path, dim: int) -> dict:
    import polars as pl
    summary_types = {}
    for kind in TYPES:
        entries = plan['types'][kind]['members']
        dones, parts = [], []
        for entry in entries:
            week = week_of(entry['member'])
            done_path = out / 'parts' / f'{kind}_{week}.done.json'
            if not done_path.is_file():
                raise VectorizeStop(f'member_not_done:{kind}')
            dones.append(json.loads(done_path.read_text(encoding='utf-8')))
            parts.append(out / 'parts' / f'{kind}_{week}.parquet')
        if parts:
            table = pl.concat([pl.read_parquet(p) for p in parts])
            if table['row'].to_list() != list(range(plan['types'][kind]['rows'])):
                raise VectorizeStop(f'metadata_rows_mismatch:{kind}')
            tmp = out / f'{kind}_meta.parquet.tmp'
            table.write_parquet(tmp)
            os.replace(tmp, out / f'{kind}_meta.parquet')
        summary_types[kind] = _summarize(kind, plan['types'][kind]['rows'], dones, dim)
        log(f'duplicate counts: {kind}')
        summary_types[kind]['duplicates'] = duplicate_counts(out / f'{kind}_meta.parquet', out / f'{kind}.f32',
                                                             plan['types'][kind]['rows'], dim)
    return {
        'description': 'Counts from vectorizing the pinned EMBER2024 PE train zips (design malware-engine-v1 '
                       '§9 step 7 phase 2). Counts only: no row-level data, hashes or sample names. Vectors and '
                       'metadata stay local under the ignored data/external/ember2024/vectors/.',
        'script': 'data/scripts/vectorize_ember2024.py',
        'lock': 'data/ember2024-lock.json',
        'generated_on': date.today().isoformat(),
        'feature_extractor': {'module': 'app.engines.malware.features.vector_from_raw',
                              'thrember_version': _features_attr('THREMBER_VERSION'),
                              'thrember_commit': _features_attr('THREMBER_COMMIT'),
                              'same_module_object_checked': True},
        'vector_dimension': dim,
        'vector_dtype': 'float32',
        'not_done_here': 'No training, split, label filter or score. Week numbering and splits are step 8.',
        'failed_rows_policy': 'A row that fails keeps its index; its vector is NaN and its status is the reason code.',
        'duplicates_policy': 'Counted, never removed here. Step 8 deduplicates by sha256 before numbering weeks '
                             'or splitting: it keeps the first row of each sha256 and stops if any duplicate '
                             'pair has a different label or vector (design §4.2 note of 26 November 2026).',
        'total_rows': sum(t['rows'] for t in summary_types.values()),
        'sha256_in_more_than_one_type': cross_type_overlap(out),
        'types': summary_types,
    }


def duplicate_counts(meta_path: Path, vectors_path: Path, rows: int, dim: int) -> dict:
    """Counts only: repeats of sha256 within one type, per type and per week, and whether each repeat's
    label and vector equal those of the first row with that sha256. Nothing is removed or rewritten."""
    import numpy as np
    import polars as pl
    meta = pl.read_parquet(meta_path, columns=['row', 'sha256', 'label_raw', 'member'])
    valid = meta.filter(pl.col('sha256').is_not_null())
    groups = valid.group_by('sha256').agg(pl.col('row').min().alias('first_row'), pl.len().alias('n'),
                                          pl.col('member').n_unique().alias('weeks'))
    pairs = (valid.join(groups.select('sha256', 'first_row'), on='sha256')
             .filter(pl.col('row') != pl.col('first_row'))
             .join(meta.select(pl.col('row').alias('first_row'), pl.col('label_raw').alias('first_label')),
                   on='first_row')
             .sort('row'))
    label_differs = int(pairs.select(pl.col('label_raw').ne_missing(pl.col('first_label')).sum()).item() or 0)
    vector_differs = 0
    if pairs.height and rows:
        vectors = np.memmap(vectors_path, dtype=np.float32, mode='r', shape=(rows, dim))
        later, first = pairs['row'].to_numpy(), pairs['first_row'].to_numpy()
        for start in range(0, len(later), 4096):
            a = np.asarray(vectors[later[start:start + 4096]]).view(np.uint32)
            b = np.asarray(vectors[first[start:start + 4096]]).view(np.uint32)
            vector_differs += int((a != b).any(axis=1).sum())
        del vectors
    weeks = (valid.group_by('member')
             .agg(pl.len().alias('rows'), pl.col('sha256').n_unique().alias('distinct')).sort('member'))
    return {
        'rows_without_sha256': meta.height - valid.height,
        'distinct_sha256': groups.height,
        'duplicate_rows': valid.height - groups.height,
        'longest_repeat': int(groups['n'].max() or 0),
        'repeat_count_distribution': {str(k): v for k, v in
                                      groups.group_by('n').len().sort('n').iter_rows()},
        'sha256_in_more_than_one_week': int(groups.filter(pl.col('weeks') > 1).height),
        'duplicate_pairs_checked': pairs.height,
        'duplicate_pairs_with_different_label': label_differs,
        'duplicate_pairs_with_different_vector': vector_differs,
        'weeks': {week_of(m): {'distinct_sha256': d, 'duplicate_rows': r - d}
                  for m, r, d in weeks.iter_rows()},
    }


def cross_type_overlap(out: Path) -> int:
    """sha256 values that occur in more than one type's table (count only)."""
    import polars as pl
    frames = [pl.read_parquet(out / f'{kind}_meta.parquet', columns=['sha256']).drop_nulls().unique()
              for kind in TYPES if (out / f'{kind}_meta.parquet').is_file()]
    if not frames:
        return 0
    return int(pl.concat(frames).group_by('sha256').len().filter(pl.col('len') > 1).height)


def _features_attr(name: str):
    return getattr(sys.modules['app.engines.malware.features'], name)


def _summarize(kind: str, rows: int, dones: list[dict], dim: int) -> dict:
    status, labels, file_types, missing, extra = Counter(), Counter(), Counter(), Counter(), Counter()
    weeks, nonfinite = {}, 0
    for done in dones:
        status.update(done['status'])
        labels.update(done['labels'])
        file_types.update(done['file_types'])
        missing.update(done['missing_fields'])
        extra.update(done['extra_fields'])
        nonfinite += done['nonfinite_rows']
        weeks[done['week']] = {'rows': done['rows'], 'ok': done['status'].get(STATUS_OK, 0),
                               'failed': done['rows'] - done['status'].get(STATUS_OK, 0),
                               'labels': dict(sorted(done['labels'].items()))}
    if sum(status.values()) != rows or sum(w['rows'] for w in weeks.values()) != rows:
        raise VectorizeStop(f'count_mismatch:{kind}')
    return {
        'zip': TYPES[kind], 'rows': rows, 'vectors_shape': [rows, dim], 'weekly_members': len(dones),
        'ok_rows': status.get(STATUS_OK, 0),
        'failed_rows': {k: v for k, v in sorted(status.items()) if k != STATUS_OK},
        'label_values': dict(sorted(labels.items())),
        'file_type_values': dict(sorted(file_types.items())),
        'missing_fields': dict(sorted(missing.items())),
        'extra_fields': dict(sorted(extra.items())),
        'rows_with_nonfinite_vector_values': nonfinite,
        'weeks': dict(sorted(weeks.items())),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--workers', type=int, default=None, help='upper bound on worker processes')
    args = parser.parse_args(argv)
    try:
        workers = worker_count(args.workers)
        lock = json.loads(LOCK.read_text(encoding='utf-8'))
        inspection = {z['file']: z for z in json.loads(INSPECTION.read_text(encoding='utf-8'))['zips']}
        summary = run(destination(), lock, inspection, workers)
    except VectorizeStop as stop:
        print(json.dumps({'stopped': str(stop)}))
        return 2
    except (zipfile.BadZipFile, OSError) as exc:
        print(json.dumps({'stopped': f'read_error:{type(exc).__name__}'}))
        return 2
    tmp = SUMMARY.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(summary, indent=1) + '\n', encoding='utf-8')
    os.replace(tmp, SUMMARY)
    log(f'summary written: {SUMMARY.relative_to(ROOT).as_posix()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
