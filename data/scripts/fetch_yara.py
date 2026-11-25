"""Download pinned signature-base YARA rule text, verify it and take a licence census (design malware-engine-v1 §3.3, §3.7, §9 step 1).

Run manually: `python data/scripts/fetch_yara.py` (download missing files, then verify) or
`--verify-only` (download nothing). The app never runs this. The pin lives in
data/yara-lock.json: the files under `yara/` of one signature-base commit (`.yar`, `.yara`
and `yara/external-variable-rules.txt`), fetched one by one from that commit. Each file's
size, SHA-256 and git blob SHA-1 must match the lock. Downloads are held in memory and
written via a `.part` file; a file that is missing or changed right after it was written
(for example removed by antivirus) stops the run with its name, and nothing works around it.
Rule text is never modified, compiled or executed. Every run re-verifies all files, the tree
hash and the licence census (counts of rules per stated licence), which must equal the lock.

YARA-Forge was dropped for v1 (see `dropped_sources` in the lock and the design §3.3).

`--pin COMMIT` (used once to create the lock) reads the commit tree from the GitHub API,
downloads and measures the files and writes data/yara-lock.json. It sends no ETIS data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'data' / 'yara-lock.json'
DESTINATION = 'data/external/yara/'
USER_AGENT = 'ETIS-Local-Research/0.2'
SB_REPO = 'Neo23x0/signature-base'
SB_RAW = 'https://raw.githubusercontent.com/Neo23x0/signature-base/'
SB_LIST = 'yara/external-variable-rules.txt'
RULE_SUFFIXES = ('.yar', '.yara')
MAX_FILE_BYTES = 20_000_000
HEX40, HEX64 = re.compile(r'^[0-9a-f]{40}$'), re.compile(r'^[0-9a-f]{64}$')
TREE_DEFINITION = ("SHA-256 of the sorted lines 'relative/path<TAB>sha256' of every pinned file, each line "
                   "ending in a newline")


class RemovedAfterWrite(RuntimeError):
    """A file vanished or changed right after it was written (for example quarantined by antivirus)."""

    def __init__(self, paths):
        self.paths = sorted(paths)
        super().__init__('removed_after_write:' + ','.join(self.paths))


# ---------------------------------------------------------------- helpers

def long_path(path: Path) -> Path:
    """Windows extended-length form, as in fetch_sigma.py."""
    text = str(Path(path).resolve())
    if os.name == 'nt' and not text.startswith('\\\\?\\'):
        text = '\\\\?\\' + text
    return Path(text)


def sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def git_blob_sha1(body: bytes) -> str:
    return hashlib.sha1(b'blob %d\0' % len(body) + body).hexdigest()


def tree_sha256(entries) -> str:
    """entries: iterable of (relative path, sha256)."""
    lines = sorted(f'{path}\t{digest}' for path, digest in entries)
    return hashlib.sha256(('\n'.join(lines) + '\n').encode('utf-8')).hexdigest()


def safe_relative(name: str) -> PurePosixPath:
    if '\\' in name or name.startswith('/') or ':' in name:
        raise ValueError('unsafe_path')
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ('..', '.', '') for part in path.parts):
        raise ValueError('unsafe_path')
    return path


def is_kept(path: str) -> bool:
    return path.startswith('yara/') and (path.endswith(RULE_SUFFIXES) or path == SB_LIST)


def read_file(path: Path) -> bytes | None:
    try:
        return long_path(path).read_bytes()
    except OSError:
        return None


def file_matches(path: Path, entry: dict) -> bool:
    body = read_file(path)
    return body is not None and len(body) == entry['size'] and sha256_bytes(body) == entry['sha256']


def write_checked(target: Path, body: bytes) -> bool:
    """Write via a .part file; True only if the file is still there and unchanged afterwards."""
    target = long_path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + '.part')
    try:
        partial.write_bytes(body)
        os.replace(partial, target)
    except OSError:
        return False
    finally:
        try:
            if partial.exists():
                partial.unlink()
        except OSError:
            pass
    again = read_file(target)
    return again is not None and sha256_bytes(again) == sha256_bytes(body)


def http_get(session, url: str, limit: int = MAX_FILE_BYTES) -> bytes:
    body = bytearray()
    with session.get(url, headers={'User-Agent': USER_AGENT}, timeout=(10, 120), stream=True) as response:
        response.raise_for_status()
        for chunk in response.iter_content(1 << 20):
            body.extend(chunk)
            if len(body) > limit:
                raise ValueError('download_too_large')
    return bytes(body)


# ---------------------------------------------------------------- lock

def load_lock(path: Path = LOCK) -> dict:
    lock = json.loads(Path(path).read_text(encoding='utf-8'))
    if lock['destination'] != DESTINATION:
        raise ValueError('unexpected_pinned_location')
    source = lock['source']
    if source['repository'] != SB_REPO or not HEX40.match(source['commit']):
        raise ValueError('unexpected_pinned_location')
    if source['url_prefix'] != f"{SB_RAW}{source['commit']}/":
        raise ValueError('unexpected_pinned_location')
    safe_relative(source['directory'])
    for entry in source['files']:
        safe_relative(entry['path'])
        if not is_kept(entry['path']):
            raise ValueError('unexpected_pinned_location')
        if not HEX64.match(entry['sha256']) or not HEX40.match(entry['git_blob_sha1']):
            raise ValueError('invalid_pinned_hash')
    if not HEX64.match(lock['rule_tree_sha256']):
        raise ValueError('invalid_pinned_hash')
    return lock


# ---------------------------------------------------------------- YARA meta parser (counts only)

RULE_HEADER = re.compile(r'(?<![A-Za-z0-9_])((?:(?:private|global)\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*'
                         r'(?::\s*[A-Za-z0-9_\s]*?)?\{')
SECTION = re.compile(r'(?<![A-Za-z0-9_])(meta|strings|condition)\s*:')
META_PAIR = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("(?:[^"\\\n]|\\.)*"|-?\d+|true|false)')


def _skeleton(text: str) -> tuple[str, str, list[tuple[int, int]]]:
    """Return (without comments, skeleton, comment spans).

    The skeleton also blanks string and regex contents. Comment spans are (start, end) offsets,
    end exclusive, one per `//` line or `/* */` block. YARA divides with a backslash, so a single
    '/' outside strings and comments starts a regex.
    """
    clean, skeleton, spans = list(text), list(text), []
    i, n, state, start = 0, len(text), 'code', 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if state == 'code':
            if c == '"':
                state = 'string'
            elif c == '/' and nxt == '/':
                state, start = 'line', i
                continue
            elif c == '/' and nxt == '*':
                state, start = 'block', i
                clean[i] = skeleton[i] = clean[i + 1] = skeleton[i + 1] = ' '
                i += 2
                continue
            elif c == '/':
                state = 'regex'
            i += 1
        elif state in ('string', 'regex'):
            closing = '"' if state == 'string' else '/'
            if c == '\\' and i + 1 < n:
                if text[i + 1] != '\n':
                    skeleton[i] = skeleton[i + 1] = ' '
                i += 2
                continue
            if c == closing or c == '\n':
                state = 'code'
            elif c != '\n':
                skeleton[i] = ' '
            i += 1
        elif state == 'line':
            if c == '\n':
                state = 'code'
                spans.append((start, i))
            else:
                clean[i] = skeleton[i] = ' '
            i += 1
        else:  # block comment
            if c == '*' and nxt == '/':
                clean[i] = skeleton[i] = clean[i + 1] = skeleton[i + 1] = ' '
                state = 'code'
                spans.append((start, i + 2))
                i += 2
                continue
            if c != '\n':
                clean[i] = skeleton[i] = ' '
            i += 1
    if state in ('line', 'block'):
        spans.append((start, n))
    return ''.join(clean), ''.join(skeleton), spans


def parse_rules(text: str) -> list[dict]:
    """Rule names, offsets and meta key/value pairs; nothing is compiled or evaluated."""
    clean, skeleton, _ = _skeleton(text)
    rules, position = [], 0
    while True:
        header = RULE_HEADER.search(skeleton, position)
        if not header:
            break
        depth, end = 0, len(skeleton) - 1
        for end in range(header.end() - 1, len(skeleton)):
            if skeleton[end] == '{':
                depth += 1
            elif skeleton[end] == '}':
                depth -= 1
                if depth == 0:
                    break
        body_start, body_end = header.end(), end
        sections = list(SECTION.finditer(skeleton, body_start, body_end))
        meta = []
        for index, section in enumerate(sections):
            if section.group(1) != 'meta':
                continue
            stop = sections[index + 1].start() if index + 1 < len(sections) else body_end
            for key, value in META_PAIR.findall(clean[section.end():stop]):
                meta.append((key, value[1:-1] if value.startswith('"') else value))
        rules.append({'name': header.group(2), 'meta': meta, 'start': header.start(), 'end': body_end + 1})
        position = body_end + 1
    return rules


# ---------------------------------------------------------------- licence classification

CLASSES = ('drl_1_1', 'other_permissive', 'copyleft', 'non_commercial', 'unclear')
NON_COMMERCIAL = re.compile(r'by-nc|\bnc\b|non-?commercial', re.I)
COPYLEFT = re.compile(r'\b[al]?gpl\b|gnu (?:lesser |affero )?general public licen[cs]e', re.I)
DRL = re.compile(r'\bdrl[ -]?1\.1\b|det\w*ction rule licen[cs]e,?\s*(?:version\s*)?1\.1', re.I)
PERMISSIVE = re.compile(r'\bmit\b|\bbsd\b|apache|creativecommons\.org/licenses/by/|\bcc[ -]by\b(?![ -](?:nc|sa|nd))'
                        r'|open[- ]government[- ]licen[cs]e', re.I)
# Free-text licence wording inside a comment (besides "License: ..." / "license = ..." lines).
COMMENT_TEXT = (
    ('non_commercial', re.compile(r'by-nc|non-?commercial', re.I)),
    ('copyleft', re.compile(r'gnu (?:lesser |affero )?general public licen[cs]e', re.I)),
    ('other_permissive', re.compile(r'2-Clause BSD|BSD 2-Clause|Redistributions of source code must retain'
                                    r'|Apache License,? Version 2\.0|\bMIT License\b', re.I)),
    ('drl_1_1', DRL),
)
COMMENT_STATEMENT = re.compile(r'(?im)^[\s/*#-]*licen[cs]e\s*[:=]\s*(.+?)\s*$')
LICENCE_WORD = re.compile(r'\blicen[cs]e[ds]?\b', re.I)
PARSER_NOTE = (
    'Rules and meta key/value pairs are read by data/scripts/fetch_yara.py parse_rules() without compiling. '
    'Licence statements come from each rule\'s license meta values and from comments. A comment covers: every '
    'rule in the file if it ends before the first rule (file header); the rule it sits inside; or the rule it '
    'sits just above (only whitespace or other comments between them). Comment lines or blocks separated only '
    'by whitespace form one comment, except that a comment containing a rule declaration is never merged. Comments that contain a rule declaration '
    '(commented-out rules) are not licence statements and stop the "just above" walk. In a comment, a '
    '"License: X" / "license = X" line is classified like a meta value, and free text is matched for NC, GNU '
    'GPL, BSD, Apache-2.0, MIT and DRL 1.1 wording; a comment that mentions a licence but matches nothing is '
    'unclear. Values are classified in this order: non_commercial (by-nc, NC, non-commercial), copyleft (GPL '
    'family), drl_1_1 (DRL 1.1 named with its version), other_permissive (MIT, BSD, Apache, CC BY, UK Open '
    'Government Licence), otherwise unclear (for example a bare link to a licence file, or DRL without a '
    'version). A rule with no statement is drl_1_1 by default; one class is that class; two or more classes '
    'are unclear (conflict).'
)


def classify_value(value: str) -> str:
    if NON_COMMERCIAL.search(value):
        return 'non_commercial'
    if COPYLEFT.search(value):
        return 'copyleft'
    if DRL.search(value):
        return 'drl_1_1'
    if PERMISSIVE.search(value):
        return 'other_permissive'
    return 'unclear'


def comment_classes(comment: str) -> set[str]:
    """Licence classes stated in one comment; empty when it says nothing about a licence."""
    found = {classify_value(value) for value in COMMENT_STATEMENT.findall(comment)}
    found |= {label for label, pattern in COMMENT_TEXT if pattern.search(comment)}
    if not found and LICENCE_WORD.search(comment):
        found.add('unclear')
    return found


def comment_blocks(text: str) -> list[tuple[int, int]]:
    """Comment spans, with neighbours separated only by whitespace merged into one block.

    A span that contains a rule declaration (a commented-out rule) is never merged.
    """
    blocks, previous_rule = [], True
    for start, end in _skeleton(text)[2]:
        is_rule = bool(RULE_HEADER.search(text[start:end]))
        merge = blocks and not is_rule and not previous_rule and not text[blocks[-1][1]:start].strip()
        previous_rule = is_rule
        if merge:
            blocks[-1] = (blocks[-1][0], end)
        else:
            blocks.append((start, end))
    return blocks


def rule_licences(text: str) -> list[dict]:
    """Each rule with its licence class and the classes of the statements that cover it."""
    rules = parse_rules(text)
    if not rules:
        return []
    comments = []
    for start, end in comment_blocks(text):
        body = text[start:end]
        commented_rule = bool(RULE_HEADER.search(body))
        comments.append({'start': start, 'end': end, 'rule': commented_rule,
                         'classes': set() if commented_rule else comment_classes(body)})
    header = set().union(*(c['classes'] for c in comments if c['end'] <= rules[0]['start']))
    out = []
    for rule in rules:
        stated = set(header)
        stated |= {cls for value in _values(rule['meta'], 'license') for cls in [classify_value(value)]}
        for c in comments:
            if c['start'] >= rule['start'] and c['end'] <= rule['end']:
                stated |= c['classes']
        boundary = rule['start']
        for c in reversed([c for c in comments if c['end'] <= rule['start']]):
            if text[c['end']:boundary].strip() or c['rule']:
                break
            stated |= c['classes']
            boundary = c['start']
        if not stated:
            cls, default = 'drl_1_1', True
        else:
            cls, default = (next(iter(stated)) if len(stated) == 1 else 'unclear'), False
        out.append({'name': rule['name'], 'meta': rule['meta'], 'class': cls, 'default': default,
                    'stated': sorted(stated)})
    return out


def _values(meta, key):
    return [value for name, value in meta if name.lower() == key]


def is_drl_11(value: str) -> bool:
    return bool(DRL.search(value))


def _sorted_counts(counter: Counter) -> dict:
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def census_of(files: dict[str, str]) -> dict:
    """Counts only. `files` maps relative path -> text (rule files and the external-variable list)."""
    licences, other, rules, with_author, multi = Counter(), [], 0, 0, 0
    without_licence = drl_field = 0
    classes, drl_default = Counter({name: 0 for name in CLASSES}), 0
    non_commercial, unclear, files_with_comment_statements, commented_out = [], [], 0, 0
    rules_per_file = {}
    for path in sorted(files):
        if not path.endswith(RULE_SUFFIXES):
            continue
        text = files[path]
        parsed = rule_licences(text)
        rules_per_file[path] = len(parsed)
        bodies = [text[s:e] for s, e in comment_blocks(text)]
        commented_out += sum(1 for body in bodies if RULE_HEADER.search(body))
        files_with_comment_statements += any(comment_classes(b) for b in bodies if not RULE_HEADER.search(b))
        for rule in parsed:
            rules += 1
            classes[rule['class']] += 1
            drl_default += rule['default']
            if rule['class'] == 'non_commercial':
                non_commercial.append({'file': path, 'rule': rule['name']})
            elif rule['class'] == 'unclear':
                unclear.append({'file': path, 'rule': rule['name'], 'stated': rule['stated']})
            values = _values(rule['meta'], 'license')
            with_author += bool(_values(rule['meta'], 'author'))
            multi += len(values) > 1
            if not values:
                without_licence += 1
                continue
            licences.update(values)
            if all(is_drl_11(v) for v in values):
                drl_field += 1
            else:
                other.append({'rule': rule['name'], 'file': path, 'license': ' | '.join(values)})
    listed = [line.strip() for line in files.get(SB_LIST, '').splitlines()
              if line.strip() and not line.strip().startswith('#')]
    listed_paths = [f'yara/{name}' for name in listed]
    present = [p for p in listed_paths if p in rules_per_file]
    other_licences = Counter(r['license'] for r in other)
    return {
        'rule_files': len(rules_per_file),
        'rules': rules,
        'licence_classes': {name: classes[name] for name in CLASSES},
        'drl_1_1_by_default': drl_default,
        'drl_1_1_stated': classes['drl_1_1'] - drl_default,
        'non_commercial_rules': non_commercial,
        'unclear_rules': unclear,
        'files_with_comment_licence_statements': files_with_comment_statements,
        'comment_blocks_with_commented_out_rules': commented_out,
        'license_field': {
            'rules_without_license_field': without_licence,
            'rules_with_drl_1_1_license_field': drl_field,
            'rules_with_other_license_field': len(other),
            'other_license_counts': _sorted_counts(other_licences),
            'other_license_rules': sorted(other, key=lambda r: (r['file'], r['rule'])),
            'values': _sorted_counts(licences),
            'rules_with_more_than_one_license_field': multi,
        },
        'rules_with_author_field': with_author,
        'rules_without_author_field': rules - with_author,
        'external_variable_list': {
            'file': SB_LIST,
            'entries': len(listed),
            'entries_are': 'rule file names under yara/',
            'listed_files_present': len(present),
            'listed_files_missing': sorted(set(listed_paths) - set(present)),
            'rules_in_listed_files': sum(rules_per_file[p] for p in present),
        },
        'parser': PARSER_NOTE,
    }


def census(lock: dict, base: Path) -> dict:
    source = lock['source']
    root = base / source['directory']
    texts = {}
    for entry in source['files']:
        body = read_file(root / entry['path'])
        if body is None:
            raise FileNotFoundError(f"rule_file_missing:{entry['path']}")
        texts[entry['path']] = body.decode('utf-8', errors='replace')
    return census_of(texts)


# ---------------------------------------------------------------- fetch and verify

def verify(lock: dict, base: Path) -> list[str]:
    """Empty list when everything matches the lock; otherwise reason codes."""
    source = lock['source']
    root = base / source['directory']
    problems = [f"file_mismatch:{e['path']}" for e in source['files'] if not file_matches(root / e['path'], e)]
    if tree_sha256((e['path'], e['sha256']) for e in source['files']) != lock['rule_tree_sha256']:
        problems.append('rule_tree_sha256_mismatch')
    if not problems and census(lock, base) != lock['census']:
        problems.append('census_mismatch')
    return problems


def download(source: dict, base: Path, session) -> None:
    root = base / source['directory']
    removed = []
    for entry in source['files']:
        target = root / entry['path']
        if file_matches(target, entry):
            continue
        body = http_get(session, source['url_prefix'] + entry['path'])
        if len(body) != entry['size'] or sha256_bytes(body) != entry['sha256'] or \
                git_blob_sha1(body) != entry['git_blob_sha1']:
            raise ValueError(f"sha256_mismatch:{entry['path']}")
        if not write_checked(target, body):
            removed.append(entry['path'])
    if removed:
        raise RemovedAfterWrite(removed)


def fetch(lock: dict, base: Path, session) -> str:
    if not verify(lock, base):
        return 'already_verified'
    download(lock['source'], base, session)
    problems = verify(lock, base)
    if problems:
        raise ValueError(problems[0])
    return 'downloaded_and_verified'


# ---------------------------------------------------------------- pinning (once)

def _api(session, path: str):
    response = session.get('https://api.github.com/repos/' + path, timeout=(10, 60),
                           headers={'User-Agent': USER_AGENT, 'Accept': 'application/vnd.github+json'})
    response.raise_for_status()
    return response.json()


def pin(commit: str, base: Path, session, reason: str, dropped: list | None = None) -> dict:
    """Build the lock from the GitHub API tree of `commit` and measured files."""
    info = _api(session, f'{SB_REPO}/commits/{commit}')
    tree = _api(session, f"{SB_REPO}/git/trees/{info['commit']['tree']['sha']}?recursive=1")
    if tree.get('truncated'):
        raise ValueError('tree_truncated')
    files = sorted(({'path': e['path'], 'size': e['size'], 'git_blob_sha1': e['sha']}
                    for e in tree['tree'] if e['type'] == 'blob' and is_kept(e['path'])), key=lambda e: e['path'])
    directory = f'signature-base/{commit[:12]}'
    prefix = f'{SB_RAW}{commit}/'
    removed = []
    for entry in files:
        target = base / directory / entry['path']
        body = read_file(target)
        if body is None or git_blob_sha1(body) != entry['git_blob_sha1']:
            body = http_get(session, prefix + entry['path'])
            if len(body) != entry['size'] or git_blob_sha1(body) != entry['git_blob_sha1']:
                raise ValueError(f"git_blob_mismatch:{entry['path']}")
            if not write_checked(target, body):
                removed.append(entry['path'])
        entry['sha256'] = sha256_bytes(body)
    if removed:
        raise RemovedAfterWrite(removed)
    lock = {
        'description': 'Pinned YARA rule text for the malware engine (docs/design/malware-engine-v1.md §3.3, §3.7). '
                       'Rule text only; fetched and verified by data/scripts/fetch_yara.py.',
        'pinned_on': date.today().isoformat(),
        'pin_reason': reason,
        'destination': DESTINATION,
        'source': {
            'repository': SB_REPO,
            'commit': commit,
            'commit_date': info['commit']['committer']['date'],
            'git_tree': info['commit']['tree']['sha'],
            'license': 'DRL-1.1, except rules whose license metadata states another licence',
            'license_url': f'https://github.com/{SB_REPO}/blob/{commit}/LICENSE',
            'url_prefix': prefix,
            'kept': 'files under yara/ ending in .yar or .yara, plus yara/external-variable-rules.txt',
            'directory': directory,
            'file_count': len(files),
            'total_size': sum(e['size'] for e in files),
            'sha256_source': 'measured on download; each file also matches the git blob SHA-1 of the pinned '
                             'commit tree',
            'files': [{k: e[k] for k in ('path', 'size', 'sha256', 'git_blob_sha1')} for e in files],
        },
        'rule_tree_sha256': tree_sha256((e['path'], e['sha256']) for e in files),
        'rule_tree_sha256_definition': TREE_DEFINITION,
        'dropped_sources': dropped or [],
    }
    lock['census'] = census(lock, base)
    return lock


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--verify-only', action='store_true', help='check existing files; download nothing')
    parser.add_argument('--pin', metavar='SIGNATURE_BASE_COMMIT')
    parser.add_argument('--reason', default='')
    parser.add_argument('--dropped', type=Path, help='JSON file with the dropped_sources list')
    args = parser.parse_args(argv)
    base = ROOT / DESTINATION
    import requests
    try:
        if args.pin:
            dropped = json.loads(args.dropped.read_text(encoding='utf-8')) if args.dropped else []
            lock = pin(args.pin, base, requests.Session(), args.reason, dropped)
            LOCK.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')
            print(json.dumps({'pinned': args.pin, 'rule_tree_sha256': lock['rule_tree_sha256']}))
            return 0
        lock = load_lock()
        if args.verify_only:
            problems = verify(lock, base)
            status = 'verified' if not problems else f'missing_or_mismatch:{len(problems)}'
        else:
            status = fetch(lock, base, requests.Session())
    except RemovedAfterWrite as exc:
        print(json.dumps({'status': 'removed_after_write', 'files': exc.paths}))
        return 2
    print(json.dumps({'signature-base': status}))
    return 0 if status in ('verified', 'already_verified', 'downloaded_and_verified') else 1


if __name__ == '__main__':
    sys.exit(main())
