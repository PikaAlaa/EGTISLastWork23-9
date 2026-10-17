"""Restore an exact pinned raw file, or verify all local copies. Never refresh a snapshot.

Only manifest-pinned research downloads are fetched. Other sources require an
independently authorised local copy because their original download identity is unknown.
Existing mismatching files are never replaced. No dataset URL is visited.
"""
import argparse,hashlib,io,json,os,tempfile,zipfile
from pathlib import Path
from urllib.request import urlopen
ROOT=Path(__file__).resolve().parents[2]
MANIFEST=ROOT/'data/raw-sources-manifest.json'

def digest(data):return hashlib.sha256(data).hexdigest()

def verify(data,expected):
    if digest(data)!=expected:raise ValueError('SHA-256 mismatch; snapshot differs. Existing files were not changed.')

def target_path(root,relative):
    target=(root/relative).resolve()
    if not target.is_relative_to((root/'data/raw').resolve()):raise ValueError('Target must stay inside data/raw')
    return target

def restore(entry,root=ROOT,input_path=None):
    target=target_path(root,entry['path'])
    if target.exists():verify(target.read_bytes(),entry['sha256']);return 'already verified'
    if input_path:
        data=Path(input_path).read_bytes()
    elif entry.get('download_url'):
        # URL comes from the curated source manifest, never from phishing data.
        with urlopen(entry['download_url'],timeout=90) as response:data=response.read()
        if entry.get('archive_sha256'):
            verify(data,entry['archive_sha256'])
            with zipfile.ZipFile(io.BytesIO(data)) as archive:data=archive.read(entry['archive_member'])
    else:
        raise ValueError('Original pinned download unavailable. Obtain an authorised copy and use --input. No latest-list/feed substitution is permitted.')
    verify(data,entry['sha256']);target.parent.mkdir(parents=True,exist_ok=True)
    # Exclusive creation prevents accidentally overwriting user data between checks.
    with target.open('xb') as stream:stream.write(data)
    return 'restored and verified'

def check_all(manifest, root=ROOT):
    """Inventory every file, including recovery instructions in a clean clone."""
    rows=[]
    for entry in manifest['files']:
        path=target_path(root,entry['path'])
        status='missing' if not path.exists() else 'verified' if digest(path.read_bytes())==entry['sha256'] else 'checksum_mismatch'
        # Git's Windows checkout can change only line endings. Recognize an
        # exact pinned LF/CRLF variant for inventory, never rewrite local data or
        # relax restore()'s byte-exact import verification.
        if status=='checksum_mismatch' and path.suffix.lower() in {'.txt','.csv'}:
            lf=path.read_bytes().replace(b'\r\n',b'\n')
            if entry['sha256'] in {digest(lf),digest(lf.replace(b'\n',b'\r\n'))}:
                status='verified_newline_variant'
        command=f'python data/scripts/restore_raw_data.py --file "{entry["path"]}"'
        if not entry.get('download_url'):command+=' --input "<authorised-original-copy>"'
        rows.append({'path':entry['path'],'status':status,'sha256':entry['sha256'],
                     'restore_command':command,'source':entry.get('source_url'),
                     'note':'Never substitute a current feed/list; obtain the authorised pinned original.' if not entry.get('download_url') else 'Pinned official download; archive and member SHA-256 verified.'})
    return {'files':rows,'verified':sum(r['status'] in {'verified','verified_newline_variant'} for r in rows),
            'verified_newline_variant':sum(r['status']=='verified_newline_variant' for r in rows),
            'missing':sum(r['status']=='missing' for r in rows),
            'checksum_mismatch':sum(r['status']=='checksum_mismatch' for r in rows),
            'network_requests':0}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file',help='Exact repo-relative path listed in the manifest')
    parser.add_argument('--input',type=Path,help='Authorised original local file to verify and copy')
    parser.add_argument('--check-all',action='store_true')
    parser.add_argument('--json',action='store_true',help='Machine-readable inventory and restore commands')
    args=parser.parse_args();manifest=json.loads(MANIFEST.read_text(encoding='utf-8'))
    if args.check_all:
        report=check_all(manifest)
        if args.json:print(json.dumps(report,indent=2))
        else:
            for row in report['files']:
                print(f"{row['status']}: {row['path']}")
                if row['status'] not in {'verified','verified_newline_variant'}:print('  Restore: '+row['restore_command']+'\n  '+row['note'])
            print(f"Verified {report['verified']} raw files; missing {report['missing']}; checksum mismatch {report['checksum_mismatch']}; no network or data changes.")
            print('Authorised restore: python data/scripts/restore_raw_data.py --file "data/raw/<path>" --input "<authorised-original-copy>". PhiUSIIL can use its pinned official download without --input.')
        return int(bool(report['missing'] or report['checksum_mismatch']))
    if not args.file:parser.error('--file or --check-all is required')
    matching=[e for e in manifest['files'] if e['path']==args.file]
    if not matching:parser.error('File is not in the pinned manifest')
    print(restore(matching[0],input_path=args.input))

if __name__=='__main__':raise SystemExit(main())
