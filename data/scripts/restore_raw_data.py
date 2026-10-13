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

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file',help='Exact repo-relative path listed in the manifest')
    parser.add_argument('--input',type=Path,help='Authorised original local file to verify and copy')
    parser.add_argument('--check-all',action='store_true')
    args=parser.parse_args();manifest=json.loads(MANIFEST.read_text(encoding='utf-8'))
    if args.check_all:
        for entry in manifest['files']:verify(target_path(ROOT,entry['path']).read_bytes(),entry['sha256'])
        print(f"Verified {len(manifest['files'])} raw files; no network or data changes.");return
    if not args.file:parser.error('--file or --check-all is required')
    matching=[e for e in manifest['files'] if e['path']==args.file]
    if not matching:parser.error('File is not in the pinned manifest')
    print(restore(matching[0],input_path=args.input))

if __name__=='__main__':main()
