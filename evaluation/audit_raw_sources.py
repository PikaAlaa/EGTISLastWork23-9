"""Inventory local raw files and publish source/terms evidence, without deleting data."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import pandas as pd
from urllib.parse import urlsplit
from evaluation.review_common import OUT,write,sha,versions

TERMS={
 'phreshphish':{'source':'Dalton et al. (2025), PhreshPhish, arXiv preprint DOI 10.48550/arxiv.2507.10854; dataset v1.0.1',
  'url':'https://huggingface.co/datasets/phreshphish/phreshphish/blob/eabec4b7a66324b79cc8a0ad856d1731dc26fe1a/README.md',
  'licence':'CC BY 4.0; additional dataset-card research-use statement',
  'quote':'should only be used for anti-phishing research',
  'redistribution':'CC BY 4.0 permits sharing subject to attribution; comply with the card research-use statement. Project policy: do not commit this dataset.',
  'reproduce':'Stored outside data/raw, only under ignored data/external/phreshphish/. Download only url, label, target, date, lang with data/scripts/download_phreshphish.py. data/phreshphish-lock.json pins revision, upstream-declared SHA-256 and independently measured selected-range/projected-file SHA-256. HTML column data is never downloaded by this script. Original whole-file hashes are not locally verified because whole-file downloading would retrieve HTML. Card test counts differ by 76; benign URL source is not stated.'},
 'openphish':{'source':'OpenPhish community feed; original retrieval date not recorded',
  'url':'https://openphish.com/terms.html','licence':'Proprietary service terms',
  'quote':'Except as expressly permitted by OpenPhish in writing',
  'redistribution':'Not permitted by current terms without written permission; restrictions include disclosure and derivatives.',
  'reproduce':'Dynamic feed cannot reproduce original snapshot. Use authorised local snapshot with checksum; do not fetch latest as a replacement.'},
 'phishtank':{'source':'PhishTank online-valid feed; original retrieval date not recorded',
  'url':'https://phishtank.org/terms.php','licence':'Current terms link to Cisco EULA; applicable snapshot-specific grant not stated',
  'quote':'Archived Terms of Use',
  'redistribution':'Not established. The CC BY-SA 2.5 statement is in archived terms, not sufficient proof of current snapshot rights.',
  'reproduce':'Dynamic feed; authorised original local snapshot only until capture provenance is established.'},
 'tranco':{'source':'Existing repository Tranco list and locally cleaned/approved derivatives; original list ID and date absent',
  'url':'https://tranco-list.eu/','licence':'not stated for these local snapshots',
  'quote':'not stated',
  'redistribution':'Not established for this snapshot; upstream component rankings carry differing terms. Do not assume a blanket CC licence.',
  'reproduce':'Use existing tranco_raw.csv and tranco_final_approved.csv only. Original download cannot be recovered from a known list ID; no new list fetched.'},
 'github_spam':{'source':'HosamMukhairez/Arabic-Text-Spam-Detection; no licence file found',
  'url':'https://github.com/HosamMukhairez/Arabic-Text-Spam-Detection','licence':'not stated','quote':'not stated',
  'redistribution':'Not established. Public access is not a redistribution licence.',
  'reproduce':'Local checksum-pinned copy; verify permission and original upstream path/revision before enabling automated download.'},
 'kaggle_fully':{'source':'Kaggle Fully Dataset; local file linked to Hosni notebook in repository, exact dataset identity not verified',
  'url':'https://www.kaggle.com/code/ahmadhosni/bert-for-arabic-phishing-and-legitimate-emails','licence':'not stated','quote':'not stated',
  'redistribution':'Not established; notebook citation does not establish spreadsheet licence.',
  'reproduce':'Obtain authorised original attachment; checksum verified. No speculative Kaggle dataset slug/download.'},
 'kaggle_dialectal':{'source':'Local dialectal Arabic phishing/safe CSV; candidate Kaggle page identity unverified',
  'url':'https://www.kaggle.com/datasets/sultannizar/arabic-phishing-dataset','licence':'not stated','quote':'not stated',
  'redistribution':'Not established; collection method and licence unverified.',
  'reproduce':'Authorised local copy with checksum; no inferred licence or generated replacement.'},
 'salloum':{'source':'Local Arabic/English email subset attributed to Salloum/Gaber corpus',
  'url':'https://salford-repository.worktribe.com/output/1732444/a-new-englisharabic-parallel-corpus-for-phishing-emails',
  'licence':'not stated for local CSVs','quote':'not stated',
  'redistribution':'Not established; the paper and its access terms are not a dataset redistribution grant.',
  'reproduce':'Authorised local copies with checksum; original CSV download identity not recorded.'},
 'phiusiil':{'source':'Prasad and Chandra, PhiUSIIL Phishing URL Dataset, UCI (2024), DOI 10.24432/C5C02Z',
  'url':'https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset','licence':'CC BY 4.0',
  'quote':'Creative Commons Attribution 4.0 International (CC BY 4.0)',
  'redistribution':'Yes, subject to attribution, licence link and indication of changes; raw file unchanged.',
  'reproduce':'Pinned UCI ZIP and member SHA-256; downloaded 2026-10-13. Contains no legitimate non-root paths/queries, so not added to training.'},
}

def category(path):
    s=path.as_posix()
    if 'research/PhiUSIIL' in s:return 'phiusiil'
    if 'github_arabic_spam' in s:return 'github_spam'
    if 'kaggle_dialectal' in s:return 'kaggle_dialectal'
    if 'kaggle_fully' in s:return 'kaggle_fully'
    if 'salloum_gaber' in s:return 'salloum'
    if path.name.startswith('tranco'):return 'tranco'
    if path.name.startswith('phishtank'):return 'phishtank'
    if path.name.startswith('openphish'):return 'openphish'
    raise ValueError(f'Unclassified raw file: {path}')

def main():
    download=json.loads((OUT/'phiusiil_download.json').read_text())
    entries=[]
    for path in sorted((ROOT/'data/raw').rglob('*')):
        if not path.is_file():continue
        key=category(path);term=TERMS[key]
        entry={'path':path.relative_to(ROOT).as_posix(),'source_key':key,'source':term['source'],'source_url':term['url'],
          'licence':term['licence'],'redistribution':term['redistribution'],'download_url':None,
          'original_download_date':None,'sha256':sha(path),'bytes':path.stat().st_size}
        if key=='phiusiil':entry.update(download_url=download['source_url'],archive_sha256=download['archive_sha256'],archive_member=download['member'],original_download_date=download['download_date'])
        entries.append(entry)
    digest=hashlib.sha256(json.dumps(entries,sort_keys=True).encode()).hexdigest()
    manifest={'checked_date':'2026-10-13','data_sha256':digest,'model_sha256':None,'libraries':versions(),'files':entries,'terms':TERMS,'data_deleted':False}
    (ROOT/'data/raw-sources-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    lines=['# Raw data licences and reproducibility','',
      'Audit date: 13 October 2026. The inventory covers every file under `data/raw/`. No raw data was deleted or replaced. Source access does not establish reuse permission. `LICENSE` is an unchosen project-code placeholder; it does not license third-party data.',
      '', '## Source terms','']
    for key,t in TERMS.items():
        lines += [f'### {key}', '', f"Source: [{t['source']}]({t['url']}).",'',f"Licence/terms: {t['licence']}. Quoted wording: “{t['quote']}”.",'',f"Public redistribution: {t['redistribution']}",'',t['reproduce'],'']
    lines += ['## Every raw file','', 'Paths are relative to `data/raw/`. Source keys link to the terms above. Full SHA-256 values are in `data/raw-sources-manifest.json`.', '', '| File | Source / terms | Licence | Public redistribution |','|---|---|---|---|']
    for e in entries:
        key=e['source_key'];allowed='Conditional yes (CC BY 4.0)' if key=='phiusiil' else 'No without written permission' if key=='openphish' else 'Not established'
        lines.append(f"| `{e['path'][9:]}` | [{key}](#{key}) | {e['licence']} | {allowed} |")
    lines += ['', '## Files the team should replace with download/import scripts before public publication','',
      'All files in the table except the attributed CC BY 4.0 PhiUSIIL file need either documented redistribution permission or removal from a future public distribution by the team. In particular: OpenPhish raw data; PhishTank snapshot pending current terms/provenance review; all four Tranco files; both Kaggle files; both Salloum CSVs; and all GitHub Arabic spam text files. No deletion has been performed.', '',
      'Also inspect derived copies (`data/processed/dataset.csv`, report `text_trainval.csv`, trained artifacts and other exported datasets) before public publication. A downloader does not resolve inherited redistribution restrictions. Existing model/data bytes are retained as explicitly requested.', '',
      'Use `python data/scripts/restore_raw_data.py --check-all` to verify the complete inventory. To restore one missing file: `python data/scripts/restore_raw_data.py --file "data/raw/<path>" --input "<authorised-original-copy>"`. It refuses checksum mismatches and refuses to overwrite different existing data.', '',
      'For PhiUSIIL, omitting `--input` downloads the pinned official UCI ZIP, verifies its SHA-256 and then the exact CSV member. Other original download URLs/versions were not recorded or are dynamic, so the script deliberately requires a local authorised snapshot. It cannot honestly reproduce those historical bytes from today’s feed. No new Tranco list is used.', '',
      'GramBeddings is not yet present. The [authors’ form](https://docs.google.com/forms/d/e/1FAIpQLScuwosnH9JIJYKUeTeR26xxiG6bWXhxYoHjoNSketW5MrCUxQ/viewform) states “free for academic purposes” and releases the download after personal details. Attach the authors’ ZIP and accompanying terms; public redistribution permission is separate. The code repository’s MIT licence is not assumed to cover that external dataset.', '',
      'The six-member AAST team must choose its project-code licence and copyright holders. Nothing here chooses one for the team.']
    (ROOT/'docs/data-licences.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    p=pd.read_csv(ROOT/'data/raw/research/PhiUSIIL_Phishing_URL_Dataset.csv',usecols=['URL','label'])
    legitimate=p[p.label==1]; paths=legitimate.URL.map(lambda u:urlsplit(u).path not in ('','/') or bool(urlsplit(u).query))
    download.update(data_sha256=download['sha256'],model_sha256=None,libraries=versions(),legitimate_rows=len(legitimate),legitimate_nonroot_path_or_query_rows=int(paths.sum()),used_for_training=False)
    write('phiusiil_download.json',download)
    write('raw_inventory_audit.json',{'data_sha256':digest,'raw_file_count':len(entries),'manifest_sha256':sha(ROOT/'data/raw-sources-manifest.json'),'no_data_deleted':True})
    print({'raw_files':len(entries),'phiusiil_legitimate':len(legitimate),'legitimate_paths':int(paths.sum())})

if __name__=='__main__':main()
