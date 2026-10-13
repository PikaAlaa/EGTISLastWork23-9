# Raw data licences and reproducibility

Audit date: 13 October 2026. The inventory covers every file under `data/raw/`. No raw data was deleted or replaced. Source access does not establish reuse permission. `LICENSE` is an unchosen project-code placeholder; it does not license third-party data.

## Source terms

### phreshphish

Source: [Dalton et al. (2025), PhreshPhish, arXiv preprint DOI 10.48550/arxiv.2507.10854; dataset v1.0.1](https://huggingface.co/datasets/phreshphish/phreshphish/blob/eabec4b7a66324b79cc8a0ad856d1731dc26fe1a/README.md).

Licence/terms: CC BY 4.0; additional dataset-card research-use statement. Quoted wording: “should only be used for anti-phishing research”.

Public redistribution: CC BY 4.0 permits sharing subject to attribution; comply with the card research-use statement. Project policy: do not commit this dataset.

Stored outside data/raw, only under ignored data/external/phreshphish/. Download only url, label, target, date, lang with data/scripts/download_phreshphish.py. data/phreshphish-lock.json pins revision, upstream-declared SHA-256 and independently measured selected-range/projected-file SHA-256. HTML column data is never downloaded by this script. Original whole-file hashes are not locally verified because whole-file downloading would retrieve HTML. Card test counts differ by 76; benign URL source is not stated.

### openphish

Source: [OpenPhish community feed; original retrieval date not recorded](https://openphish.com/terms.html).

Licence/terms: Proprietary service terms. Quoted wording: “Except as expressly permitted by OpenPhish in writing”.

Public redistribution: Not permitted by current terms without written permission; restrictions include disclosure and derivatives.

Dynamic feed cannot reproduce original snapshot. Use authorised local snapshot with checksum; do not fetch latest as a replacement.

### phishtank

Source: [PhishTank online-valid feed; original retrieval date not recorded](https://phishtank.org/terms.php).

Licence/terms: Current terms link to Cisco EULA; applicable snapshot-specific grant not stated. Quoted wording: “Archived Terms of Use”.

Public redistribution: Not established. The CC BY-SA 2.5 statement is in archived terms, not sufficient proof of current snapshot rights.

Dynamic feed; authorised original local snapshot only until capture provenance is established.

### tranco

Source: [Existing repository Tranco list and locally cleaned/approved derivatives; original list ID and date absent](https://tranco-list.eu/).

Licence/terms: not stated for these local snapshots. Quoted wording: “not stated”.

Public redistribution: Not established for this snapshot; upstream component rankings carry differing terms. Do not assume a blanket CC licence.

Use existing tranco_raw.csv and tranco_final_approved.csv only. Original download cannot be recovered from a known list ID; no new list fetched.

### github_spam

Source: [HosamMukhairez/Arabic-Text-Spam-Detection; no licence file found](https://github.com/HosamMukhairez/Arabic-Text-Spam-Detection).

Licence/terms: not stated. Quoted wording: “not stated”.

Public redistribution: Not established. Public access is not a redistribution licence.

Local checksum-pinned copy; verify permission and original upstream path/revision before enabling automated download.

### kaggle_fully

Source: [Kaggle Fully Dataset; local file linked to Hosni notebook in repository, exact dataset identity not verified](https://www.kaggle.com/code/ahmadhosni/bert-for-arabic-phishing-and-legitimate-emails).

Licence/terms: not stated. Quoted wording: “not stated”.

Public redistribution: Not established; notebook citation does not establish spreadsheet licence.

Obtain authorised original attachment; checksum verified. No speculative Kaggle dataset slug/download.

### kaggle_dialectal

Source: [Local dialectal Arabic phishing/safe CSV; candidate Kaggle page identity unverified](https://www.kaggle.com/datasets/sultannizar/arabic-phishing-dataset).

Licence/terms: not stated. Quoted wording: “not stated”.

Public redistribution: Not established; collection method and licence unverified.

Authorised local copy with checksum; no inferred licence or generated replacement.

### salloum

Source: [Local Arabic/English email subset attributed to Salloum/Gaber corpus](https://salford-repository.worktribe.com/output/1732444/a-new-englisharabic-parallel-corpus-for-phishing-emails).

Licence/terms: not stated for local CSVs. Quoted wording: “not stated”.

Public redistribution: Not established; the paper and its access terms are not a dataset redistribution grant.

Authorised local copies with checksum; original CSV download identity not recorded.

### phiusiil

Source: [Prasad and Chandra, PhiUSIIL Phishing URL Dataset, UCI (2024), DOI 10.24432/C5C02Z](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset).

Licence/terms: CC BY 4.0. Quoted wording: “Creative Commons Attribution 4.0 International (CC BY 4.0)”.

Public redistribution: Yes, subject to attribution, licence link and indication of changes; raw file unchanged.

Pinned UCI ZIP and member SHA-256; downloaded 2026-10-13. Contains no legitimate non-root paths/queries, so not added to training.

## Every raw file

Paths are relative to `data/raw/`. Source keys link to the terms above. Full SHA-256 values are in `data/raw-sources-manifest.json`.

| File | Source / terms | Licence | Public redistribution |
|---|---|---|---|
| `arabic_sources/github_arabic_spam/non spam/1.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/11.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/12.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/13.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/14.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/21.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/22.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/24.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/25.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/26.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/31.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/32.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/33.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/34.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/35.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/36.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/37.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/38.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/39.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/40.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/41.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/43.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/44.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/45.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/46.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/47.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/48.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/49.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/50.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/58.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/59.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/60.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/65.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/66.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/67.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/68.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/69.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/70.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/73.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/74.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/75.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/76.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/77.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/78.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/79.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/8.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/80.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/81.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/85.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/86.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/87.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/non spam/9.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/12.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/13.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/14.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/15.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/16.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/18.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/19.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/2.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/20.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/21.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/22.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/25.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/28.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/29.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/3.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/30.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/31.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/32.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/35.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/36.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/37.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/38.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/41.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/6.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/7.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/github_arabic_spam/spam/9.txt` | [github_spam](#github_spam) | not stated | Not established |
| `arabic_sources/kaggle_dialectal/dialectal_arabic_phishing_dataset.csv` | [kaggle_dialectal](#kaggle_dialectal) | not stated | Not established |
| `arabic_sources/kaggle_fully_dataset/Arabic Phishing and Legitimate emails - Fully Dataset.xlsx` | [kaggle_fully](#kaggle_fully) | not stated | Not established |
| `arabic_sources/salloum_gaber_corpus/legit-bilingual.csv` | [salloum](#salloum) | not stated for local CSVs | Not established |
| `arabic_sources/salloum_gaber_corpus/phishing-bilingual.csv` | [salloum](#salloum) | not stated for local CSVs | Not established |
| `openphish_raw.txt` | [openphish](#openphish) | Proprietary service terms | No without written permission |
| `phishtank_raw.csv` | [phishtank](#phishtank) | Current terms link to Cisco EULA; applicable snapshot-specific grant not stated | Not established |
| `research/PhiUSIIL_Phishing_URL_Dataset.csv` | [phiusiil](#phiusiil) | CC BY 4.0 | Conditional yes (CC BY 4.0) |
| `tranco_clean.csv` | [tranco](#tranco) | not stated for these local snapshots | Not established |
| `tranco_final_approved.csv` | [tranco](#tranco) | not stated for these local snapshots | Not established |
| `tranco_flagged_for_review.csv` | [tranco](#tranco) | not stated for these local snapshots | Not established |
| `tranco_raw.csv` | [tranco](#tranco) | not stated for these local snapshots | Not established |

## Files the team should replace with download/import scripts before public publication

All files in the table except the attributed CC BY 4.0 PhiUSIIL file need either documented redistribution permission or removal from a future public distribution by the team. In particular: OpenPhish raw data; PhishTank snapshot pending current terms/provenance review; all four Tranco files; both Kaggle files; both Salloum CSVs; and all GitHub Arabic spam text files. No deletion has been performed.

Also inspect derived copies (`data/processed/dataset.csv`, report `text_trainval.csv`, trained artifacts and other exported datasets) before public publication. A downloader does not resolve inherited redistribution restrictions. Existing model/data bytes are retained as explicitly requested.

Use `python data/scripts/restore_raw_data.py --check-all` to verify the complete inventory. To restore one missing file: `python data/scripts/restore_raw_data.py --file "data/raw/<path>" --input "<authorised-original-copy>"`. It refuses checksum mismatches and refuses to overwrite different existing data.

For PhiUSIIL, omitting `--input` downloads the pinned official UCI ZIP, verifies its SHA-256 and then the exact CSV member. Other original download URLs/versions were not recorded or are dynamic, so the script deliberately requires a local authorised snapshot. It cannot honestly reproduce those historical bytes from today’s feed. No new Tranco list is used.

GramBeddings is not yet present. The [authors’ form](https://docs.google.com/forms/d/e/1FAIpQLScuwosnH9JIJYKUeTeR26xxiG6bWXhxYoHjoNSketW5MrCUxQ/viewform) states “free for academic purposes” and releases the download after personal details. Attach the authors’ ZIP and accompanying terms; public redistribution permission is separate. The code repository’s MIT licence is not assumed to cover that external dataset.

The six-member AAST team must choose its project-code licence and copyright holders. Nothing here chooses one for the team.
