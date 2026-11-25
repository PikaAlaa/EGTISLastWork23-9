# Raw data licences and reproducibility

## October v4 public-tree hygiene

The raw files inventoried below are now untracked and ignored, including PhiUSIIL.
Their existing local bytes are retained. The original September processed dataset,
the v3 text train/validation export and the historical Tranco export are likewise
untracked without changing their local contents. Frozen hash/split reports remain.
See `evaluation/reports/2026-10-v4/data_hygiene.json` for exact paths and SHA-256.

**These files remain in Git history and on GitHub.** Removing them from the current
tree does not purge them. Making the repository private limits public access; a
separately authorized history rewrite would be needed to remove historical copies.
No history rewrite or push was performed for this work.

Research model binaries were moved to ignored `release-artifacts/`; its local
`MANIFEST.json` maps original paths to SHA-256-verified release paths. A committed
copy is `evaluation/reports/2026-10-v4/release_manifest.json`. This prepares files for
the team's review; it does not establish redistribution rights for learned models
or authorize uploading them. Deployed artifacts and the preserved September model
and tokenizer remain tracked as required; their data provenance restrictions still apply.

Fresh clones run the packaged scanner and tests without the removed research data.
For authorized research reproduction, run `python data/scripts/restore_raw_data.py
--check-all` for per-file restore commands. Missing historical files require the
authorized pinned originals with `--input`; PhiUSIIL retains its pinned official
download. Import remains byte-exact; inventory recognizes exact LF/CRLF variants
introduced by Git without changing files. Restore the processed dataset from an
authorized original copy matching the hash in the v4 inventory, then use the existing
rebuild command in the historical reports. Never replace snapshots with current feeds.

The audit and table below are retained as historical provenance, not a list of files
still distributed in the current tree.

Audit date: 13 October 2026. The inventory covers every file under `data/raw/`. No raw data was deleted or replaced. Source access does not establish reuse permission. `LICENSE` is an unchosen project-code placeholder; it does not license third-party data.

## Source terms

### phreshphish

Source: [Dalton et al. (2025), PhreshPhish, arXiv preprint DOI 10.48550/arxiv.2507.10854; dataset v1.0.1](https://huggingface.co/datasets/phreshphish/phreshphish/blob/eabec4b7a66324b79cc8a0ad856d1731dc26fe1a/README.md).

Licence/terms: CC BY 4.0; additional dataset-card research-use statement. Quoted wording: “should only be used for anti-phishing research”.

Public redistribution: CC BY 4.0 permits sharing subject to attribution; comply with the card research-use statement. Project policy: do not commit this dataset.

Stored outside data/raw, only under ignored data/external/phreshphish/. Download only url, label, target, date, lang with data/scripts/download_phreshphish.py. data/phreshphish-lock.json pins revision, upstream-declared SHA-256 and independently measured selected-range/projected-file SHA-256. HTML column data is never downloaded by this script. Original whole-file hashes are not locally verified because whole-file downloading would retrieve HTML. Card test counts differ by 76; benign URL source is not stated.

### attack

Source: [MITRE ATT&CK STIX 2.1 data, Enterprise and Mobile collections v20.0 (modified 2026-10-13)](https://github.com/mitre-attack/attack-stix-data).

Licence/terms: [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). Quoted wording from the files' own STIX marking definition: “Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.” The Terms of Use page itself was not re-read for this entry; the team should confirm its current wording before publishing ATT&CK text.

Public redistribution: Not performed. Project policy: do not commit the STIX files. Any console page or committed artifact that shows ATT&CK names must carry the copyright statement above.

Stored only under ignored data/external/attack/. Download only the two files pinned in data/attack-lock.json with data/scripts/fetch_attack.py, which verifies size and SHA-256 and discards any mismatch. The app never downloads ATT&CK data. The committed test fixture backend/tests/fixtures/attack-20.0-subset.json (added with the catalogue loader) holds technique identifiers, names, tactics, platforms and status flags only, with the copyright statement and the source files' hashes; no descriptions. backend/tests/fixtures/attack-20.0-host-subset.json (added with the host Sigma harness) holds the same kind of fields for the host engine's techniques plus the five `revoked-by` relationships it remaps; no descriptions.

### sigmahq

Source: [SigmaHQ rules, release r2026-07-01 (published 2026-07-09), package `sigma_all_rules.zip`](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01).

Licence/terms: [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md), read 2026-11-24. Quoted wording: “If you share the Rules (including in modified form), you must retain the following if it is supplied within the Rules: 1. identification of the authors(s) ("author" field) of the Rule and any others designated to receive attribution, in any reasonable manner requested by the Rule author (including by pseudonym if designated). 2. a URI or hyperlink to the Rule set or explicit Rule to the extent reasonably practicable 3. indicate the Rules are licensed under this Detection Rule License, and include the text of, or the URI or hyperlink to, this Detection Rule License to the extent reasonably practicable” and “If you use the Rules (including in modified form) on data, messages based on matches with the Rules must retain the following if it is supplied within the Rules: 1. identification of the authors(s) ("author" field) of the Rule and any others designated to receive attribution, in any reasonable manner requested by the Rule author (including by pseudonym if designated).”

Public redistribution: Not performed. Project policy: do not commit rule files or rule text. Committed artifacts may name rule ids, titles, authors, paths and file hashes (the shipped-rule manifest). Every Sigma-based finding stores the rule's id, title, author, level, status, release, path, SHA-256, `license: DRL-1.1` and a link to the rule (docs/design/host-engine-v1.md §2.2), and the console must show the author and source with it.

Stored only under ignored data/external/sigma/. Download only the package pinned in data/sigma-lock.json with data/scripts/fetch_sigma.py, which verifies size and SHA-256 (equal to the digest GitHub publishes for the asset), extracts only `.yml` files and `version.txt`, refuses unsafe paths and oversized members, and keeps the extraction only when its tree hash matches the lock. Rule files are never modified. The app never downloads rules.

### signature_base

Source: [Neo23x0/signature-base, commit de3c7252c22b3376352b5a68defa46459a12a693 (2026-11-06)](https://github.com/Neo23x0/signature-base/tree/de3c7252c22b3376352b5a68defa46459a12a693), YARA rule text only: the 753 `.yar`/`.yara` files under `yara/` and `yara/external-variable-rules.txt`.

Licence/terms: [Detection Rule License (DRL) 1.1](https://github.com/Neo23x0/signature-base/blob/de3c7252c22b3376352b5a68defa46459a12a693/LICENSE) since 13 August 2021, except rules that state another licence in their `license` metadata (repository README, read by the reviewer 2026-11-25). The DRL attribution terms are those quoted in the [sigmahq](#sigmahq) entry. Per-rule exceptions are counted in the census in data/yara-lock.json: rules whose `license` field names another licence are listed there by name and licence (including CC BY-NC 4.0, which forbids commercial use). A licence stated in a comment also counts: a file-header comment covers every rule in its file, and a comment inside or just above a rule covers that rule; it overrides the DRL 1.1 default. The census classes each rule as drl_1_1, other_permissive, copyleft, non_commercial or unclear and lists the non_commercial and unclear rules by file and name. Those two classes are excluded from the YARA pool in step 5 (docs/design/malware-engine-v1.md §4.5). Rules under other licences keep their own attribution terms. A commercial signature-base rule feed exists and is not used.

Public redistribution: Not performed. Project policy: do not commit rule files or rule text. Committed artifacts may name rule names, files, authors, licences and file hashes (the lock file and, later, the shipped-rule manifest). As for Sigma, every YARA-based finding will store the rule's name, author, source, licence and pinned commit and a link to the rule (docs/design/malware-engine-v1.md §6.6), and the console must show the author and source with it.

Stored only under ignored data/external/yara/. Download only the files pinned in data/yara-lock.json with data/scripts/fetch_yara.py, which fetches each file from the pinned commit, verifies its size, SHA-256 and git blob SHA-1, writes through a `.part` file and stops with the file names if a file disappears after writing (for example removed by antivirus). Rule files are never modified; this step does not compile them. The app never downloads rules.

YARA-Forge (`YARAHQ/yara-forge`, release 20261108, `yara-forge-rules-core.zip`) was attempted on 2026-11-25 and dropped for v1: Windows Defender removed the package on download. It was never opened, extracted or measured; the attempt is recorded under `dropped_sources` in data/yara-lock.json.

### evtx_attack_samples

Source: [EVTX-ATTACK-SAMPLES by sbousseaden, commit 4ceed2f4706daf601c212a8f91c113dd85349a2c (2023-01-24)](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tree/4ceed2f4706daf601c212a8f91c113dd85349a2c).

Licence/terms: GNU General Public License v3.0 (repository `LICENSE.GPL`; README: “EVTX_ATT&CK's GNU General Public License”). Checked 2026-11-24.

Public redistribution: Not performed. Project policy: do not commit the `.evtx` files, their contents, or any projection or per-event output derived from them. Committed artifacts may name the files' paths and SHA-256 (the lock, the per-file technique manifest) and aggregate results.

Stored only under ignored data/external/evtx-attack-samples/. Download only the commit pinned in data/evtx-attack-samples-lock.json with data/scripts/fetch_evtx_samples.py. It keeps only the 278 `.evtx` files, `LICENSE.GPL` and `README.md`, refuses unsafe paths and oversized members, and keeps the extraction only when exactly the pinned files are present with matching SHA-256. GitHub-generated archives are not guaranteed byte-stable, so the per-file hashes are the authority. The repository's scripts and its `evtx_data.csv` (an event-level dump of the samples) are not kept. These are public lab recordings of attack tools: an exposed development set, not evidence about Egyptian users' PCs.

### host-engine-libraries

Source: PyPI packages pinned in requirements-runtime.txt for the host engine (docs/design/host-engine-v1.md §1.3, §2.3): `evtx` 0.15.0, `pySigma` 2.1.0, `pySigma-backend-sqlite` 2.1.1, `pySigma-pipeline-windows` 3.0.0, `pySigma-pipeline-sysmon` 3.0.0 (resolved on 2026-11-24 with nothing newer than 2026-11-10).

Licence/terms: `evtx` MIT (PyPI classifier). `pySigma`, `pySigma-pipeline-windows` and `pySigma-pipeline-sysmon` LGPL-2.1-only; `pySigma-backend-sqlite` LGPL-3.0-only (PyPI licence expressions, checked 2026-11-24).

Public redistribution: These are code libraries installed with pip, used unmodified as separate dependencies; ETIS does not copy or vendor their source. Anyone distributing a bundle that includes them must keep their licence texts and allow replacing the LGPL libraries. `LICENSE` remains the team's decision.

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
