# URL contribution-gate v3 handover

Branch: `fix/url-subdomains-and-hygiene`. Local commit only; no push or merge.

Deployed **ordinary** support from existing `combined_full_url_lightgbm.joblib`,
full URL, threshold **0.99032868461552581** from the unchanged v2 frozen table.
Packaged SHA-256: `4fb9b6afbb4b356e54b842490e9192628a74db22a6dc88bb60d6c1054ce335f8`.

Rule v3 was written after v2 results and before new computation. All 202 frozen
candidates were compared; 97 pass the model-own and incremental-FP gates. The selected
model adds 48/91,260 PhreshPhish benign alerts and 2/2,916 ETIS alerts.
Total scanner FP: **254/91,260** and **10/2,916**; recall **59.479%** and **17.294%**.

The training-only frozen `four_structural_only` pattern proposal passes: test pattern
FPR **17/91,260 (0.018628%)**, and all 23/7/15 replays. Its integrated recall cost is
**11.710 percentage points PhreshPhish / 9.861 points ETIS**, versus the same model
and registry with legacy patterns. Raw weak flags remain diagnostic observations.
Seven cited official-domain additions fix seven of the 13 brand pairs; six remain
known limitations. All pairs and sources are in the report. Vodafone Group remains sourced.

Checks: **251 pytest tests**, initialize, frontend build and lint pass;
**23/23, 7/7, 15/15** replays; **17/17** legitimate host probes avoid MEDIUM/HIGH.
Full production scanner verification: **1,619 matches, zero mismatches**.

Read [REPORT.md](REPORT.md), [PR_DESCRIPTION.md](PR_DESCRIPTION.md),
[selection](url_v3_final_selection.json), [pattern acceptance](pattern_evaluation_v3.json),
and [brand pairs](etis_brand_resemblance_pairs_v3.json).
The v1 probability export and requested 13 brand pairs are the only authorized
minimal cohort exports; row predictions/data remain ignored. Historical v1/v2
reports remain available. September/text models, tokenizer, targets and frozen
partitions are preserved. No sealed test; genuine Egyptian SMS count 0.
Repeated development selection is not independent validation. Stop after this commit.
