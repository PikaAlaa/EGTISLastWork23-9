# Review follow-up — 8 October 2026

The supplied independent review identified three evaluation concerns. These fixes
are local; no commit or push was made. The reviewer subsequently supplied the extra
test inputs and captured outputs. They are preserved with checksums under
`evaluation/review-evidence/followup-2026-10-08/`. A local isolated replay matches
all 15 supplied probe outcomes, including the NBE false alarm. See
[replay instructions](../evaluation/FOLLOWUP.md). These exposed inputs are development
regressions, not a final held-out test set.

## Validation composition

All candidate reports now show source, language, content type and source/type
intersections, including class counts, confusion counts, false-positive denominators
and Wilson 95% intervals. [The generated comparison](validation-by-source.md) makes
the composition visible: 179 translated-source rows, 55 dialect-source rows and
48 bilingual-source rows. Only **15 legitimate dialect-source messages** are present;
zero errors on that subset cannot establish the target everyday-SMS false-alarm rate.
All 282 validation records are labelled `text` in the existing metadata, including the
translated material. Content-type labels therefore do not substitute for source
inspection or independent genre/dialect adjudication. No labels were silently changed.

The pooled character F1 of about 0.995 is retained as a validation selection result,
with an explicit warning that it is not representative everyday bank-SMS accuracy.
The twelve invented everyday-message probes still return 5 HIGH, 3 MEDIUM and 4 LOW.

## Three-model comparison

The original selector really did include only character and BiLSTM. The locally
available LightGBM report carried the same old file hash, so the stale-hash claim
could not be reproduced from that local file. It was nevertheless absent from the
final selection comparison, and the previous handover overstated that comparison.

Character, BiLSTM and LightGBM were all retrained on the same current corpus for
this follow-up. Selection now requires all three reports, current content identity,
subgroup results and matching model/tokenizer hashes. It refuses missing or stale
candidates. Validation F1: character 0.9946, BiLSTM 0.9733, LightGBM 0.8837.
Character remains selected. LightGBM is a comparison baseline; if it wins in a later
revision, deployment stops until runtime support is implemented and tested.

The final evaluation gate also verifies that the three candidate artifacts and
thresholds still match frozen selection before creating its one-shot reservation.
No final test was run, and no supervisor targets were approved by this change.

## Portable input identity

`dataset_sha256` now identifies versioned CSV content rather than raw bytes, using
`etis-csv-content-v1`. CSV quoting, column order and LF/CRLF differences do not change
identity. Row order, duplicate rows and exact cell values remain significant.
Embedded newlines normalize to LF; other whitespace is preserved. The raw file hash
remains separately available as `dataset_file_sha256` for provenance.

The rebuild writes explicit LF line endings. New training, selection, dataset
manifests and evaluation reports use the same identity helper. Older reports in
`iterations/` are historical and use the former byte hash. Tests cover both portable
equivalence and meaningful content changes. A matching dataset does not guarantee
bit-identical model weights across hardware or numerical-library versions.

## Verification and remaining work

130 backend tests passed after the evaluation fixes, including nine new guards.
After importing the reviewer probes, the suite reports **144 passed and 1 xfailed**;
the expected failure explicitly records the unresolved NBE-notice false alarm.
The selected real
model again passed the 23 development cases (including the reference) and seven
robustness probes. The full grouped URL validation result remains about 17.18%
MEDIUM-or-HIGH phishing recall. These are development results.

The outstanding work is unchanged: reduce ordinary-message false alarms and improve
new-domain detection using representative reviewed data; collect and reserve genuine
consented samples; approve targets; run the final protocols; verify Docker/PostgreSQL
and clean deployment. Optional reporting, accounts/history and Telegram stay deferred.
