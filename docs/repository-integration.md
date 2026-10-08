# Repository integration — 8 October 2026

The user authorized publishing the reviewed local build to
`https://github.com/PikaAlaa/EGTISLastWork23-9` after its local evidence review.
The original Mido-77 repository is not a publication destination.

The destination initially pointed to `11e95da1c5d5821f48cc64d8c00c2ca036d41805` and contained a different
implementation and different dataset/model artifacts. This revision imports the
reviewed decision-v2 build as a normal successor commit. It does not rewrite history.
The prior implementation, dataset and models remain recoverable from that commit.
Its old API/dataset contracts are additionally preserved under `docs/history/`.
Obsolete runtime modules, conflicting tests and alternative frontend files are
superseded so a fresh checkout runs one coherent implementation.

The imported baseline input and September model/tokenizer are the same reviewed
artifacts preserved from Mido-77 commit `bd56f3b`. Current grouped v2 data is regenerated
separately. This intentionally replaces the destination's other processed dataset;
the destination's old metrics must not be attached to the new selected artifact.

Prior destination artifact byte hashes, for recovery and comparison:

```json
{
  "data/processed/dataset.csv": "54476cdc4ecd05c17670c69a4481a067e3c5ddbc077352d8b7db1185e3dfb43f",
  "ml/artifacts/bilstm.keras": "1dfa9522fd4544cdff458ae77a0718c0e7b24936a2081d38384a8f8785fb5e3b",
  "ml/artifacts/text_model.joblib": "23723b00bc6f11f5a02a7fc81420bc249dceb19a907827aea8b9087ed1fd6340"
}
```

The publication includes the selected character model, migrations, scanner, bilingual
interface, proxy, feed tools, install/start/stop scripts, CI workflow, source-level
validation reports and unchanged reviewer evidence. Local secrets, databases, logs,
private submissions, installed dependencies and intermediate candidate weights are
excluded. Fresh clones must install dependencies and initialize their own database;
feed health is not transferred through Git.

The local implementation/review documents retain historical facts about earlier
local-only stages. This integration note records the subsequent publication request.
Saved evidence is under `evaluation/reports/reviewed-2026-10-08/`; older plots,
`ml/results/` and root `acceptance_test_report.json` are historical baseline material,
not final results for this build. Hosted CI status is checked after publication.

Known SMS false alarms, weak new-domain detection, genuine-data collection,
supervisor-approved targets, Docker/PostgreSQL validation and final thesis evaluation
remain open. Optional reporting, accounts/history and Telegram remain deferred.
