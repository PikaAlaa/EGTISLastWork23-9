# ETIS repository guardrails

- Treat `docs/dataset_schema.md` and `docs/api_contract.md` as shared contracts.
- Never report evaluation metrics unless they were produced by a saved, reproducible run.
- Keep synthetic phishing examples inside the labeled dataset; do not turn them into reusable attack templates.
- Preserve Arabic text as UTF-8 and verify both Arabic and English user flows.
- Do not add out-of-scope bot, multi-tenant, billing, or marketing-site features before the thesis submission.
