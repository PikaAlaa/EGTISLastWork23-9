# Gate URL-model contribution and reduce pattern false alarms

V2's total-scanner gate obscured an ordinary model policy that adds few false alarms.
Freeze v3 after disclosing v2 results, reuse all 202 calibration-frozen candidates,
and deploy the highest integrated PhreshPhish-recall passer: existing full-URL
LightGBM at 0.9903286846155258, with ordinary support. Its own alerts pass all three
FPR limits; extra scanner FP are 48/91,260 on PhreshPhish and 2/2,916 on ETIS.

Choose one pattern proposal only on PhreshPhish training/calibration after freezing
acceptance. Keep keyword, HTTP, length and subdomain-count observations diagnostic;
IP, userinfo, nonstandard port and punycode may alert. Test pattern FPR is
17/91,260 (0.018628%), and the 23/7/15 replays have no loss. The same model's integrated
recall falls 11.710 points on PhreshPhish and 9.861 on ETIS from this change.

List all 13 ETIS brand/domain pairs offline. Add only seven cited missing official
Amazon/Orange domains; retain six unsupported resemblance cases as limitations.
Final scanner recall is 59.479% PhreshPhish / 17.294% ETIS, with total false positives
254/91,260 and 10/2,916. Report matched original-v3, v1 and corroboration-only results,
separating non-model and model-added false positives on both cohorts.

Validation: 251 pytest tests; initialize, frontend build and lint pass; replays
23/23, 7/7, 15/15; all 17 host probes avoid MEDIUM/HIGH; full-scanner cohort checks
have zero mismatches. Logs and detailed evidence: [REPORT.md](REPORT.md).

The text model, frozen thresholds and historical data safeguards remain. These
repeatedly exposed cohorts do not establish independent or Egyptian SMS accuracy.
No sealed test, push, merge, data upload or history rewrite.
