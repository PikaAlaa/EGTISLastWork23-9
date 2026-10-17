# URL-pattern acceptance rule — v3 follow-up

Written after seeing the v2 aggregate results and **before new pattern
measurement or proposal selection**. The known 5,544/91,260 scanner benign flags
are exposed development evidence, not a fresh final test.

Diagnose the current PhreshPhish-test benign pattern flags as counts per flag
only. Print no example hosts. This diagnostic must not determine a proposal.

Derive and freeze ONE proposed pattern-alert policy using PhreshPhish official
TRAINING rows in the existing combined fitting/calibration pools only, excluding
ETIS-source rows. Do not use test or ETIS validation to choose its flag set or
parameters. Keep each detected flag for explanation; independently define which
flags may create supporting alerts/corroboration.

Choose among these predeclared nested proposals on training/calibration only:

1. Structural flags independently alert: userinfo, IP host, nonstandard port,
   punycode, many subdomains. no_https, long_url and suspicious_path_keyword alert
   only in a pair with another of those three weak flags.
2. Structural flags independently alert as above; weak flags remain diagnostic
   only, requiring independent brand/blacklist/secret evidence for model support.
3. Only userinfo, IP host, nonstandard port and punycode independently alert;
   other flags remain diagnostic only.
4. Only userinfo and punycode independently alert; other flags remain diagnostic
   only.

On the frozen training/calibration pools, choose the proposal with highest
pattern-only recall subject to pattern-only benign FPR <= 0.5%; exact ties
prefer lower FPR then the listed order. If no proposal qualifies, propose no
change. Save its identity and training measurements before evaluating it on test
or ETIS validation. Do not try another proposal after seeing evaluation results.

Acceptance requires BOTH:

* Proposed pattern-rule FPR on full PhreshPhish test <= 1% (all benign rows in
  denominator; invalid inputs abstain).
* No loss on the 23/7/15 regression replays: all 23 detection, 7 robustness and
  15 follow-up expectations must pass under the final ordinary URL-model policy.

Report pattern-only and integrated recall changes, all current/proposed benign
per-flag counts, and the acceptance outcome. Also run ETIS validation as a
diagnostic, never as a proposal-selection input. If acceptance fails, keep the
current pattern rules and document the limitation; do not retune using test,
validation, or replay failures. Replay expectations are acceptance checks only.

Registry fixes are separate: export the 13 ETIS benign brand-resemblance
brand/domain pairs offline; add only missing official domains supported by
official citations. All unsourced/nonofficial pairs remain known limitations.
No destination visits, more than 20 example hosts, push or merge.
