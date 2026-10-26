# Retrospective latency and seed aggregation amendment

Written on 26 October 2026, after seeing the reported Colab timings (about
800 ms p95 on its two-core CPU), and before importing/aggregating the returned
evidence or measuring local transformer latency. This is a retrospective
hardware-comparability amendment, not a prospective preregistration. The frozen
13 October rule, its 300 ms p95 limit, data and assignments remain unchanged.

The five local candidates were timed on this PC. Colab CPU times cannot fairly
decide the same hardware gate. Re-time both transformer architectures on this PC
using pretrained weights with an untrained two-class head, without fitting:
latency depends on architecture, tokenizer and windowing, rather than the
fine-tuned numerical weights. This is an architecture latency proxy, not a
measurement of the unavailable fine-tuned artifacts. Record both machines;
apply the frozen 300 ms p95 gate to the local measurement only.

The requested new pass uses the same ordered 227 eligible validation messages
as the Colab pass, normalization and 150-word/75-stride windows, complete
message batch size one, three warmups on the first validation message, two
CPU threads, tokenization and all windows inside each timed call. Transformer
token truncation remains 256 tokens and inference follows the Colab scorer's
window batching. Record raw timings, hardware, versions and artifact identities.
No network fetching or URL resolution is permitted; use locally cached weights.

Code inspection before measuring found that the historical local-candidate
timings are not this exact protocol: `run_text_v3._latency_ms` uses all 282
validation messages, one warmup and precomputed normalized windows. Its BiLSTM
path also uses 282 messages, with preprocessing outside timing and no explicit
warmup. The frozen review reuses those timings. LightGBM uses two worker threads;
BiLSTM training configures two intra-op and two inter-op threads. Thus a new
227-message pass cannot honestly be described as exactly reproducing all five
historical timings. Preserve them and disclose this discrepancy; no reviewed
report is rewritten. The requested transformer pass is still the specified
227-message, three-warmup protocol, and includes preprocessing.

The frozen rule does not specify combining transformer seeds. Before computing
their aggregate for selection, declare: compute the frozen primary loss for
each of seeds 42, 43 and 44, then take their arithmetic mean as the candidate
loss. Report each seed, minimum and maximum, all loss components, and source
counts. Also report mean eligible-validation macro-F1 for the existing tie
breaker if needed. Do not select a favorable seed or pool source counts to
replace the rule's equal-source means. A transformer deployment would require
an explicit artifact choice and new deployment work; predictions alone cannot
serve inference.

## Execution history and owner clarification

### Owner-authorized common protocol, recorded before any new measurement

The owner clarified that the no-fetch restriction concerns message/data URLs;
package installation and downloads of the two public pretrained models are
authorized. Dependencies go only into ignored `.venv-latency`, never `.venv`.
Pretrained snapshots go under ignored `evaluation/local-results/text-transformers/`.
Use the exact pretrained revisions recorded in the returned Colab evidence.

This supersedes the proposed transformer-only re-timing above: **all seven
candidates** will be re-timed on this PC under one common protocol. Use the
227 eligible validation messages in the exact bundle/Colab order; complete
message batch size one; three warmups on the first message; normalization,
150-word windows with stride 75, tokenization/vectorization and every window
inside each timed call. Use a fixed count of **two threads** for every model:
Torch intra-op and inter-op, TensorFlow intra-op and inter-op, BLAS/OpenMP pools
and LightGBM prediction threads are each capped/configured at two. Disable
tokenizer parallelism. Run candidates sequentially in fresh subprocesses, with
no concurrent timing jobs. Record the CPU model, versions, effective thread
settings, ordered row IDs and all raw durations. Aggregate each message's
windows by maximum phishing probability. Transformer window batches retain
the existing Colab scorer's cap of eight windows and 256-token truncation;
batch size one refers to complete messages, consistently for all candidates.
BiLSTM uses its existing 200-token padding/truncation. The initial direct eager
executor is superseded by the compiled executor in the correction below.
FeatureUnion vectorizers use one job to avoid extra worker processes on top of
the common two-thread numerical pools; no messages run concurrently. A
single-threaded algorithm is not artificially parallelized: two is the common
configured numerical thread count/ceiling, not a claim that every stage uses
both threads simultaneously.

Historical local and Colab timings are reported separately and are never mixed
with this new pass. Apply the frozen **300 ms p95** gate only to the new common
protocol timings, for every candidate. The primary loss, thresholds and seed
aggregation specified above remain unchanged. The transformer pass still uses
pretrained weights plus an explicitly untrained two-class head: it is an
architecture proxy, not a measurement of the missing fine-tuned weights.

At the initial offline attempt, the strict importer accepted all six runs on
26 October 2026 and wrote ignored
`evaluation/local-results/text-transformers/imported.json`. No candidate was
selected or deployed. Recorded Colab CPU: Intel Xeon CPU at 2.00 GHz, two Torch
threads; the runner records threads, not a physical-core inventory.

The following table records the initial import, before the new common pass.
Final common-protocol measurements belong in `REPORT.md` and `comparison.json`,
so this pre-measurement amendment can retain its original measurement hash.

| Architecture | Seed | Colab p50 ms | Colab p95 ms | Local p95 at initial import |
| --- | ---: | ---: | ---: | --- |
| MARBERTv2 | 42 | 112.393121 | 801.451363 | Not measured |
| MARBERTv2 | 43 | 112.004868 | 806.796656 | Not measured |
| MARBERTv2 | 44 | 113.506767 | 791.263333 | Not measured |
| CAMeLBERT-DA | 42 | 111.394200 | 796.952487 | Not measured |
| CAMeLBERT-DA | 43 | 112.425273 | 802.376366 | Not measured |
| CAMeLBERT-DA | 44 | 114.343170 | 807.164609 | Not measured |

The initial attempt stopped pending dependencies and pretrained artifacts:
`.venv` had neither PyTorch nor Transformers, the default Hugging Face cache was
absent, and no pretrained transformer weights were found in the project. No
packages or weights had been fetched at that point. The owner then explicitly
authorized the isolated dependency/model downloads and all-seven common pass
described above. Colab latency is never substituted for the local latency gate.

### Executor correction before the complete common pass

After seeing four preliminary TF-IDF timings (p95 7.859520, 3.243790, 3.438120
and 1.673760 ms, in frozen simplicity order), the first pass was stopped during
BiLSTM inference. The direct eager BiLSTM call did not match the compiled
inference used by its historical `predict` timing and was still running after
approximately 19 minutes. **No completed BiLSTM p95 exists for that attempt**;
neither transformer had been timed. No selection or deployment had occurred.
The incomplete attempt's four raw timing files, runner and amendment snapshot
are retained under ignored `incomplete-eager-attempt/` and excluded from the
final gate and comparison. This correction is also retrospective and disclosed.

Before any replacement measurements: use `tf.function` for BiLSTM inference,
with signature `[None, 200]` int32 (dynamic window batch). Its graph is traced
during the first of the same three warmups; padding/tokenization and graph
execution remain inside every timed message call. This is the compiled
equivalent of the declared direct call, avoids Keras `predict` worker pools,
and keeps the fixed two intra-op/two inter-op thread settings. It changes no
weights, thresholds, messages or windows. **Re-run all seven candidates from
scratch**, sequentially in fresh processes, under the same 227-message,
batch-one, preprocessing-included, three-warmup, two-thread protocol; do not
reuse the four preliminary timings. Freeze the corrected runner hash in every
result. Apply the 300 ms gate only to this complete replacement pass.
