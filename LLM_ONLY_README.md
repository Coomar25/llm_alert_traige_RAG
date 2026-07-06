# LLM-Only Triage Pipeline — Stage 5a of the AIT-ADS Pipeline

This document is the complete reference for the LLM-only triage pipeline: how
it works, every design decision, the debugging journey that got it working,
and the empirical results on the full evaluation sample.

The LLM-only pipeline is the **ablation baseline** for the dissertation's core
experiment. It uses a large language model to triage each alert using only the
model's pre-trained knowledge, with no retrieved context. Comparing it against
the LLM+RAG pipeline (identical in every way except the presence of retrieved
context) isolates the contribution of retrieval — which is the dissertation's
central research question.

```
Stage 1: ingest.py                ── parse 16 JSON files into unified schema   [DONE]
Stage 2: label_alerts.py          ── apply ground-truth attack labels          [DONE]
Stage 3: run_baseline.py          ── rule-based baseline + evaluation harness  [DONE]
Stage 4: build_knowledge_base.py  ── RAG knowledge base construction           [DONE]
Stage 5a: run_llm_only.py         ── LLM-only triage (ablation baseline)        [YOU ARE HERE]
Stage 5b: run_llm_rag.py          ── LLM+RAG triage (proposed system)          [NEXT]
Stage 6:  compare_pipelines.py    ── three-way comparison                      [PENDING]
```

---

## Table of Contents

1. [Purpose and Research Role](#1-purpose-and-research-role)
2. [How the Pipeline Works — End to End](#2-how-the-pipeline-works--end-to-end)
3. [Component Architecture](#3-component-architecture)
4. [The Model: Llama 3.2 3B via Ollama](#4-the-model-llama-32-3b-via-ollama)
5. [Design Decisions](#5-design-decisions)
6. [The Stratified Sampler](#6-the-stratified-sampler)
7. [Concurrency Design](#7-concurrency-design)
8. [Dependencies and Setup](#8-dependencies-and-setup)
9. [How to Run It — Step by Step](#9-how-to-run-it--step-by-step)
10. [Outputs](#10-outputs)
11. [The Debugging Journey](#11-the-debugging-journey)
12. [Empirical Results](#12-empirical-results)
13. [Interpretation and Dissertation Implications](#13-interpretation-and-dissertation-implications)
14. [Known Limitations](#14-known-limitations)
15. [What Comes Next](#15-what-comes-next)
16. [Quick Reference: Every Command Used](#16-quick-reference-every-command-used)

---

## 1. Purpose and Research Role

The dissertation compares three alert-triage approaches:

1. **Rule-based** (Stage 3) — severity thresholds and correlation rules.
2. **LLM-only** (this stage) — a language model reasoning over each alert with
   no external context.
3. **LLM+RAG** (Stage 5b) — the same language model, but with relevant security
   knowledge retrieved and injected into the prompt.

The LLM-only pipeline exists to answer one precise question by comparison:
**what does retrieval add?** If LLM+RAG outperforms LLM-only, and the two are
identical except for the presence of retrieved context, then the improvement is
attributable to retrieval. This is a controlled ablation.

For the ablation to be valid, LLM-only must:

- Use the same model as LLM+RAG (llama3.2:3b)
- Use the same decoding settings (temperature 0)
- Use the same prompt template except for the retrieved-context section
- Be evaluated on the same alerts with the same metrics harness

Every one of these is enforced in the implementation.

---

## 2. How the Pipeline Works — End to End

For each alert in the evaluation sample, the pipeline performs five steps:

```
   ┌─────────────────────────────────────────────────────────────────┐
   │  1. Load alert (JSONL record with ~30 fields + ground-truth      │
   │     is_attack / attack_phase labels)                             │
   └─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  2. Build compact alert text  (compact_alert_text)               │
   │     - Distil ~30 fields down to the decision-relevant ones       │
   │     - CRITICALLY: include the raw log message (the actual         │
   │       observed behaviour), not just the normalised rule name     │
   └─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  3. Build triage prompt  (build_llm_only_prompt)                 │
   │     - Task framing + base-rate anchoring + two few-shot examples │
   │     - Ask for structured JSON output                             │
   └─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  4. Call the model  (Ollama /api/generate, temperature 0)        │
   │     - Returns text; extract + parse the JSON                     │
   │     - Normalise: coerce types, validate phase vocabulary         │
   └─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  5. Record prediction against ground truth  (EvaluationResult)   │
   │     - Same harness as the rule-based baseline (M6)               │
   │     - Accumulate confusion matrix (overall / per-scenario /      │
   │       per-phase) + latency                                       │
   └─────────────────────────────────────────────────────────────────┘
```

The model outputs a JSON object with four fields:

```json
{
  "is_attack": true,
  "attack_phase": "wpscan",
  "confidence": 0.85,
  "explanation": "A suspicious HTTP request to a WordPress theme file..."
}
```

Only `is_attack` feeds the primary binary evaluation (directly comparable to
the rule-based baseline). `attack_phase` supports per-phase analysis.
`explanation` is retained for the explanation-quality evaluation (M9).
`confidence` supports later threshold analysis.

---

## 3. Component Architecture

The pipeline is split into small, single-responsibility modules under `llm/`:

```
ait_parser/
├── run_llm_only.py            ← orchestrator (concurrency + aggregation)
├── test_llm.py                ← 25 unit tests
└── llm/
    ├── __init__.py
    ├── sampler.py             ← stratified test-split sampler
    ├── alert_repr.py          ← compact alert text for the prompt
    ├── prompts.py             ← triage prompt templates + output normalisation
    └── ollama_client.py       ← resilient Ollama HTTP client + JSON extraction
```

(The `retrieval.py` module in the same folder belongs to the LLM+RAG pipeline,
Stage 5b, and is not used by LLM-only.)

### 3.1 `llm/sampler.py`

Draws a stratified subsample from the test split. See Section 6.

### 3.2 `llm/alert_repr.py`

Two functions:

- `compact_alert_text(alert)` — the text the model reasons over.
- `retrieval_query_text(alert)` — used by the RAG pipeline (Stage 5b) only.

The compact text includes: IDS source, severity (label + level), rule
description, rule categories (with an explicit note when attack-indicating
categories are present), log source, source/destination IP, and — most
importantly — the **raw log message**, truncated to 300 characters. The raw
message is the single most important field for triage accuracy (see the
debugging journey in Section 11).

### 3.3 `llm/prompts.py`

- `build_llm_only_prompt(alert_text)` — the no-retrieval prompt.
- `build_rag_prompt(alert_text, context)` — the RAG prompt (Stage 5b).
- `normalise_llm_output(parsed)` — coerces the model's JSON into a clean,
  predictable shape (bool/float coercion, phase-vocabulary validation, forcing
  benign alerts to have a null phase, clamping confidence to [0,1]).

The two prompt builders are deliberately near-identical: they share a
character-identical task-instruction block and differ ONLY in that the RAG
prompt inserts a retrieved-context section. A unit test enforces this so the
ablation stays clean.

### 3.4 `llm/ollama_client.py`

- `generate(prompt, ...)` — one call to Ollama's `/api/generate`, with
  temperature 0, retries with backoff, latency measurement, and robust JSON
  extraction (handles clean JSON, markdown-fenced JSON, and JSON embedded in
  prose).
- `check_ollama(...)` — a fast health check to fail early if Ollama is not
  running or the model is not pulled.

### 3.5 `run_llm_only.py`

The orchestrator. Health-checks Ollama, loads the sample, runs inference
concurrently (Section 7), records results using the **same** `EvaluationResult`
harness built for the rule-based baseline in M6, and writes predictions +
results.

---

## 4. The Model: Llama 3.2 3B via Ollama

### 4.1 Why Ollama

Ollama runs open-weight LLMs locally and exposes a simple HTTP API at
`http://localhost:11434`. It was chosen because:

- One-line model install (`ollama pull <model>`)
- Automatic GGUF quantisation — a 3B model runs comfortably on CPU
- Stable HTTP API with no Python/CUDA dependency management
- Identical interface whether running on CPU or GPU

### 4.2 Why Llama 3.2 3B (and not Mistral 7B)

The dissertation proposal named Mistral-7B. During implementation, the initial
smoke test on Mistral-7B ran at ~24.9 seconds per alert on CPU (no GPU
available). At that rate the evaluation sample would take ~34 hours per
pipeline, ~68 hours for both LLM-only and LLM+RAG — not tractable.

Llama 3.2 3B was adopted instead:

- ~3× faster on CPU (initial smoke test ~8.7 s/alert vs 24.9 s)
- Smaller download (~2 GB vs ~4 GB)
- Still a capable instruction-following model, well-suited to a structured
  binary-classification task

This is a normal, defensible engineering decision. The dissertation methodology
records Mistral-7B as the initial choice and documents the switch to Llama 3.2
3B for tractable CPU inference. Critically, **the same model is used for both
LLM-only and LLM+RAG**, so the ablation remains valid.

### 4.3 Decoding settings

Temperature is set to **0.0** (greedy decoding). This makes triage decisions
deterministic and reproducible: the same alert produces the same output on
re-runs. This matters for reproducibility and for the integrity of the
comparison — any difference between LLM-only and LLM+RAG is due to the input,
not to sampling randomness. Output is capped at 512 tokens (triage JSON is
small). Ollama's `format: json` option is used to constrain output.

---

## 5. Design Decisions

Each decision is recorded explicitly for the viva.

### 5.1 Structured JSON output, not free text

**Decision.** The model must output a JSON object with `is_attack`,
`attack_phase`, `confidence`, `explanation`.

**Rationale.** The primary metric (`is_attack`) must be machine-parseable and
feed the same evaluation harness as the rule-based baseline. Asking for free
text and then parsing it would be fragile. Forcing a strict JSON schema is the
standard reliable approach for LLM classification.

### 5.2 The closed attack-phase vocabulary is given to the model

**Decision.** The prompt lists the ten valid AIT-ADS attack phases and asks the
model to choose one.

**Rationale.** Constraining the output vocabulary improves phase-labelling
consistency and keeps outputs comparable with the ground-truth labels. The
`normalise_llm_output` function further validates the returned phase against the
allowed set and discards anything out-of-vocabulary.

### 5.3 The raw log message is included in the alert text

**Decision.** The compact alert representation includes the raw log message
(truncated), not just the normalised rule description.

**Rationale.** This was the single most impactful decision, discovered through
debugging (Section 11). The normalised rule description is often too generic to
distinguish attack from benign — for example, a wpscan probe for the vulnerable
`timthumb.php` component is normalised by Wazuh to "Web server 400 error code",
which sounds benign. The discriminating evidence (the requested URL path) lives
only in the raw message. Including it moved the pipeline from a degenerate
all-benign classifier to a working triage system.

### 5.4 The prompt anchors the base rate and warns against two traps

**Decision.** The prompt states that attacks are common in this environment and
explicitly warns the model not to assume (a) low severity means benign or (b)
internal IPs are safe.

**Rationale.** Also discovered through debugging. Shown a single alert in
isolation with no base-rate context, the model applied its general-world prior
("most log lines are normal") and classified everything as benign. The
calibration statements are factual descriptions of the evaluation environment
(the base rate genuinely is high; 76% of severity-2 alerts here are real
attacks per the labelling analysis; attack traffic genuinely is internal). They
are applied identically to both pipelines, so they do not advantage LLM+RAG.

### 5.5 Two few-shot examples

**Decision.** The prompt includes one attack example (a low-severity scan
correctly labelled as attack) and one benign example (a localhost cron backup).

**Rationale.** Small instruction-tuned models anchor strongly on examples.
Few-shot exemplars give the model a concrete decision pattern rather than an
invented default, and demonstrate the exact JSON output shape.

### 5.6 The evaluation harness is reused unchanged from M6

**Decision.** Import `ConfusionMatrix` and `EvaluationResult` from `baselines/`
rather than re-implementing metrics.

**Rationale.** Guarantees the LLM pipeline is scored on identical metric
definitions as the rule-based baseline. No risk of "different precision in
different scripts" drift. Build once, use three times.

---

## 6. The Stratified Sampler

### 6.1 Why sampling is necessary

The test split (wheeler, wilson, santos) contains ~1.38M alerts. At ~9 seconds
per alert (CPU, concurrent), triaging all of them would take weeks. Sampling is
mandatory.

### 6.2 Why the sample must be stratified

The attack-phase distribution is wildly imbalanced. In the test split, `dirb`
dominates while `reverse_shell` has ~66 instances, `webshell` ~68, and
`service_stop` only 7. A naive random sample of a few thousand alerts would be
almost entirely dirb and benign, containing perhaps one reverse shell — making
per-phase evaluation impossible for the rare-but-critical phases.

### 6.3 The quota strategy

The sampler applies per-phase quotas:

- **Take-all phases** (rare, precious): every instance is included, regardless
  of profile — reverse_shell, webshell, service_stop, privilege_escalation.
- **Capped phases** (common): subsampled to a maximum.
- **Benign**: sized to roughly balance the attack set.

Two profiles are provided:

| Profile | Common-phase caps | Benign | Total | Use case |
|---|---|---|---|---|
| `full` | dirb 800, others 400-500 | 1500 | ~4,800 | GPU inference |
| `small` | dirb 250, others 150-200 | 600 | ~2,000 | CPU inference |

The rare phases are identical across profiles — only common-phase and benign
caps differ. This preserves per-phase precision/recall on the phases that carry
the dissertation's core argument while roughly halving CPU inference time.

### 6.4 Integrity properties

- **Only test-split scenarios** are sampled. Train scenarios (fox, harrison,
  russellmitchell, shaw, wardbeck) are never touched — the scenario-level split
  is preserved.
- **Deterministic**: a fixed random seed (42) makes the sample reproducible.
  Re-running produces the identical sample, so LLM-only and LLM+RAG run on
  exactly the same alerts.
- Alerts are shuffled after selection so phases are interleaved, avoiding
  ordering artefacts.

---

## 7. Concurrency Design

### 7.1 The problem

CPU inference is slow (~9-27 s/alert depending on input length). Ollama can
serve several requests in parallel, so the pipeline overlaps them with a thread
pool. But parallelism must not corrupt results.

### 7.2 The correctness guarantee

The design keeps parallelism where the time is spent (the LLM calls) while
keeping all bookkeeping single-threaded and safe:

- **Worker threads** do only pure, independent work: build the prompt, call
  Ollama, parse the output. They share no mutable state.
- Each worker returns a **self-contained result** binding the prediction to its
  own alert. A prediction can never be separated from its alert.
- **All result recording** (the `EvaluationResult` harness, which is not
  thread-safe) happens on the **main thread only**, sequentially, as futures
  complete. The prediction file is guarded by a lock.

### 7.3 Determinism under concurrency

Concurrency does not affect the predictions themselves. With temperature 0,
each alert's output depends only on its own prompt, not on execution order. The
sample order in the output file may vary run-to-run, but the per-alert
predictions and the aggregate metrics are deterministic.

### 7.4 Worker count

The `--workers` flag (default 3) controls concurrency. On CPU, 2-4 is usually
optimal: Ollama already uses multiple cores per request, so too many concurrent
requests cause contention and slow the whole run down. The optimal value
depends on the machine's core count and is worth tuning on a small smoke test.

---

## 8. Dependencies and Setup

### 8.1 Ollama

Install once:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

This installs the Ollama binary and starts it as a background service.

### 8.2 The model

Pull once (~2 GB):

```bash
ollama pull llama3.2:3b
```

Verify with `ollama list`.

### 8.3 Python

No new Python packages are required beyond the standard library — the pipeline
talks to Ollama over plain HTTP using `urllib`. The evaluation harness is
imported from the existing `baselines/` package.

---

## 9. How to Run It — Step by Step

From the project root (the directory containing `ait_parser/` and `data/`):

### Step 1: Install Ollama and pull the model (one-time)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b
```

### Step 2: Run the unit tests

Validates the deterministic logic (alert representation, JSON extraction,
output normalisation, prompt structure) without needing Ollama:

```bash
cd ait_parser
python3 test_llm.py
cd ..
```

Expect 25 OK lines and `All tests passed.`

### Step 3: Build the evaluation sample

```bash
python3 ait_parser/llm/sampler.py \
    --input data/processed/alerts_labeled.jsonl \
    --output data/processed/sample_5k.jsonl \
    --profile full \
    --seed 42
```

(Use `--profile small` for the ~2,000-alert CPU-optimised sample.) Inspect the
printed `=== Sample Summary ===` to confirm the composition — in particular
that the rare phases came through in full.

### Step 4: Smoke test on 20 alerts

Validates that Ollama responds, the model returns parseable JSON, and the whole
chain works. Also reports the throughput so you can estimate the full-run time:

```bash
python3 ait_parser/run_llm_only.py \
    --input data/processed/sample_5k.jsonl \
    --output results/llm_only_smoke \
    --model llama3.2:3b \
    --workers 3 \
    --limit 20
```

### Step 5: Tune the worker count (optional)

Try `--workers 2` and `--workers 4` on the smoke test; keep whichever gives the
best `alerts/sec`.

### Step 6: Full run

```bash
python3 ait_parser/run_llm_only.py \
    --input data/processed/sample_5k.jsonl \
    --output results/llm_only \
    --model llama3.2:3b \
    --workers 3
```

The ETA printout after the first 25 alerts tells you how long it will take.

---

## 10. Outputs

After a run, the output directory contains:

### 10.1 `predictions.jsonl`

One record per alert with the full prediction:

```json
{
  "alert_id": "...",
  "scenario": "wheeler",
  "actual_is_attack": true,
  "actual_attack_phase": "wpscan",
  "predicted_is_attack": true,
  "predicted_attack_phase": "wpscan",
  "confidence": 0.85,
  "explanation": "...",
  "latency_ms": 10616.3,
  "parse_ok": true
}
```

This file is the input for the explanation-quality evaluation (M9) and for
error analysis.

### 10.2 `results.json`

The aggregate metrics: overall confusion matrix and precision/recall/F1/FPR,
plus the same broken down per scenario and per attack phase, plus wall-clock
time, throughput, worker count, malformed-output count, and the model name.

---

## 11. The Debugging Journey

The pipeline did not work on the first attempt. The path to a working system is
recorded here because it is itself a methodological contribution — and because
the fixes explain why the final design looks as it does.

### 11.1 Symptom: all-benign collapse (Mistral-7B)

The first smoke test on Mistral-7B classified all 20 alerts as benign
(precision, recall, F1 all 0.0), at ~24.9 s/alert. The all-benign result was
suspicious but could have been model conservatism.

### 11.2 Switched to Llama 3.2 3B for speed

To make iteration tractable, the model was switched to Llama 3.2 3B (~8.7
s/alert, ~3× faster). The all-benign collapse persisted, with the model now
even more confident (0.95-0.99) that everything was benign.

### 11.3 Diagnosis attempt 1: prompt calibration

Hypothesis: the model was over-conservative because it lacked base-rate
context. The prompt was rewritten to state that attacks are common and to warn
against assuming low-severity or internal-IP alerts are benign. **This did not
fix it** — the model remained all-benign.

### 11.4 The real diagnosis: the model could not see the evidence

Inspecting the model's explanations revealed the true cause. The explanations
repeatedly said things like "a low-severity IDS event with no specific rule or
signature description" and "lacks concrete indicators". The model was telling us
it could not see enough to make a decision.

Investigation of the alert representation showed that `compact_alert_text` was
including the normalised rule DESCRIPTION but NOT the raw log message. For a
wpscan probe, the description was the generic "Web server 400 error code" —
which genuinely sounds benign. The discriminating evidence (the requested URL
path `/wp-content/themes/horizon/extensions/layouts/timthumb.php`, a
notoriously vulnerable WordPress component) lived only in the raw message, which
the model never saw.

**This explained why three different configurations (Mistral, Llama, and the
recalibrated prompt) all produced the identical all-benign failure: the problem
was upstream of the model, in the data being fed to it.**

### 11.5 The fix: include the raw log message

`alert_repr.py` was rewritten to include the raw log message (truncated to 300
characters), to surface attack-indicating rule categories explicitly, and to
add the log source. The next smoke test moved from all-benign to a working
triage system: precision 1.0, recall 0.385, F1 0.556 on the 20-alert sample,
with the model now correctly naming WPScan because it could see the
`timthumb.php` request.

### 11.6 The speed fix: concurrency + sampling profile

Even working, the pipeline was slow (~10 s/alert). Two changes made the full
run tractable:

- The runner was made concurrent (thread pool, default 3 workers), overlapping
  Ollama requests for a ~3× throughput improvement.
- A `small` sampling profile was added (~2,000 alerts, reduced common-phase
  caps) as an option for faster iteration.

The full run was ultimately executed on the ~2,000-alert sample with 3 workers,
completing in ~5 hours.

---

## 12. Empirical Results

Results from the full run on the 2,013-alert evaluation sample (test split
only), Llama 3.2 3B, 3 concurrent workers.

### 12.1 Overall metrics

```
Precision:  0.781
Recall:     0.217
F1:         0.340
FPR:        0.143
Accuracy:   0.408
```

Confusion matrix: TP=307, FP=86, TN=514, FN=1106.

**Profile:** high precision, low recall. When the model flags an alert as an
attack it is usually right (78%), but it misses most attacks (only 22% recall).
It is conservative — 1,106 false negatives versus only 86 false positives.

### 12.2 Per-scenario metrics

| Scenario | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| wilson | 0.971 | 0.099 | 0.180 | 0.008 |
| wheeler | 0.828 | 0.401 | 0.540 | 0.177 |
| santos | 0.541 | 0.190 | 0.281 | 0.319 |

### 12.3 Per-phase recall — the key result

| Phase | Recall | Interpretation |
|---|---|---|
| wpscan | 0.950 | Recognised — attack signature self-evident in the raw request |
| network_scans | 0.320 | Partial |
| service_scans | 0.213 | Partial |
| reverse_shell | 0.121 | Mostly missed |
| dirb | 0.068 | Almost entirely missed |
| dnsteal | 0.050 | Almost entirely missed |
| privilege_escalation | 0.016 | Missed all but 2 of 122 |
| cracking | 0.000 | Missed all 200 |
| webshell | 0.000 | Missed all 68 |
| service_stop | 0.000 | Missed all 7 |

Precision was 1.0 on nearly every attack phase — when the model detects an
attack it rarely mislabels the phase. The false positives were concentrated in
benign alerts (santos FPR 0.319).

### 12.4 Performance

```
Sample size:        2,013 alerts
Workers:            3
Wall clock:         ~5 hours (18,014 seconds)
Throughput:         0.112 alerts/sec (wall-clock, with concurrency)
Mean latency:       26.8 s/alert (per-alert model time)
Malformed outputs:  0 / 2,013
```

The mean per-alert latency (26.8 s) and the wall-clock throughput (0.112/s ≈
9 s/alert effective) reconcile through the 3× concurrency: ~27 s of model time
per alert, three in parallel, gives ~9 s of wall-clock per alert. Zero
malformed outputs confirms the JSON extraction and `format: json` constraint
worked reliably across the whole run.

---

## 13. Interpretation and Dissertation Implications

### 13.1 The phase-dependency is the central finding

The per-phase recall table tells the dissertation's core story. The LLM-only
model, with no security context:

- **Recognises attacks that are self-evident in the raw text.** wpscan (0.95
  recall) — the suspicious URL path is visible in the raw message and the model
  can reason about it directly.
- **Fails on attacks that require knowing what the pattern means.** cracking
  (0.00), webshell (0.00), privilege_escalation (0.016), dnsteal (0.05),
  service_stop (0.00) — these require domain knowledge to recognise. A cracking
  alert (repeated auth failures), a webshell access, or a privilege-escalation
  event looks ordinary unless the analyst knows its security significance.

This phase-dependency is precisely the gap the LLM+RAG pipeline is designed to
fill: retrieving the MITRE technique, CVE, or runbook that explains what a
pattern means. When LLM+RAG improves recall on the phases where LLM-only scored
near zero, that improvement is the dissertation's central empirical finding —
and this LLM-only run provides the quantified "before" half of that comparison.

### 13.2 Comparison with the rule-based baseline

The rule-based B1 baseline achieved F1=0.833 but only by flagging ~78% of all
alerts (operationally useless despite the high F1). LLM-only achieves a lower
F1 (0.340) but far better precision (0.781 vs 0.715) and dramatically lower FPR
(0.143 vs 0.710). This is a more nuanced three-way story than a single metric
would suggest, and it reinforces the argument that F1 alone is a misleading
measure for imbalanced SOC triage.

### 13.3 The debugging journey is a methodological point

The all-benign collapse and its resolution (the raw log message being the
critical field) is itself worth reporting. It demonstrates that the
representation of an alert — what information the model is actually given —
matters as much as the model or the prompt. This is a transferable finding for
anyone applying LLMs to log or alert triage.

---

## 14. Known Limitations

To be disclosed in the dissertation.

### 14.1 Small model

Llama 3.2 3B is a small model chosen for CPU tractability. A larger model
(Mistral-7B, or a hosted frontier model) would likely achieve higher recall.
The dissertation's contribution is the *relative* comparison (LLM-only vs
LLM+RAG), which is valid regardless of absolute model capability, but the
absolute numbers would differ with a stronger model.

### 14.2 Single-alert context

The pipeline triages each alert in isolation. It has no view of the surrounding
alert stream, so it cannot recognise multi-step attack patterns that only become
apparent across a sequence of alerts. This is a deliberate scoping choice (the
rule-based and RAG pipelines share the same constraint for fair comparison), but
it limits achievable recall on phases whose individual alerts look benign.

### 14.3 Phase-labelling is secondary

The pipeline's primary metric is the binary is_attack decision. Phase labels are
recorded but their accuracy is not the focus; the model sometimes assigns a
plausible-but-wrong phase to a correctly-detected attack (e.g. labelling a
wpscan alert as webshell). This does not affect the binary evaluation.

### 14.4 Sample size

The evaluation was run on ~2,000 alerts rather than the full 1.38M test split,
for tractability. The stratified sampling preserves rare-phase representation,
but the absolute counts for the rarest phases (service_stop, n=7) are small.

---

## 15. What Comes Next

| Stage | Purpose | Status |
|---|---|---|
| LLM+RAG pipeline (`run_llm_rag.py`) | Same model + retrieved context | Built, pending run |
| Three-way comparison (`compare_pipelines.py`) | Rules vs LLM-only vs LLM+RAG | Built, pending inputs |
| Explanation-quality evaluation (M9) | Faithfulness / supportedness metrics | Pending |
| Dissertation results chapter | Write up the comparison | In progress |

The LLM+RAG pipeline reuses this pipeline's sampler, alert representation,
prompt template (with the added context section), Ollama client, concurrency
design, and evaluation harness. The only addition is the retrieval step. Running
it on the SAME sample (`sample_5k.jsonl`) with the SAME model produces the
paired comparison the dissertation needs.

---

## 16. Quick Reference: Every Command Used

```bash
# Navigate to project root
cd ~/Downloads/A\ Dessertation\ Research\ Cybersecurity/code_work

# One-time setup
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b          # (mistral was tried first, then switched)

# Unit tests
cd ait_parser && python3 test_llm.py && cd ..

# Build the evaluation sample (full profile ~4.8k, or small ~2k)
python3 ait_parser/llm/sampler.py \
    --input data/processed/alerts_labeled.jsonl \
    --output data/processed/sample_5k.jsonl \
    --profile full --seed 42

# Smoke test (20 alerts) — validate + measure throughput
python3 ait_parser/run_llm_only.py \
    --input data/processed/sample_5k.jsonl \
    --output results/llm_only_smoke \
    --model llama3.2:3b --workers 3 --limit 20

# Diagnostic: inspect predictions + explanations
python3 << 'EOF'
import json
from collections import Counter
preds = [json.loads(l) for l in open('results/llm_only_smoke/predictions.jsonl')]
print("Predicted:", Counter(p['predicted_is_attack'] for p in preds))
print("Actual:   ", Counter(p['actual_is_attack'] for p in preds))
for p in preds[:6]:
    print(p['actual_is_attack'], p['predicted_is_attack'], p['confidence'],
          repr(p['explanation'])[:150])
EOF

# Full run
python3 ait_parser/run_llm_only.py \
    --input data/processed/sample_5k.jsonl \
    --output results/llm_only \
    --model llama3.2:3b --workers 3
```

### 16.1 Actual run configuration and result

- Model: `llama3.2:3b` (temperature 0)
- Sample: 2,013 test-split alerts (stratified)
- Workers: 3
- Wall clock: ~5 hours
- Result: precision 0.781, recall 0.217, F1 0.340, FPR 0.143
- Malformed outputs: 0 / 2,013

---

*Last updated: after the full LLM-only run on 2,013 AIT-ADS test-split alerts.*
*Stage 5a (M8 Part A) of the dissertation pipeline. Author: Kumar Chaudhary
(2562392), MRes Cybersecurity, University of Wolverhampton.*
