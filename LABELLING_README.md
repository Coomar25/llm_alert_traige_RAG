# Ground-Truth Labelling — Stage 2 of the AIT-ADS Pipeline

This section documents the labelling stage that joins parsed alerts with the
ground-truth attack windows published in `labels.csv`. It is the second of
three data preparation stages:

```
Stage 1: ingest.py        ── parse 16 JSON files into a unified schema
Stage 2: label_alerts.py  ── apply ground-truth labels  ← YOU ARE HERE
Stage 3: split.py         ── train/test split (next step)
```

After this stage, every alert in the dataset carries `is_attack: bool` and
`attack_phase: str | None`, transforming a raw alert collection into a
supervised learning dataset suitable for training and evaluation.

---

## Table of Contents

1. [What This Stage Does](#1-what-this-stage-does)
2. [Why We Need Labelling](#2-why-we-need-labelling)
3. [Inputs](#3-inputs)
4. [Outputs](#4-outputs)
5. [The Labelling Algorithm](#5-the-labelling-algorithm)
6. [Code Structure](#6-code-structure)
7. [Design Decisions](#7-design-decisions)
8. [How to Run It](#8-how-to-run-it)
9. [Validation and Testing](#9-validation-and-testing)
10. [Results Summary](#10-results-summary)
11. [Severity vs Ground Truth — Key Finding](#11-severity-vs-ground-truth)
12. [Implications for the Dissertation](#12-implications-for-the-dissertation)
13. [Known Limitations](#13-known-limitations)
14. [What Comes Next](#14-what-comes-next)

---

## 1. What This Stage Does

Each alert produced by Stage 1 (`ingest.py`) emerges from the parser with two
fields set to default values:

```python
is_attack: bool = False        # parser does not know about ground truth
attack_phase: str | None = None
```

The labeller's job is to fill in those two fields by joining each alert's
`timestamp` and `scenario` against the attack-window definitions in
`labels.csv` from the AIT-ADS Zenodo release. The output is a fully labelled
dataset suitable for downstream supervised learning, evaluation, and
statistical analysis.

---

## 2. Why We Need Labelling

A supervised learning dataset requires three components: features (the alert
content), inputs (the alert records themselves), and ground-truth labels
(whether each alert corresponds to a real attack). Stage 1 produced the first
two; Stage 2 produces the third.

Without ground-truth labels:

- No precision, recall, F1-score, or false positive rate can be computed.
- No comparison between rule-based, LLM-only, and LLM+RAG pipelines is
  possible.
- The dissertation has no quantitative results.

Labelling is therefore the gating step between data preparation and
empirical evaluation.

---

## 3. Inputs

### 3.1 `data/processed/alerts.jsonl`

The output of Stage 1. One JSON record per line, in unified schema form,
preserving the original parsed JSON in a `raw_record` field. Each alert has
the fields needed for labelling already present:

- `timestamp`: ISO 8601 string in UTC (e.g., `"2022-01-15T03:45:39.681006+00:00"`)
- `scenario`: one of `fox`, `harrison`, `russellmitchell`, `santos`, `shaw`,
  `wardbeck`, `wheeler`, `wilson`

### 3.2 `data/ait-ads/labels.csv`

The ground-truth file published with AIT-ADS on Zenodo. Four columns:

```
scenario, attack, start, end
```

- `scenario`: matches the `scenario` field of alerts (one of the eight names).
- `attack`: the name of the attack phase (one of ten — see Section 5.1).
- `start`: Unix epoch seconds (UTC) marking when the attack phase began.
- `end`: Unix epoch seconds (UTC) marking when the attack phase ended.

Each row defines a half-open interval `[start, end]` during which a given
attack was executing in a given scenario.

After loading, the file contains **79 attack windows across 8 scenarios**.
Seven scenarios contain 10 windows each (one per attack phase); the
`wheeler` scenario contains 9 windows (its `cracking` phase is omitted in
the source data).

---

## 4. Outputs

After running the labeller, `data/processed/` contains the following new
files:

### 4.1 `alerts_labeled.jsonl` (~3–5 GB)

One labelled `UnifiedAlert` per line, with `is_attack` and `attack_phase`
populated. The original `raw_record` is preserved verbatim for downstream
RAG embedding. This is the primary input for the LLM/RAG pipelines.

### 4.2 `alerts_labeled.parquet` (~300 MB)

Flat columnar form of the same data, **without** `raw_record` and with list
fields joined by semicolons. This is the input for traditional ML baselines
(rule-based scoring, Random Forest, SVM) and statistical analysis tools
like Pandas.

If `pyarrow` is not installed, `alerts_labeled.csv` is written as a
fallback (~2 GB, slower to load).

### 4.3 `label_stats.json`

A summary of the labelling run containing:

- `input_alerts`: total alerts processed
- `is_attack_true` / `is_attack_false`: attack vs benign counts
- `attack_ratio`: fraction of alerts inside any attack window
- `unknown_scenario_count`: alerts whose scenario does not appear in
  `labels.csv` (should be 0)
- `by_scenario`: per-scenario breakdown of attack/benign counts and ratios
- `by_attack_phase`: per-phase counts across all scenarios
- `by_scenario_phase`: cross-tabulation of scenario × attack phase
- `severity_x_attack`: cross-tabulation of normalised severity × is_attack
  (see Section 11 — one of the dissertation's key empirical findings)
- `labels_summary`: counts and types loaded from `labels.csv`
- `output_format`: `"parquet"` or `"csv"`

The numbers in this file are dissertation-grade; they are cited verbatim in
the methodology and results chapters.

---

## 5. The Labelling Algorithm

### 5.1 Attack Phases

The ten attack phases in AIT-ADS correspond to standard penetration-testing
sequence steps. Each maps to a MITRE ATT&CK tactic, useful for the RAG
knowledge base:

| Phase                  | MITRE Tactic           | Typical Duration |
|------------------------|------------------------|------------------|
| `network_scans`        | T1046 Network Scanning | minutes          |
| `service_scans`        | T1046 Network Scanning | seconds–minutes  |
| `dirb`                 | T1595 Active Scanning  | **~20 minutes**  |
| `wpscan`               | T1595 Active Scanning  | seconds–minutes  |
| `webshell`             | T1505.003 Web Shell    | seconds          |
| `cracking`             | T1110 Brute Force      | minutes          |
| `reverse_shell`        | T1059 Command-Line     | ~30 seconds      |
| `privilege_escalation` | T1068 Privilege Escal. | ~30 seconds      |
| `service_stop`         | T1489 Service Stop     | ~2 seconds       |
| `dnsteal`              | T1048 Exfiltration     | minutes          |

The wide variation in phase duration has major consequences for the label
distribution — see Section 11.

### 5.2 The Decision Rule

For each alert, the labeller answers two questions:

1. Is there an attack window in this alert's scenario that contains this
   alert's timestamp?
2. If so, which one?

Concretely:

```
for each alert in alerts.jsonl:
    epoch  = parse_iso_timestamp(alert.timestamp)
    windows = labels_csv.windows_for[alert.scenario]
    for window in windows:
        if window.start <= epoch <= window.end:
            alert.is_attack    = True
            alert.attack_phase = window.attack
            break
    else:
        alert.is_attack    = False
        alert.attack_phase = None
```

Boundaries are **inclusive on both ends**: an alert firing exactly at
`start` or exactly at `end` is considered inside the attack. This is the
standard convention in academic intrusion-detection evaluation and is
consistent with how the AIT-ADS authors define the dataset.

### 5.3 Overlap Handling

The attack windows in `labels.csv` are sequential and non-overlapping in
practice. However, when two adjacent windows share a boundary (e.g.,
`network_scans` ends at `1642508220` and `service_scans` starts at
`1642508220`), an alert at exactly that boundary epoch belongs to both
intervals under inclusive comparison.

The labeller resolves this by **taking the first match**, where "first" is
defined by sorting windows by `start_epoch` ascending. This is a stable,
documented choice. In the AIT-ADS data this affects fewer than 10 alerts in
the entire 2.6M-record dataset, so the choice has no material impact on
results — but the algorithm is fully deterministic.

---

## 6. Code Structure

The labelling stage adds three new files alongside the existing parser:

```
ait_parser/
├── ...
├── label_alerts.py               ← entry point (this stage)
├── test_labeller.py              ← assertion-based smoke test
└── labeller/
    ├── __init__.py
    ├── labels_loader.py          ← parse labels.csv into a per-scenario lookup
    └── label_engine.py           ← match an alert against a scenario's windows
```

### 6.1 `labeller/labels_loader.py`

Parses `labels.csv` into a `Dict[str, List[AttackWindow]]` keyed by
scenario name. The `AttackWindow` dataclass holds:

- `scenario`, `attack` (strings)
- `start_epoch`, `end_epoch` (floats — fast numeric comparison)
- `start_utc`, `end_utc` (datetime objects — for logging/diagnostics)
- `contains(epoch) -> bool` helper

Windows within each scenario are sorted ascending by `start_epoch` at load
time, which enables the deterministic first-match behaviour described in
Section 5.3.

Validates that `start <= end` for every row and raises `ValueError` on
malformed input — the CSV is small (79 rows) so we want loud, immediate
failure rather than silent skipping.

### 6.2 `labeller/label_engine.py`

The core decision function:

```python
def label_alert(timestamp_epoch, scenario, windows_for_scenario):
    if not windows_for_scenario:
        return False, None
    for window in windows_for_scenario:
        if window.contains(timestamp_epoch):
            return True, window.attack
    return False, None
```

Three properties worth noting:

1. **Pure function.** No global state, no I/O. Easy to test in isolation
   (see Section 9).
2. **Defensive about missing scenarios.** If an alert's scenario doesn't
   appear in `labels.csv`, it is silently labelled as benign and counted in
   `unknown_scenario_count`. In our run, this counter was zero — every
   scenario in alerts matched a scenario in labels.
3. **Linear scan.** For each alert we scan all 10 windows of its scenario.
   With ~10 windows per scenario and 2.6M alerts, this is ~26M comparisons
   total — completes in under 5 minutes on a typical laptop.

### 6.3 `label_alerts.py`

The orchestrator. Streams `alerts.jsonl` line by line, applies labels,
writes JSONL and parquet/CSV outputs, and accumulates the statistics
dictionary that becomes `label_stats.json`.

Key design choices:

- **Streaming reads, batched writes.** The JSONL output is appended one
  line at a time so memory use stays constant regardless of input size.
  Flat rows are accumulated in memory before parquet write (acceptable
  for 2.6M records on a 4 GB+ RAM machine).
- **Defensive timestamp parsing.** Alerts with malformed timestamps are
  skipped silently — the parser shouldn't produce these but defensive code
  is cheap.
- **No mutation of source data.** Reads `alerts.jsonl`, writes
  `alerts_labeled.jsonl` — the unlabelled input remains intact in case
  re-labelling is needed.

---

## 7. Design Decisions

These decisions are documented explicitly so they can be defended in the
dissertation viva.

### 7.1 Boundary Inclusivity (closed interval)

We chose `start <= timestamp <= end` rather than `start <= timestamp < end`.
The closed-interval convention is standard in academic IDS evaluation
(Khraisat et al., 2019) and is consistent with the AIT-ADS authors' own
documentation. The choice affects fewer than 10 alerts in the entire
dataset.

### 7.2 Timezone Handling

Unix epoch seconds are timezone-agnostic by definition. The parser stores
all alert timestamps as UTC `datetime` objects, which round-trip cleanly to
epoch seconds via `datetime.timestamp()`. No timezone conversion is
performed anywhere in the labeller — both inputs are already in the same
universal reference frame.

### 7.3 First-Match Resolution on Overlapping Windows

When boundary epochs collide between adjacent phases, the alert is assigned
to the *earlier* phase (by `start_epoch`). This is deterministic and
documented but represents a judgement call — an alternative would be to
take the *later* phase, on the argument that the new phase has just begun.
We chose the first-match rule because it's simpler to test and audit, and
the empirical impact is negligible.

### 7.4 Scenarios Absent from labels.csv

If an alert's scenario does not appear in `labels.csv`, the alert is
labelled as benign rather than failing. The `unknown_scenario_count` field
in stats lets us audit this — in our actual run it was zero.

### 7.5 Two Output Formats

Same rationale as the parser stage: JSONL preserves the nested record for
LLM/RAG embedding; parquet/CSV provides a flat columnar view for
traditional ML and statistical analysis. Producing both from one pass
avoids re-processing 2.6M records later.

---

## 8. How to Run It

From your project root (directory containing `ait_parser/` and `data/`):

### Step 1: Run the labeller unit tests

Validates the algorithm on synthetic fixtures with no need for real data:

```bash
cd ait_parser
python3 test_labeller.py
cd ..
```

Expected output:

```
  Load OK: 2 scenarios, 5 total windows
  Sort OK: windows are chronologically sorted within each scenario
  Inside-window OK: ts=1642507500 → is_attack=True, phase=network_scans
  Start-boundary OK: ts=1642507140 (window start) → is_attack=True
  End-boundary OK: ts=1642508220 (boundary) → is_attack=True, phase=network_scans
  Outside-window OK: ts=1640000000 (before any window) → is_attack=False
  Unknown-scenario OK: wilson not in labels → is_attack=False, phase=None
  Second-window OK: ts=1642508250 → is_attack=True, phase=service_scans
  AttackWindow.contains OK: boundaries inclusive, outside excluded
  Summary OK: 5 windows, 3 unique attack types
  Timezone round-trip OK: UTC datetime ↔ epoch consistent

All tests passed.
```

If any test fails, do not proceed — the labeller has a bug and would mislabel
the full dataset.

### Step 2: Small smoke test on real data

Process the first 5,000 alerts only — completes in seconds:

```bash
python3 ait_parser/label_alerts.py \
    --alerts data/processed/alerts.jsonl \
    --labels data/ait-ads/labels.csv \
    --output data/processed_labelled_smoketest \
    --limit 5000
```

Inspect the resulting `data/processed_labelled_smoketest/label_stats.json`.
The `attack_ratio` will be unusual (because the first 5,000 alerts all come
from one scenario), but the run should complete without errors and
`unknown_scenario_count` should be `0`.

### Step 3: Full labelling run

```bash
python3 ait_parser/label_alerts.py \
    --alerts data/processed/alerts.jsonl \
    --labels data/ait-ads/labels.csv \
    --output data/processed
```

Expected runtime: **3–6 minutes** on a typical laptop. The script prints
progress every 100,000 alerts.

When it finishes, four files exist in `data/processed/`:

```
alerts_labeled.jsonl      ← labelled alerts in nested form
alerts_labeled.parquet    ← labelled alerts in flat form
label_stats.json          ← summary statistics
```

(Plus the original `alerts.jsonl` and `alerts.parquet` from Stage 1, kept
intact.)

---

## 9. Validation and Testing

The labeller is validated through three independent mechanisms:

### 9.1 Unit tests (`test_labeller.py`)

Eleven assertion-based tests cover:

1. CSV loading and structural integrity
2. Chronological sorting of windows within each scenario
3. Inside-window matching
4. Start-boundary inclusivity
5. End-boundary inclusivity (including overlap handling)
6. Outside-window detection (timestamp before any window)
7. Unknown-scenario handling
8. Multi-window scenarios (sequential phases)
9. The `AttackWindow.contains()` helper
10. The summary statistics function
11. Timezone round-trip consistency

All eleven tests pass on the current implementation.

### 9.2 Self-consistency check (`label_stats.json`)

The orchestrator validates internal consistency at run time:

- `input_alerts == is_attack_true + is_attack_false`
- Sum of `by_scenario` totals equals `input_alerts`
- Sum of `by_attack_phase` counts equals `is_attack_true`
- `unknown_scenario_count` should equal zero (every alert's scenario must
  exist in `labels.csv`)

In the actual run, all four invariants hold.

### 9.3 Domain sanity check

The empirical `by_attack_phase` distribution matches the expected duration
of each phase. `dirb` (longest phase at ~20 minutes) produces the most
labels; `service_stop` (shortest at ~2 seconds) produces the fewest. This
ordering is exactly what physics demands and provides independent evidence
the labeller is working correctly.

---

## 10. Results Summary

Numbers from the actual run on the full 2,655,821-alert dataset.

### 10.1 Aggregate counts

```
Total alerts:        2,655,821
Attack-labelled:     1,764,581   (66.4%)
Benign-labelled:       891,240   (33.6%)
Unknown scenarios:           0
```

### 10.2 Per-scenario attack ratios

| Scenario          | Total alerts | Attack | Benign | Attack ratio |
|-------------------|-------------:|-------:|-------:|-------------:|
| `fox`             | 473,104      | 421,653 | 51,451 | **89.1%** |
| `harrison`        | 593,948      | 431,492 | 162,456 | 72.6% |
| `wheeler`         | 616,161      | 432,334 | 183,827 | 70.2% |
| `wilson`          | 634,246      | 440,108 | 194,138 | 69.4% |
| `russellmitchell` | 45,544       | 12,015 | 33,529 | 26.4% |
| `santos`          | 130,779      | 13,004 | 117,775 | 9.9% |
| `shaw`            | 70,782       | 6,935 | 63,847 | 9.8% |
| `wardbeck`        | 91,257       | 7,040 | 84,217 | **7.7%** |

The variance is striking: attack ratio ranges from 7.7% (`wardbeck`) to
89.1% (`fox`). The four attack-heavy scenarios (`fox`, `harrison`,
`wheeler`, `wilson`) account for the vast majority of attack labels; the
four attack-light scenarios are dominated by benign background traffic.

### 10.3 Per-phase distribution

```
dirb:                 1,690,144   (95.8% of attack labels)
wpscan:                  55,606
dnsteal:                  8,630
cracking:                 5,396
service_scans:            2,580
network_scans:            1,624
privilege_escalation:       352
webshell:                   127
reverse_shell:              101
service_stop:                21
```

The `dirb` phase alone produces 96% of all attack labels because the dirb
tool brute-forces web directories continuously for ~20 minutes per scenario,
generating millions of HTTP-policy alerts that fall within its window. In
contrast, short-duration phases like `service_stop` (~2 seconds) and
`reverse_shell` (~30 seconds) produce far fewer labels despite being more
operationally critical from a security standpoint.

**This distribution must be acknowledged in the evaluation methodology.**
Reporting only aggregate precision/recall would let `dirb` dominate the
score; per-phase metrics are required to avoid masking poor performance on
the rare-but-critical phases.

---

## 11. Severity vs Ground Truth — Key Finding

The single most important table in `label_stats.json` is the cross-tabulation
of normalised severity against attack labels:

| Normalised severity | Attack | Benign  | Attack ratio |
|---------------------|-------:|--------:|-------------:|
| 1 (informational)   | 7,217 | 283,609 | 2.5% |
| 2 (low)             | 1,587,101 | 500,843 | **76.0%** |
| 3 (medium)          | 47,128 | 4,320 | 92.0% |
| 4 (high)            | 122,997 | 102,456 | **54.6%** |
| 5 (critical)        | 138 | 12 | 92.0% |

**Two observations have direct dissertation implications:**

### 11.1 Severity 2 (low) is not low

76% of severity-2 alerts fall inside an attack window. The "low" severity
designation made by Wazuh and Suricata reflects *rule semantics* (this
matched a low-priority policy rule) but not *operational relevance*. The
dirb scans that drive most attack labels fire as severity-2 HTTP-policy
alerts. A SOC analyst who deprioritises severity-2 alerts misses the
majority of active attack traffic.

### 11.2 Severity 4 (high) is barely better than random

Only 55% of severity-4 alerts are inside attack windows — meaning 45% of
"high severity" alerts are false positives even with perfect ground-truth
labelling. This is empirical confirmation of the alert-fatigue thesis: SOC
analysts triaging by severity alone are wrong nearly half the time on
high-severity events.

### 11.3 Severity 5 (critical) is reliable but rare

92% of severity-5 alerts are real, but there are only 150 of them across
2.6 million records (0.006% of all alerts). When severity-5 fires, it is
highly trustworthy — but it fires so rarely that it cannot drive a SOC's
overall workflow.

**This single table is a dissertation result in its own right.** It
empirically demonstrates that native IDS severity is a poor proxy for
operational relevance and motivates the need for context-aware,
retrieval-grounded triage systems — which is precisely the contribution
this dissertation proposes.

---

## 12. Implications for the Dissertation

The labelling results affect several downstream chapters:

### 12.1 Methodology chapter (Chapter 3)

A new subsection (3.4 Ground-truth labelling) covers the algorithm, the
boundary convention, the timezone handling, and the overlap-resolution rule.
The aggregate counts and the `attack_ratio` are cited as dataset
characteristics. The empirical attack-phase duration variance is discussed
as motivation for per-phase evaluation.

### 12.2 Evaluation strategy

Two consequences:

1. **Per-phase metrics are mandatory.** Aggregate precision/recall would let
   `dirb` dominate; per-phase reporting is required to evaluate performance
   on rare phases like `privilege_escalation` and `webshell`.
2. **Stratified scenario split.** Random scenario assignment to train/test
   would risk all attack-heavy scenarios landing in one split. The
   recommended allocation is:
   - **Train:** `fox`, `harrison`, `russellmitchell`, `shaw`, `wardbeck`
     (5 scenarios, mix of attack-heavy and attack-light)
   - **Test:** `wheeler`, `wilson`, `santos` (3 scenarios, mix)

   This ensures both splits contain attack-heavy and attack-light data,
   forcing the model to generalise rather than memorise scenario-level
   patterns.

### 12.3 Results chapter

The severity-vs-attack cross-tabulation (Section 11) becomes a results
finding in its own right, used to:

- Motivate the dissertation's central hypothesis (that rule-based severity
  is insufficient).
- Provide a baseline against which the LLM+RAG system's performance is
  measured.
- Justify the focus on explainability — even severity-4 alerts have a
  ~45% false positive rate, so analysts need richer context to triage
  effectively.

---

## 13. Known Limitations

These should be acknowledged explicitly in the dissertation's limitations
section.

### 13.1 Phase-duration bias

`dirb` produces 96% of attack labels purely because it runs for 20 minutes
while other phases run for seconds. This biases naive aggregate metrics
toward dirb performance. The dissertation mitigates this through per-phase
evaluation, but the label distribution itself remains skewed.

### 13.2 Closed-interval choice

An alert firing at exactly the millisecond a phase starts or ends is
included in that phase. Alternative conventions (half-open intervals, fuzzy
windows) would produce slightly different label counts. The choice was made
for consistency with academic IDS evaluation literature and the affected
alert count is negligible (<10 across 2.6M records).

### 13.3 No correlation between phases

Each alert is labelled in isolation against its scenario's windows. The
labeller does not attempt to identify multi-step attack chains. This is
intentional: the LLM+RAG system is meant to perform that correlation, and
labelling decisions made by the ground-truth pipeline should not pre-empt
that capability.

### 13.4 Phase-window definitions are authoritative

The labeller treats `labels.csv` as ground truth. If the AIT-ADS authors
mis-recorded a phase boundary by a few seconds, those errors propagate into
the labels and ultimately into evaluation. Cross-validation against the
original AIT-LDS v2 dataset (the raw logs from which AIT-ADS was generated)
could detect such errors but is beyond the dissertation's scope.

---

## 14. What Comes Next

With Stage 2 complete, the labelled dataset is ready for evaluation. The
remaining stages are:

| Stage | Purpose | Status |
|-------|---------|--------|
| Stratified train/test split | Build scenario-level splits with balanced phase representation | Next |
| Rule-based baseline | First comparison number (severity thresholds + simple correlation) | After split |
| Knowledge base construction | CVE + MITRE ATT&CK + runbooks in ChromaDB | Parallel to baseline |
| LLM-only pipeline | Mistral-7B without retrieval (ablation) | After KB |
| LLM + RAG pipeline | Full proposed system | After LLM-only |
| Cross-pipeline evaluation | Precision, recall, F1, FPR, latency | After all three pipelines |

The rule-based baseline runs on the full labelled dataset (no LLM
inference, so 2.6M records is fast). The LLM pipelines will require
subsampling — likely a stratified sample of ~50,000 alerts that preserves
both scenario diversity and phase representation — because Mistral-7B
inference at consumer-GPU speed would take days to process the full
dataset.

---

## Citation

When referring to the labelling stage in the dissertation:

> Ground-truth labels were applied to each alert by joining its UTC
> timestamp against the attack windows defined in `labels.csv` (Landauer et
> al., 2024). An alert is labelled as `is_attack = True` and tagged with the
> corresponding `attack_phase` if and only if its timestamp falls within
> the closed interval [start, end] of any attack window for its scenario.
> Of 2,655,821 alerts, 1,764,581 (66.4%) fell within an attack window. The
> attack distribution across phases is heavily skewed by phase duration:
> the `dirb` directory enumeration phase alone accounts for 95.8% of
> attack-labelled alerts, reflecting the high alert volume generated by a
> sustained 20-minute brute-force scan.

### Key reference

Landauer, M., Skopik, F., & Wurzenberger, M. (2024). Introducing a new
alert data set for multi-step attack analysis. In *Proceedings of the 17th
Cyber Security Experimentation and Test Workshop (CSET '24)* (pp. 41–53).
ACM. https://doi.org/10.1145/3675741.3675748

---

*Last updated: after the full labelling run on 2,655,821 AIT-ADS alerts.*
*Stage 2 of the data preparation pipeline. Author: Kumar Chaudhary (2562392).*
