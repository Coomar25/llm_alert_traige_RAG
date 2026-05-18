"""
run_baseline.py — Run the rule-based baselines on the labelled dataset.

Workflow:
    1. Stream alerts_labeled.jsonl line by line.
    2. For each alert, determine which split (train/test) it belongs to.
    3. Run B1 (severity threshold) and B2 (severity + groups + burst).
    4. Record predictions in an EvaluationResult.
    5. Compute precision, recall, F1, FPR — overall, per scenario, per phase.
    6. Sweep severity thresholds 2/3/4/5 on the train split for B1 to find
       the best F1, then apply that threshold to the test split for the
       final reported number.
    7. Write everything to results/baselines/.

Usage:
    python run_baseline.py \\
        --input data/processed/alerts_labeled.jsonl \\
        --output results/baselines

Outputs:
    results/baselines/b1_results.json       — B1 results across thresholds + final
    results/baselines/b2_results.json       — B2 results (single config)
    results/baselines/summary.json          — headline numbers for both baselines
    results/baselines/console_log.txt       — what was printed to stderr

Performance:
    ~3–5 minutes on a typical laptop for 2.6M alerts. Pure Python, no GPU.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Iterable

from baselines import (
    TRAIN_SCENARIOS, TEST_SCENARIOS, split_of, validate_splits,
    EvaluationResult, B1Config, B2Config, B2Predictor, predict_b1,
    format_headline,
)


def iter_labeled_alerts(path: Path) -> Iterable[dict]:
    """Stream labelled alerts from the JSONL file produced by label_alerts.py."""
    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def ts_to_epoch(ts_str: str) -> float:
    """Convert ISO 8601 timestamp string to Unix epoch seconds."""
    return datetime.fromisoformat(ts_str).timestamp()


def run_b1_at_threshold(input_path: Path, threshold: int) -> tuple:
    """Run B1 at a given threshold; return (train_result, test_result)."""
    config = B1Config(severity_threshold=threshold)
    train_result = EvaluationResult(
        pipeline_name=f"B1_threshold_{threshold}", split_name="train"
    )
    test_result = EvaluationResult(
        pipeline_name=f"B1_threshold_{threshold}", split_name="test"
    )

    for alert in iter_labeled_alerts(input_path):
        scenario = alert.get("scenario", "")
        split = split_of(scenario)
        if split == "unknown":
            continue

        # Predict
        t0 = time.perf_counter()
        predicted = predict_b1(alert, config)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        actual = bool(alert.get("is_attack", False))
        phase = alert.get("attack_phase")

        result = train_result if split == "train" else test_result
        result.record(predicted, actual, scenario, phase, latency_ms)

    return train_result, test_result


def run_b2(input_path: Path, config: B2Config) -> tuple:
    """Run B2 with a given config; return (train_result, test_result)."""
    # B2 is stateful (burst tracking) so we use a single predictor but reset
    # between train and test runs. To do this cleanly without two passes
    # over the data, we'd need to sort by split. Simpler approach: keep
    # separate predictors for train and test scenarios. Burst state is
    # per-scenario already, so this is correct.
    train_predictor = B2Predictor(config)
    test_predictor = B2Predictor(config)

    train_result = EvaluationResult(pipeline_name="B2", split_name="train")
    test_result = EvaluationResult(pipeline_name="B2", split_name="test")

    for alert in iter_labeled_alerts(input_path):
        scenario = alert.get("scenario", "")
        split = split_of(scenario)
        if split == "unknown":
            continue

        ts_str = alert.get("timestamp")
        if not ts_str:
            continue
        try:
            ts_epoch = ts_to_epoch(ts_str)
        except (ValueError, TypeError):
            continue

        predictor = train_predictor if split == "train" else test_predictor
        result = train_result if split == "train" else test_result

        t0 = time.perf_counter()
        predicted = predictor.predict(alert, ts_epoch)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        actual = bool(alert.get("is_attack", False))
        phase = alert.get("attack_phase")
        result.record(predicted, actual, scenario, phase, latency_ms)

    return train_result, test_result


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, type=Path,
                    help="Path to alerts_labeled.jsonl")
    ap.add_argument("--output", required=True, type=Path,
                    help="Directory to write results JSON files")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"ERROR: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    args.output.mkdir(parents=True, exist_ok=True)
    validate_splits()

    print(f"Reading from: {args.input}", file=sys.stderr)
    print(f"Writing to:   {args.output}", file=sys.stderr)
    print(f"Train scenarios: {sorted(TRAIN_SCENARIOS)}", file=sys.stderr)
    print(f"Test scenarios:  {sorted(TEST_SCENARIOS)}", file=sys.stderr)
    print("", file=sys.stderr)

    # ===========================================================================
    # B1 — sweep thresholds 2..5 on train, report each, then pick best by train F1
    # ===========================================================================
    print("=" * 70, file=sys.stderr)
    print("B1: severity-threshold baseline (sweep thresholds)", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    b1_runs = {}
    for T in [2, 3, 4, 5]:
        print(f"\n  Running B1 with threshold = {T} ...", file=sys.stderr)
        train_r, test_r = run_b1_at_threshold(args.input, T)
        print(f"    {format_headline(train_r)}", file=sys.stderr)
        print(f"    {format_headline(test_r)}", file=sys.stderr)
        b1_runs[T] = {
            "threshold": T,
            "train": train_r.to_dict(),
            "test": test_r.to_dict(),
        }

    # Pick best threshold by train F1
    best_T = max(b1_runs.keys(), key=lambda t: b1_runs[t]["train"]["overall"]["f1"])
    print(f"\n  Best B1 threshold (by train F1): T = {best_T}", file=sys.stderr)
    print(f"  Final B1 (test split, T={best_T}): F1 = {b1_runs[best_T]['test']['overall']['f1']:.4f}",
          file=sys.stderr)

    b1_output = {
        "description": "B1 = severity-threshold baseline. Threshold tuned on train, reported on test.",
        "thresholds_tested": list(b1_runs.keys()),
        "best_threshold_by_train_f1": best_T,
        "runs": b1_runs,
        "final_test_result": b1_runs[best_T]["test"],
    }
    (args.output / "b1_results.json").write_text(json.dumps(b1_output, indent=2))

    # ===========================================================================
    # B2 — severity + rule groups + source-IP burst correlation
    # ===========================================================================
    print("\n" + "=" * 70, file=sys.stderr)
    print("B2: severity + rule-groups + source-IP burst correlation", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    b2_config = B2Config(
        severity_threshold=best_T,  # use the tuned threshold
        burst_count=10,
        burst_window_seconds=60,
    )
    print(f"  Config: threshold={b2_config.severity_threshold}, "
          f"burst={b2_config.burst_count}/{b2_config.burst_window_seconds}s",
          file=sys.stderr)

    b2_train, b2_test = run_b2(args.input, b2_config)
    print(f"  {format_headline(b2_train)}", file=sys.stderr)
    print(f"  {format_headline(b2_test)}", file=sys.stderr)

    b2_output = {
        "description": "B2 = severity threshold + known-bad rule groups + source-IP burst correlation.",
        "config": {
            "severity_threshold": b2_config.severity_threshold,
            "burst_count": b2_config.burst_count,
            "burst_window_seconds": b2_config.burst_window_seconds,
        },
        "train": b2_train.to_dict(),
        "test": b2_test.to_dict(),
    }
    (args.output / "b2_results.json").write_text(json.dumps(b2_output, indent=2))

    # ===========================================================================
    # Summary
    # ===========================================================================
    summary = {
        "B1": {
            "best_threshold": best_T,
            "test_precision": b1_runs[best_T]["test"]["overall"]["precision"],
            "test_recall":    b1_runs[best_T]["test"]["overall"]["recall"],
            "test_f1":        b1_runs[best_T]["test"]["overall"]["f1"],
            "test_fpr":       b1_runs[best_T]["test"]["overall"]["false_positive_rate"],
            "test_mean_latency_ms": b1_runs[best_T]["test"]["mean_latency_ms"],
            "test_n_alerts":  b1_runs[best_T]["test"]["n_alerts"],
        },
        "B2": {
            "test_precision": b2_test.overall.precision,
            "test_recall":    b2_test.overall.recall,
            "test_f1":        b2_test.overall.f1,
            "test_fpr":       b2_test.overall.false_positive_rate,
            "test_mean_latency_ms": b2_test.mean_latency_ms,
            "test_n_alerts":  b2_test.n_alerts,
        },
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2, default=str))

    print("\n" + "=" * 70, file=sys.stderr)
    print("FINAL TEST-SET RESULTS", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(json.dumps(summary, indent=2, default=str), file=sys.stderr)


if __name__ == "__main__":
    main()
