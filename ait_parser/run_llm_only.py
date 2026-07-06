"""
run_llm_only.py — LLM-only triage pipeline (no retrieval), concurrent.

This is the ablation baseline: the model reasons about each alert using only
its pre-trained knowledge, with no retrieved context. Comparing this against
LLM+RAG isolates the contribution of retrieval.

Concurrency design (correctness-critical)
-----------------------------------------
LLM inference on CPU is slow (~8-11s/alert). Ollama can serve several
requests in parallel, so we use a thread pool to overlap them. But
parallelism must not corrupt results. The design guarantees correctness:

    - Worker threads do ONLY the pure, independent work: build the prompt,
      call Ollama, parse the output. They share no mutable state.
    - Each worker returns a (alert, prediction) PAIR, so a prediction can
      never be separated from its own alert.
    - ALL result recording (the EvaluationResult harness, which is NOT
      thread-safe) happens on the MAIN thread only, sequentially, as
      futures complete.

This keeps the parallelism where the time goes (inference) while keeping the
bookkeeping single-threaded and safe.

Determinism note
----------------
Concurrency does not affect the predictions themselves — temperature is 0,
so each alert's output depends only on its own prompt, not on execution
order. The sample order in the output file may differ run-to-run, but the
per-alert predictions and the aggregate metrics are deterministic.

Usage
-----
    python run_llm_only.py \\
        --input data/processed/sample_2k.jsonl \\
        --output results/llm_only \\
        --model llama3.2:3b \\
        --workers 3

    # Test on the first 20 alerts before the full run
    python run_llm_only.py --input ... --output ... --limit 20 --workers 3

The evaluation harness (ConfusionMatrix, EvaluationResult) is imported from
baselines/ — built once in M6, reused unchanged. This guarantees the LLM
pipeline is scored on identical metric definitions as the rule-based baseline.

python3 ait_parser/run_llm_only.py \
    --input data/processed/sample_5k.jsonl \
    --output results/llm_only \
    --model llama3.2:3b \
    --workers 3
"""

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Reuse the baseline evaluation harness and split logic
sys.path.insert(0, str(Path(__file__).parent.parent))
from baselines.evaluation import EvaluationResult, format_headline
from baselines.splits import split_of

from llm import (
    compact_alert_text, build_llm_only_prompt, normalise_llm_output,
    generate, check_ollama, DEFAULT_MODEL, DEFAULT_OLLAMA_URL,
)


def iter_alerts(path: Path):
    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def infer_one(alert: dict, model: str, url: str) -> dict:
    """Pure worker function: run one alert through the model.

    Returns a self-contained result dict binding the prediction to its alert.
    No shared state is touched here — safe to run in parallel.
    """
    alert_text = compact_alert_text(alert)
    prompt = build_llm_only_prompt(alert_text)
    resp = generate(prompt, model=model, url=url)
    pred = normalise_llm_output(resp.parsed_json)

    return {
        "alert_id": alert.get("alert_id", ""),
        "scenario": alert.get("scenario", ""),
        "actual_is_attack": bool(alert.get("is_attack", False)),
        "actual_attack_phase": alert.get("attack_phase"),
        "predicted_is_attack": pred["is_attack"],
        "predicted_attack_phase": pred["attack_phase"],
        "confidence": pred["confidence"],
        "explanation": pred["explanation"],
        "latency_ms": round(resp.latency_ms, 1),
        "parse_ok": resp.parse_ok,
        "malformed": pred["_malformed"] or not resp.parse_ok,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, type=Path,
                    help="Sampled alerts JSONL (from sampler.py)")
    ap.add_argument("--output", required=True, type=Path,
                    help="Output directory for predictions and results")
    ap.add_argument("--model", default=DEFAULT_MODEL,
                    help=f"Ollama model name (default {DEFAULT_MODEL})")
    ap.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    ap.add_argument("--workers", type=int, default=3,
                    help="Number of concurrent inference requests (default 3). "
                         "On CPU, 2-4 is usually optimal; more causes contention.")
    ap.add_argument("--limit", type=int, default=None,
                    help="Process only the first N alerts (for testing)")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"ERROR: input not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    args.output.mkdir(parents=True, exist_ok=True)

    # ---- Health check ----
    print("Checking Ollama...", file=sys.stderr)
    ok, msg = check_ollama(model=args.model, url=args.ollama_url)
    print(f"  {msg}", file=sys.stderr)
    if not ok:
        print("ERROR: Ollama health check failed. Is it running? "
              "Did you `ollama pull` the model?", file=sys.stderr)
        sys.exit(1)

    # ---- Load alerts (test-split only, honour --limit) ----
    alerts = []
    for alert in iter_alerts(args.input):
        if split_of(alert.get("scenario", "")) != "test":
            continue
        alerts.append(alert)
        if args.limit is not None and len(alerts) >= args.limit:
            break
    print(f"\nLoaded {len(alerts)} test-split alerts for inference.",
          file=sys.stderr)
    print(f"Running LLM-only triage with model '{args.model}' "
          f"using {args.workers} concurrent workers...", file=sys.stderr)

    # ---- Concurrent inference, sequential aggregation ----
    result = EvaluationResult(pipeline_name="LLM-only", split_name="test")
    predictions_path = args.output / "predictions.jsonl"
    n_malformed = 0
    n_done = 0
    t_start = time.perf_counter()

    # We write predictions as they complete. A lock guards the file handle
    # and the counters — but NOT the model calls (those are in the workers).
    write_lock = threading.Lock()

    with predictions_path.open("w") as pred_f:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            # Submit all alerts
            future_to_alert = {
                pool.submit(infer_one, alert, args.model, args.ollama_url): alert
                for alert in alerts
            }

            # Collect as they finish — this loop runs on the MAIN thread,
            # so result.record() and file writes are serialised and safe.
            for future in as_completed(future_to_alert):
                rec = future.result()

                # Record into the shared evaluation harness (main thread only)
                result.record(
                    predicted_attack=rec["predicted_is_attack"],
                    actual_attack=rec["actual_is_attack"],
                    scenario=rec["scenario"],
                    attack_phase=rec["actual_attack_phase"],
                    latency_ms=rec["latency_ms"],
                )
                if rec["malformed"]:
                    n_malformed += 1

                # Persist the full prediction record
                with write_lock:
                    pred_f.write(json.dumps({
                        k: v for k, v in rec.items() if k != "malformed"
                    }, default=str) + "\n")

                n_done += 1
                if n_done % 25 == 0:
                    elapsed = time.perf_counter() - t_start
                    rate = n_done / elapsed if elapsed > 0 else 0
                    eta = (len(alerts) - n_done) / rate if rate > 0 else 0
                    print(f"  ... {n_done}/{len(alerts)} done "
                          f"({rate:.2f} alerts/sec, "
                          f"ETA {eta/60:.1f} min, "
                          f"{n_malformed} malformed)", file=sys.stderr)

    elapsed = time.perf_counter() - t_start

    # ---- Results ----
    results_dict = result.to_dict()
    results_dict["malformed_outputs"] = n_malformed
    results_dict["wall_clock_seconds"] = round(elapsed, 1)
    results_dict["throughput_alerts_per_second"] = round(n_done / elapsed, 3) if elapsed else 0
    results_dict["workers"] = args.workers
    results_dict["model"] = args.model

    (args.output / "results.json").write_text(
        json.dumps(results_dict, indent=2, default=str))

    print("\n" + "=" * 70, file=sys.stderr)
    print("LLM-ONLY RESULTS", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"  {format_headline(result)}", file=sys.stderr)
    print(f"  Malformed outputs: {n_malformed}/{n_done}", file=sys.stderr)
    if elapsed:
        print(f"  Wall clock: {elapsed:.0f}s "
              f"({n_done / elapsed:.2f} alerts/sec with {args.workers} workers)",
              file=sys.stderr)
    print(f"\n  Predictions: {predictions_path}", file=sys.stderr)
    print(f"  Results:     {args.output / 'results.json'}", file=sys.stderr)


if __name__ == "__main__":
    main()