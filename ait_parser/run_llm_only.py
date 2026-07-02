"""
run_llm_only.py — LLM-only triage pipeline (no retrieval).

This is the ablation baseline: Mistral-7B reasons about each alert using
only its pre-trained knowledge, with no retrieved context. Comparing this
against LLM+RAG isolates the contribution of retrieval.

Workflow:
    1. Health-check Ollama (fail fast if not running)
    2. Load the sampled alerts (output of sampler.py)
    3. For each alert:
         a. Build the compact alert text
         b. Build the LLM-only prompt
         c. Call Ollama (Mistral-7B), measure latency
         d. Parse + normalise the JSON output
         e. Record the prediction against ground truth
    4. Compute precision/recall/F1/FPR (overall, per-scenario, per-phase)
       using the SAME EvaluationResult harness as the rule-based baseline
    5. Write predictions + results + a sample of explanations

Usage:
    python run_llm_only.py \\
        --input data/processed/sample_5k.jsonl \\
        --output results/llm_only \\
        --model mistral

    # Test on the first 20 alerts before committing to the full run
    python run_llm_only.py --input ... --output ... --limit 20

The evaluation harness (ConfusionMatrix, EvaluationResult) is imported from
baselines/ — built once in M6, reused unchanged here. This guarantees the
LLM pipeline is scored on identical metric definitions as the baseline.
"""

import argparse
import json
import sys
import time
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

    # ---- Run ----
    result = EvaluationResult(pipeline_name="LLM-only", split_name="test")
    predictions_path = args.output / "predictions.jsonl"
    n_malformed = 0
    n_processed = 0
    t_start = time.perf_counter()

    print(f"\nRunning LLM-only triage with model '{args.model}'...",
          file=sys.stderr)

    with predictions_path.open("w") as pred_f:
        for alert in iter_alerts(args.input):
            if args.limit is not None and n_processed >= args.limit:
                break

            scenario = alert.get("scenario", "")
            # Safety: only score test-split alerts
            if split_of(scenario) != "test":
                continue

            actual_attack = bool(alert.get("is_attack", False))
            actual_phase = alert.get("attack_phase")

            alert_text = compact_alert_text(alert)
            prompt = build_llm_only_prompt(alert_text)
            resp = generate(prompt, model=args.model, url=args.ollama_url)

            pred = normalise_llm_output(resp.parsed_json)
            if pred["_malformed"] or not resp.parse_ok:
                n_malformed += 1

            # Record into the shared evaluation harness
            result.record(
                predicted_attack=pred["is_attack"],
                actual_attack=actual_attack,
                scenario=scenario,
                attack_phase=actual_phase,
                latency_ms=resp.latency_ms,
            )

            # Persist the full prediction record for later analysis (M9)
            pred_f.write(json.dumps({
                "alert_id": alert.get("alert_id", ""),
                "scenario": scenario,
                "actual_is_attack": actual_attack,
                "actual_attack_phase": actual_phase,
                "predicted_is_attack": pred["is_attack"],
                "predicted_attack_phase": pred["attack_phase"],
                "confidence": pred["confidence"],
                "explanation": pred["explanation"],
                "latency_ms": round(resp.latency_ms, 1),
                "parse_ok": resp.parse_ok,
            }, default=str) + "\n")

            n_processed += 1
            if n_processed % 50 == 0:
                elapsed = time.perf_counter() - t_start
                rate = n_processed / elapsed if elapsed > 0 else 0
                print(f"  ... {n_processed} processed "
                      f"({rate:.1f} alerts/sec, "
                      f"{n_malformed} malformed so far)", file=sys.stderr)

    elapsed = time.perf_counter() - t_start

    # ---- Results ----
    results_dict = result.to_dict()
    results_dict["malformed_outputs"] = n_malformed
    results_dict["wall_clock_seconds"] = round(elapsed, 1)
    results_dict["alerts_per_second"] = round(n_processed / elapsed, 2) if elapsed else 0
    results_dict["model"] = args.model

    (args.output / "results.json").write_text(
        json.dumps(results_dict, indent=2, default=str))

    print("\n" + "=" * 70, file=sys.stderr)
    print("LLM-ONLY RESULTS", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"  {format_headline(result)}", file=sys.stderr)
    print(f"  Malformed outputs: {n_malformed}/{n_processed}", file=sys.stderr)
    print(f"  Wall clock: {elapsed:.0f}s "
          f"({n_processed / elapsed:.1f} alerts/sec)" if elapsed else "",
          file=sys.stderr)
    print(f"\n  Predictions: {predictions_path}", file=sys.stderr)
    print(f"  Results:     {args.output / 'results.json'}", file=sys.stderr)


if __name__ == "__main__":
    main()
