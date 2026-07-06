"""
run_llm_rag.py — LLM+RAG triage pipeline (retrieval-augmented).

This is the proposed system. For each alert it:
    1. Retrieves the top-K most relevant knowledge-base entries (MITRE /
       CVE / runbook) using ONLY the alert's observable content.
    2. Injects that context into the triage prompt.
    3. Asks the model to decide attack/benign with the context available.

Comparing this against run_llm_only (identical model, prompt, sample, and
evaluation — differing ONLY by the retrieved context) isolates the
contribution of retrieval. That is the dissertation's core experiment.

Everything about concurrency and correctness matches run_llm_only.py:
    - Worker threads do the pure work (retrieve + build prompt + call model).
    - Each worker returns a self-contained (prediction bound to its alert).
    - All result recording happens on the main thread, sequentially.

The retrieval step runs INSIDE each worker so it parallelises with the LLM
call. The Retriever guards its internal calls with a lock, so concurrent
retrieval is safe.

No ground-truth leakage
-----------------------
Retrieval uses retrieval_query_text(alert), which reads only observable
fields (description, rule groups, raw message). The alert's known
attack_phase / is_attack is NEVER used to retrieve. This keeps the
experiment honest.

Usage
-----
    python run_llm_rag.py \\
        --input data/processed/sample_5k.jsonl \\
        --output results/llm_rag \\
        --kb-dir data/kb \\
        --model llama3.2:3b \\
        --workers 3 \\
        --top-k 3

    # Smoke test first
    python run_llm_rag.py --input ... --output ... --kb-dir data/kb --limit 20
"""

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from baselines.evaluation import EvaluationResult, format_headline
from baselines.splits import split_of

from llm import (
    compact_alert_text, build_rag_prompt, normalise_llm_output,
    generate, check_ollama, DEFAULT_MODEL, DEFAULT_OLLAMA_URL,
)
from llm.retrieval import Retriever


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


def infer_one(alert: dict, retriever: Retriever, top_k: int,
              model: str, url: str) -> dict:
    """Pure worker: retrieve context, build RAG prompt, call model.

    Returns a self-contained result binding the prediction to its alert.
    Retrieval uses observable content only (no ground-truth leakage).
    """
    # --- Retrieval (observable content only) ---
    t_ret0 = time.perf_counter()
    context = retriever.retrieve_and_format(alert, top_k=top_k)
    retrieval_ms = (time.perf_counter() - t_ret0) * 1000.0

    # --- LLM call ---
    alert_text = compact_alert_text(alert)
    prompt = build_rag_prompt(alert_text, context)
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
        "retrieval_ms": round(retrieval_ms, 1),
        "latency_ms": round(resp.latency_ms, 1),
        "parse_ok": resp.parse_ok,
        "malformed": pred["_malformed"] or not resp.parse_ok,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, type=Path,
                    help="Sampled alerts JSONL (SAME file used for LLM-only)")
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--kb-dir", required=True, type=Path,
                    help="ChromaDB persist dir (data/kb)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--top-k", type=int, default=3,
                    help="Number of KB entries to retrieve per alert (default 3)")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    if not args.input.exists():
        print(f"ERROR: input not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    if not args.kb_dir.exists():
        print(f"ERROR: KB dir not found: {args.kb_dir}", file=sys.stderr)
        sys.exit(1)
    args.output.mkdir(parents=True, exist_ok=True)

    # ---- Health checks ----
    print("Checking Ollama...", file=sys.stderr)
    ok, msg = check_ollama(model=args.model, url=args.ollama_url)
    print(f"  {msg}", file=sys.stderr)
    if not ok:
        print("ERROR: Ollama health check failed.", file=sys.stderr)
        sys.exit(1)

    print("Loading knowledge base...", file=sys.stderr)
    retriever = Retriever(args.kb_dir, top_k=args.top_k)
    kb_count = retriever.document_count()
    print(f"  KB ready: {kb_count:,} documents, retrieving top-{args.top_k}",
          file=sys.stderr)
    if kb_count == 0:
        print("ERROR: knowledge base is empty. Build it first "
              "(build_knowledge_base.py).", file=sys.stderr)
        sys.exit(1)

    # ---- Load alerts ----
    alerts = []
    for alert in iter_alerts(args.input):
        if split_of(alert.get("scenario", "")) != "test":
            continue
        alerts.append(alert)
        if args.limit is not None and len(alerts) >= args.limit:
            break
    print(f"\nLoaded {len(alerts)} test-split alerts.", file=sys.stderr)
    print(f"Running LLM+RAG with model '{args.model}', {args.workers} workers, "
          f"top-{args.top_k} retrieval...", file=sys.stderr)

    # ---- Concurrent inference, sequential aggregation ----
    result = EvaluationResult(pipeline_name="LLM+RAG", split_name="test")
    predictions_path = args.output / "predictions.jsonl"
    n_malformed = 0
    n_done = 0
    total_retrieval_ms = 0.0
    t_start = time.perf_counter()
    write_lock = threading.Lock()

    with predictions_path.open("w") as pred_f:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            future_to_alert = {
                pool.submit(infer_one, alert, retriever, args.top_k,
                            args.model, args.ollama_url): alert
                for alert in alerts
            }
            for future in as_completed(future_to_alert):
                rec = future.result()

                result.record(
                    predicted_attack=rec["predicted_is_attack"],
                    actual_attack=rec["actual_is_attack"],
                    scenario=rec["scenario"],
                    attack_phase=rec["actual_attack_phase"],
                    latency_ms=rec["latency_ms"],
                )
                if rec["malformed"]:
                    n_malformed += 1
                total_retrieval_ms += rec["retrieval_ms"]

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
                          f"({rate:.2f} alerts/sec, ETA {eta/60:.1f} min, "
                          f"{n_malformed} malformed)", file=sys.stderr)

    elapsed = time.perf_counter() - t_start

    # ---- Results ----
    results_dict = result.to_dict()
    results_dict["malformed_outputs"] = n_malformed
    results_dict["wall_clock_seconds"] = round(elapsed, 1)
    results_dict["throughput_alerts_per_second"] = round(n_done / elapsed, 3) if elapsed else 0
    results_dict["mean_retrieval_ms"] = round(total_retrieval_ms / n_done, 1) if n_done else 0
    results_dict["workers"] = args.workers
    results_dict["top_k"] = args.top_k
    results_dict["model"] = args.model
    results_dict["kb_document_count"] = kb_count

    (args.output / "results.json").write_text(
        json.dumps(results_dict, indent=2, default=str))

    print("\n" + "=" * 70, file=sys.stderr)
    print("LLM+RAG RESULTS", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"  {format_headline(result)}", file=sys.stderr)
    print(f"  Malformed outputs: {n_malformed}/{n_done}", file=sys.stderr)
    print(f"  Mean retrieval time: {total_retrieval_ms / n_done:.1f}ms/alert"
          if n_done else "", file=sys.stderr)
    if elapsed:
        print(f"  Wall clock: {elapsed:.0f}s "
              f"({n_done / elapsed:.2f} alerts/sec)", file=sys.stderr)
    print(f"\n  Predictions: {predictions_path}", file=sys.stderr)
    print(f"  Results:     {args.output / 'results.json'}", file=sys.stderr)


if __name__ == "__main__":
    main()
