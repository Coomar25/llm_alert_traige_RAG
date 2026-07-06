"""
compare_pipelines.py — Three-way comparison of the triage pipelines.

Reads the results.json produced by each pipeline and emits a unified
comparison: overall metrics side by side, per-phase recall side by side, and
the key deltas (how much RAG improved over LLM-only, per phase).

This produces the headline table for the dissertation's results chapter.

Inputs (any subset; missing ones are skipped):
    --rule-based   results/baselines/summary.json      (B1/B2 from M6)
    --llm-only     results/llm_only/results.json        (M8)
    --llm-rag      results/llm_rag/results.json         (M8)

Note on the rule-based input: the baseline stage wrote a different JSON shape
(summary.json with B1/B2 blocks). This script adapts it. If you prefer, point
--rule-based at results/baselines/b1_results.json and it will read the
final_test_result block.

Usage:
    python compare_pipelines.py \\
        --llm-only results/llm_only/results.json \\
        --llm-rag  results/llm_rag/results.json \\
        --rule-based results/baselines/summary.json \\
        --output results/comparison
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional


ALL_PHASES = [
    "network_scans", "service_scans", "dirb", "wpscan", "webshell",
    "cracking", "reverse_shell", "privilege_escalation", "service_stop",
    "dnsteal",
]


def load_json(path: Optional[Path]) -> Optional[dict]:
    if path is None:
        return None
    if not path.exists():
        print(f"  (skipping missing file: {path})", file=sys.stderr)
        return None
    return json.loads(path.read_text())


def extract_overall(results: dict, pipeline_hint: str) -> Optional[dict]:
    """Pull overall precision/recall/f1/fpr from a results dict.

    Handles both the LLM pipeline shape (top-level 'overall') and the
    rule-based summary shape (B1/B2 blocks).
    """
    if results is None:
        return None

    # LLM pipeline shape
    if "overall" in results:
        o = results["overall"]
        return {
            "precision": o.get("precision"),
            "recall": o.get("recall"),
            "f1": o.get("f1"),
            "fpr": o.get("false_positive_rate"),
            "n_alerts": results.get("n_alerts"),
            "mean_latency_ms": results.get("mean_latency_ms")
                               or _latency_from(results),
        }

    # Rule-based summary.json shape: {"B1": {...}, "B2": {...}}
    # Prefer B1 (it was the stronger baseline in M6).
    for key in ("B1", "B2"):
        if key in results:
            b = results[key]
            return {
                "precision": b.get("test_precision"),
                "recall": b.get("test_recall"),
                "f1": b.get("test_f1"),
                "fpr": b.get("test_fpr"),
                "n_alerts": b.get("test_n_alerts"),
                "mean_latency_ms": b.get("test_mean_latency_ms"),
                "_variant": key,
            }

    # b1_results.json shape: {"final_test_result": {...}}
    if "final_test_result" in results:
        ftr = results["final_test_result"]
        o = ftr.get("overall", {})
        return {
            "precision": o.get("precision"),
            "recall": o.get("recall"),
            "f1": o.get("f1"),
            "fpr": o.get("false_positive_rate"),
            "n_alerts": ftr.get("n_alerts"),
            "mean_latency_ms": ftr.get("mean_latency_ms"),
        }

    return None


def _latency_from(results: dict):
    return results.get("mean_latency_ms")


def extract_per_phase_recall(results: dict) -> Dict[str, Optional[float]]:
    """Pull per-phase recall. Only LLM pipelines have by_phase; rule-based
    summary.json does not (its per-phase lives in b1_results.json)."""
    out: Dict[str, Optional[float]] = {p: None for p in ALL_PHASES}
    if results is None:
        return out
    by_phase = results.get("by_phase")
    if not by_phase:
        # Try nested (b1_results final_test_result)
        ftr = results.get("final_test_result", {})
        by_phase = ftr.get("by_phase")
    if not by_phase:
        return out
    for phase in ALL_PHASES:
        if phase in by_phase:
            out[phase] = by_phase[phase].get("recall")
    return out


def fmt(v, width=8):
    if v is None:
        return " " * (width - 1) + "-"
    return f"{v:>{width}.4f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rule-based", type=Path, default=None)
    ap.add_argument("--llm-only", type=Path, default=None)
    ap.add_argument("--llm-rag", type=Path, default=None)
    ap.add_argument("--output", type=Path, default=None,
                    help="Optional directory to write comparison.json + .md")
    args = ap.parse_args()

    rb = load_json(args.rule_based)
    lo = load_json(args.llm_only)
    rag = load_json(args.llm_rag)

    rb_o = extract_overall(rb, "rule")
    lo_o = extract_overall(lo, "llm_only")
    rag_o = extract_overall(rag, "llm_rag")

    # ---- Overall comparison table ----
    print("\n" + "=" * 74)
    print("OVERALL METRICS (test split)")
    print("=" * 74)
    print(f"{'Pipeline':<16}{'Precision':>11}{'Recall':>10}{'F1':>10}"
          f"{'FPR':>10}{'N':>8}")
    print("-" * 74)
    rows = [("Rule-based (B1)", rb_o), ("LLM-only", lo_o), ("LLM+RAG", rag_o)]
    for name, o in rows:
        if o is None:
            print(f"{name:<16}{'(not provided)':>49}")
            continue
        print(f"{name:<16}{fmt(o['precision'],11)}{fmt(o['recall'],10)}"
              f"{fmt(o['f1'],10)}{fmt(o['fpr'],10)}"
              f"{str(o.get('n_alerts','-')):>8}")

    # ---- Per-phase recall comparison ----
    lo_ph = extract_per_phase_recall(lo)
    rag_ph = extract_per_phase_recall(rag)

    print("\n" + "=" * 74)
    print("PER-PHASE RECALL: LLM-only vs LLM+RAG  (the core ablation)")
    print("=" * 74)
    print(f"{'Phase':<24}{'LLM-only':>12}{'LLM+RAG':>12}{'Delta':>12}")
    print("-" * 74)
    for phase in ALL_PHASES:
        a = lo_ph.get(phase)
        b = rag_ph.get(phase)
        if a is None and b is None:
            continue
        delta = (b - a) if (a is not None and b is not None) else None
        delta_str = fmt(delta, 12) if delta is not None else " " * 11 + "-"
        # Mark improvements with a + for readability
        marker = ""
        if delta is not None:
            marker = "  ↑" if delta > 0.001 else ("  ↓" if delta < -0.001 else "  =")
        print(f"{phase:<24}{fmt(a,12)}{fmt(b,12)}{delta_str}{marker}")

    # ---- Build output structure ----
    comparison = {
        "overall": {
            "rule_based": rb_o,
            "llm_only": lo_o,
            "llm_rag": rag_o,
        },
        "per_phase_recall": {
            phase: {
                "llm_only": lo_ph.get(phase),
                "llm_rag": rag_ph.get(phase),
                "delta": (rag_ph.get(phase) - lo_ph.get(phase))
                         if (lo_ph.get(phase) is not None
                             and rag_ph.get(phase) is not None) else None,
            } for phase in ALL_PHASES
        },
    }

    # ---- Summary of RAG's effect ----
    if lo_o and rag_o:
        print("\n" + "=" * 74)
        print("RAG EFFECT SUMMARY")
        print("=" * 74)
        d_f1 = (rag_o["f1"] or 0) - (lo_o["f1"] or 0)
        d_recall = (rag_o["recall"] or 0) - (lo_o["recall"] or 0)
        d_prec = (rag_o["precision"] or 0) - (lo_o["precision"] or 0)
        d_fpr = (rag_o["fpr"] or 0) - (lo_o["fpr"] or 0)
        print(f"  F1:        {lo_o['f1']:.4f} -> {rag_o['f1']:.4f}  "
              f"(delta {d_f1:+.4f})")
        print(f"  Recall:    {lo_o['recall']:.4f} -> {rag_o['recall']:.4f}  "
              f"(delta {d_recall:+.4f})")
        print(f"  Precision: {lo_o['precision']:.4f} -> {rag_o['precision']:.4f}  "
              f"(delta {d_prec:+.4f})")
        print(f"  FPR:       {lo_o['fpr']:.4f} -> {rag_o['fpr']:.4f}  "
              f"(delta {d_fpr:+.4f})")

        # Count phases improved
        improved = sum(1 for p in ALL_PHASES
                       if comparison["per_phase_recall"][p]["delta"] is not None
                       and comparison["per_phase_recall"][p]["delta"] > 0.001)
        worsened = sum(1 for p in ALL_PHASES
                       if comparison["per_phase_recall"][p]["delta"] is not None
                       and comparison["per_phase_recall"][p]["delta"] < -0.001)
        print(f"\n  Per-phase recall: {improved} phases improved, "
              f"{worsened} phases worsened under RAG")
        comparison["rag_effect"] = {
            "delta_f1": d_f1, "delta_recall": d_recall,
            "delta_precision": d_prec, "delta_fpr": d_fpr,
            "phases_improved": improved, "phases_worsened": worsened,
        }

    # ---- Write output ----
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "comparison.json").write_text(
            json.dumps(comparison, indent=2, default=str))
        print(f"\nWrote comparison.json to {args.output}", file=sys.stderr)

    print()


if __name__ == "__main__":
    main()
