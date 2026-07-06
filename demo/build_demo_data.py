"""
One-time build step for the viva demonstration UI.

Bakes everything the demo needs into static JSON so the demo runs fully cached
(no live LLM, no live embedding) during the viva:

    demo/backend/data/overview.json   headline metrics + baselines + config
    demo/backend/data/phases.json     per-attack-phase recall, both pipelines
    demo/backend/data/alerts.json     every test alert with both predictions,
                                      correctness, and the REAL RAG retrieval

The LLM predictions are read from the committed 8B result files (cached). The
RAG "retrieved context" is the only thing not already on disk, so we recompute
it here ONCE using the exact same Retriever the pipeline used. This requires
sentence-transformers + chromadb (installed in demo/.venv) and reads the KB at
data/kb — but only at build time. The backend never imports them.

Run:  demo/.venv/bin/python demo/build_demo_data.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # code_work/
AIT = ROOT / "ait_parser"
sys.path.insert(0, str(AIT))                            # make llm / kb importable

OUT = Path(__file__).resolve().parent / "backend" / "data"

# --- Input files (all cached / committed) ---
ALERTS_SRC = ROOT / "data" / "processed" / "sample_120.jsonl"      # 129 test alerts
LLM_ONLY_PRED = ROOT / "results" / "llm_only_8b" / "predictions.jsonl"
LLM_RAG_PRED = ROOT / "results" / "llm_rag_8b" / "predictions.jsonl"
LLM_ONLY_RES = ROOT / "results" / "llm_only_8b" / "results.json"
LLM_RAG_RES = ROOT / "results" / "llm_rag_8b" / "results.json"
COMPARISON = ROOT / "results" / "comparison_8b" / "comparison.json"
BASELINES = ROOT / "results" / "baselines" / "summary.json"
KB_DIR = ROOT / "data" / "kb"

TOP_K = 3  # matches the 8B RAG run (results.json -> top_k)


def read_jsonl(path: Path):
    rows = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def index_by_id(rows):
    return {r["alert_id"]: r for r in rows if r.get("alert_id")}


def triage_correct(actual_is_attack, predicted_is_attack):
    return bool(actual_is_attack) == bool(predicted_is_attack)


def classify_pair(only_ok, rag_ok):
    """Tag the interesting story of each alert for the demo filters."""
    if only_ok and rag_ok:
        return "both_correct"
    if not only_ok and rag_ok:
        return "rag_fixed"      # RAG rescued a wrong LLM-only call
    if only_ok and not rag_ok:
        return "rag_broke"      # RAG regressed a correct LLM-only call
    return "both_wrong"


def build_retriever():
    from llm.retrieval import Retriever
    print(f"  Loading KB + embedding model from {KB_DIR} ...", file=sys.stderr)
    r = Retriever(KB_DIR, top_k=TOP_K, balance_sources=True)
    print(f"  KB documents: {r.document_count()}", file=sys.stderr)
    return r


# Matches llm/retrieval.py: each doc is trimmed to this many chars before
# being injected into the prompt. We show the SAME budgeted text so the UI
# faithfully represents what the model actually received.
DOC_CHAR_BUDGET = 320


def _budget(text: str):
    t = (text or "").strip().replace("\n", " ")
    if len(t) > DOC_CHAR_BUDGET:
        return t[:DOC_CHAR_BUDGET].rstrip() + "…", True
    return t, False


def format_hits(hits):
    """Shape retrieval hits for the UI (source, id, title, snippet, score).

    `text` is the budgeted snippet actually injected into the LLM+RAG prompt;
    `text_full` is the complete KB entry, revealed on demand in the UI.
    """
    out = []
    for h in hits:
        meta = h.get("metadata", {}) or {}
        source = meta.get("source", "unknown")
        ident = (meta.get("mitre_id") or meta.get("cve_id")
                 or meta.get("runbook_id") or "")
        dist = h.get("distance")
        full = (h.get("text") or "").strip()
        injected, truncated = _budget(full)
        out.append({
            "source": source,
            "ident": ident,
            "title": meta.get("title", ""),
            "text": injected,          # what the model saw (320-char budget)
            "text_full": full,         # complete entry, for the UI expander
            "truncated": truncated,
            "distance": round(dist, 4) if isinstance(dist, (int, float)) else None,
            # cosine distance -> rough similarity for a friendly bar (0..1)
            "similarity": round(max(0.0, 1.0 - dist), 3)
            if isinstance(dist, (int, float)) else None,
        })
    return out


DISPLAY_FIELDS = [
    "timestamp", "scenario", "host", "host_ip", "log_source", "program_name",
    "severity_norm", "severity_raw", "rule_id", "description", "raw_message",
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "rule_groups",
    "mitre_techniques", "mitre_tactics",
]


def main():
    OUT.mkdir(parents=True, exist_ok=True)

    alerts = index_by_id(read_jsonl(ALERTS_SRC))
    only_pred = index_by_id(read_jsonl(LLM_ONLY_PRED))
    rag_pred = index_by_id(read_jsonl(LLM_RAG_PRED))
    comparison = json.loads(COMPARISON.read_text())
    only_res = json.loads(LLM_ONLY_RES.read_text())
    rag_res = json.loads(LLM_RAG_RES.read_text())
    baselines = json.loads(BASELINES.read_text()) if BASELINES.exists() else {}

    ids = list(rag_pred.keys())
    print(f"Alerts in test set: {len(ids)}", file=sys.stderr)

    retriever = build_retriever()

    # ---------- alerts.json ----------
    records = []
    tally = {"both_correct": 0, "rag_fixed": 0, "rag_broke": 0, "both_wrong": 0}
    for i, aid in enumerate(ids, 1):
        alert = alerts.get(aid, {})
        op = only_pred.get(aid, {})
        rp = rag_pred.get(aid, {})

        actual = bool(rp.get("actual_is_attack", alert.get("is_attack", False)))
        only_ok = triage_correct(actual, op.get("predicted_is_attack"))
        rag_ok = triage_correct(actual, rp.get("predicted_is_attack"))
        tag = classify_pair(only_ok, rag_ok)
        tally[tag] += 1

        # REAL retrieval — same query builder + KB the pipeline used.
        hits = retriever.retrieve(alert) if alert else []
        print(f"  [{i}/{len(ids)}] {aid[:8]}  {tag}  ({len(hits)} docs)",
              file=sys.stderr)

        display = {k: alert.get(k) for k in DISPLAY_FIELDS}
        records.append({
            "alert_id": aid,
            "display": display,
            "ground_truth": {
                "is_attack": actual,
                "attack_phase": rp.get("actual_attack_phase"),
            },
            "llm_only": {
                "predicted_is_attack": op.get("predicted_is_attack"),
                "predicted_attack_phase": op.get("predicted_attack_phase"),
                "confidence": op.get("confidence"),
                "explanation": op.get("explanation"),
                "latency_ms": op.get("latency_ms"),
                "correct": only_ok,
            },
            "llm_rag": {
                "predicted_is_attack": rp.get("predicted_is_attack"),
                "predicted_attack_phase": rp.get("predicted_attack_phase"),
                "confidence": rp.get("confidence"),
                "explanation": rp.get("explanation"),
                "latency_ms": rp.get("latency_ms"),
                "retrieval_ms": rp.get("retrieval_ms"),
                "correct": rag_ok,
                "retrieved": format_hits(hits),
            },
            "tag": tag,
        })

    (OUT / "alerts.json").write_text(json.dumps(records, indent=1))

    # ---------- overview.json ----------
    ov = comparison["overall"]
    overview = {
        "config": {
            "model": rag_res.get("model", "llama3.1:8b"),
            "kb_document_count": rag_res.get("kb_document_count",
                                            retriever.document_count()),
            "n_alerts": ov["llm_only"]["n_alerts"],
            "split": rag_res.get("split_name", "test"),
            "top_k": rag_res.get("top_k", TOP_K),
            "dataset": "AIT-ADS (Zenodo 8263181)",
        },
        "pipelines": {
            "llm_only": ov["llm_only"],
            "llm_rag": ov["llm_rag"],
        },
        "confusion": {
            "llm_only": only_res.get("overall", {}),
            "llm_rag": rag_res.get("overall", {}),
        },
        "rag_effect": comparison.get("rag_effect", {}),
        "baselines": baselines,
        "story_counts": tally,
    }
    (OUT / "overview.json").write_text(json.dumps(overview, indent=1))

    # ---------- phases.json ----------
    phases = []
    for name, d in comparison["per_phase_recall"].items():
        phases.append({
            "phase": name,
            "llm_only": d["llm_only"],
            "llm_rag": d["llm_rag"],
            "delta": round(d["delta"], 4),
        })
    (OUT / "phases.json").write_text(json.dumps(phases, indent=1))

    print("\nWrote:", file=sys.stderr)
    for f in ("overview.json", "phases.json", "alerts.json"):
        print(f"  {OUT / f}", file=sys.stderr)
    print(f"\nStory tally: {tally}", file=sys.stderr)


if __name__ == "__main__":
    main()
