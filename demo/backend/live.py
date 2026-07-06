"""
LIVE inference router — runs the real pipelines on demand and streams results.

This is the opposite of the cached path: it actually calls the rule-based
baseline, the LLM-only pipeline, and the LLM+RAG pipeline, and pushes each
result to the browser over Server-Sent Events (SSE) as it completes.

It reuses the dissertation code unchanged:
    baselines.rule_based.predict_b1        (instant)
    llm.retrieval.Retriever                (~1s embed + ChromaDB)
    llm.generate  -> Ollama                (seconds, the slow part)

Heavy deps (torch / sentence-transformers / chromadb) and Ollama are only
touched when a /api/live/* endpoint is actually hit — importing this module is
cheap, so the cached endpoints in main.py keep working even with no Ollama.

Requires (at demo time, unlike the cached path):
    - Ollama running with the chosen model pulled
    - demo/.venv (has torch/sentence-transformers/chromadb/fastapi)
    - the ChromaDB knowledge base at data/kb
"""

import json
import sys
import threading
import time
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[2]        # code_work/
AIT = ROOT / "ait_parser"
KB_DIR = ROOT / "data" / "kb"
SAMPLES = ROOT / "data" / "processed" / "sample_120.jsonl"

if str(AIT) not in sys.path:
    sys.path.insert(0, str(AIT))

router = APIRouter(prefix="/api/live")

DEFAULT_MODEL = "llama3.2:3b"     # fast enough to feel live; 8b is ~4x slower
OLLAMA_TAGS = "http://localhost:11434/api/tags"
B1_THRESHOLD = 2                  # tuned best threshold from baselines/summary.json

# --- lazy singletons -------------------------------------------------------
_retriever = None
_retriever_lock = threading.Lock()
_alerts_cache = None


def _load_alerts():
    global _alerts_cache
    if _alerts_cache is None:
        idx = {}
        with SAMPLES.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    a = json.loads(line)
                    idx[a["alert_id"]] = a
        _alerts_cache = idx
    return _alerts_cache


def _get_retriever():
    """Load + warm the retriever once (embedding model load is ~5s)."""
    global _retriever
    if _retriever is None:
        with _retriever_lock:
            if _retriever is None:
                from llm.retrieval import Retriever
                _retriever = Retriever(KB_DIR, top_k=3, balance_sources=True)
    return _retriever


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"


# --- health ----------------------------------------------------------------
@router.get("/health")
def live_health():
    """Report whether live inference is possible right now."""
    import urllib.request

    models, ollama_ok, err = [], False, None
    try:
        with urllib.request.urlopen(OLLAMA_TAGS, timeout=3) as resp:
            body = json.loads(resp.read())
        models = [m["name"] for m in body.get("models", [])]
        ollama_ok = True
    except Exception as e:  # noqa: BLE001
        err = str(e)

    return {
        "ollama": ollama_ok,
        "models": models,
        "default_model": DEFAULT_MODEL,
        "kb_present": KB_DIR.exists(),
        "error": err,
    }


@router.get("/samples")
def live_samples():
    """A pick-list of dataset alerts for the input dropdown."""
    out = []
    for a in _load_alerts().values():
        out.append({
            "alert_id": a["alert_id"],
            "description": a.get("description") or "(no description)",
            "scenario": a.get("scenario"),
            "log_source": a.get("log_source"),
            "is_attack": bool(a.get("is_attack", False)),
            "attack_phase": a.get("attack_phase"),
        })
    return out


# --- run -------------------------------------------------------------------
class RunRequest(BaseModel):
    alert_id: str | None = None          # pick from dataset …
    alert: dict | None = None            # … or bring your own alert JSON
    pipelines: list[str] = ["baseline", "llm_only", "llm_rag"]
    model: str = DEFAULT_MODEL


def _resolve_alert(req: RunRequest) -> dict | None:
    if req.alert:
        return req.alert
    if req.alert_id:
        return _load_alerts().get(req.alert_id)
    return None


def _baseline_result(alert: dict) -> dict:
    from baselines.rule_based import predict_b1, B1Config
    t0 = time.perf_counter()
    pred = predict_b1(alert, B1Config(severity_threshold=B1_THRESHOLD))
    return {
        "predicted_is_attack": bool(pred),
        "predicted_attack_phase": None,
        "confidence": None,
        "explanation": f"Rule B1: severity_norm "
                       f"({alert.get('severity_norm', 1)}) "
                       f"{'≥' if pred else '<'} threshold {B1_THRESHOLD}.",
        "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }


def _format_hits(hits):
    from llm.retrieval import DOC_CHAR_BUDGET
    out = []
    for h in hits:
        meta = h.get("metadata", {}) or {}
        txt = (h.get("text") or "").strip().replace("\n", " ")
        out.append({
            "source": meta.get("source", "unknown"),
            "ident": (meta.get("mitre_id") or meta.get("cve_id")
                      or meta.get("runbook_id") or ""),
            "title": meta.get("title", ""),
            "text": txt[:DOC_CHAR_BUDGET] + ("…" if len(txt) > DOC_CHAR_BUDGET else ""),
            "distance": round(h["distance"], 4) if h.get("distance") is not None else None,
            "similarity": round(max(0.0, 1.0 - h["distance"]), 3)
            if h.get("distance") is not None else None,
        })
    return out


def _stream(req: RunRequest):
    alert = _resolve_alert(req)
    if not alert:
        yield _sse({"type": "error", "message": "No alert provided (alert_id or alert)."})
        return

    gt = {
        "is_attack": bool(alert.get("is_attack", False)),
        "attack_phase": alert.get("attack_phase"),
    } if "is_attack" in alert else None

    yield _sse({"type": "start", "alert_id": alert.get("alert_id"),
                "pipelines": req.pipelines, "model": req.model,
                "ground_truth": gt})

    # 1) rule-based baseline — instant
    if "baseline" in req.pipelines:
        yield _sse({"type": "pipeline_start", "pipeline": "baseline"})
        res = _baseline_result(alert)
        if gt is not None:
            res["correct"] = res["predicted_is_attack"] == gt["is_attack"]
        yield _sse({"type": "result", "pipeline": "baseline", "result": res})

    # Heavy imports only if an LLM pipeline is requested.
    if "llm_only" in req.pipelines or "llm_rag" in req.pipelines:
        from llm import (compact_alert_text, build_llm_only_prompt,
                         build_rag_prompt, normalise_llm_output, generate)

        alert_text = compact_alert_text(alert)

        # 2) LLM-only
        if "llm_only" in req.pipelines:
            yield _sse({"type": "pipeline_start", "pipeline": "llm_only"})
            prompt = build_llm_only_prompt(alert_text)
            resp = generate(prompt, model=req.model)
            pred = normalise_llm_output(resp.parsed_json)
            res = {
                "predicted_is_attack": pred["is_attack"],
                "predicted_attack_phase": pred["attack_phase"],
                "confidence": pred["confidence"],
                "explanation": pred["explanation"] or (resp.error or ""),
                "latency_ms": round(resp.latency_ms, 1),
                "parse_ok": resp.parse_ok,
            }
            if gt is not None:
                res["correct"] = res["predicted_is_attack"] == gt["is_attack"]
            yield _sse({"type": "result", "pipeline": "llm_only", "result": res})

        # 3) LLM + RAG — retrieve first (stream the docs), then call the model
        if "llm_rag" in req.pipelines:
            yield _sse({"type": "pipeline_start", "pipeline": "llm_rag"})
            yield _sse({"type": "status", "pipeline": "llm_rag",
                        "message": "Embedding alert & querying knowledge base…"})
            retriever = _get_retriever()
            t_ret0 = time.perf_counter()
            hits = retriever.retrieve(alert)
            context = retriever.retrieve_and_format(alert)
            retrieval_ms = round((time.perf_counter() - t_ret0) * 1000.0, 1)
            yield _sse({"type": "retrieval", "pipeline": "llm_rag",
                        "retrieval_ms": retrieval_ms,
                        "docs": _format_hits(hits)})
            yield _sse({"type": "status", "pipeline": "llm_rag",
                        "message": f"Calling {req.model} with retrieved context…"})
            prompt = build_rag_prompt(alert_text, context)
            resp = generate(prompt, model=req.model)
            pred = normalise_llm_output(resp.parsed_json)
            res = {
                "predicted_is_attack": pred["is_attack"],
                "predicted_attack_phase": pred["attack_phase"],
                "confidence": pred["confidence"],
                "explanation": pred["explanation"] or (resp.error or ""),
                "latency_ms": round(resp.latency_ms, 1),
                "retrieval_ms": retrieval_ms,
                "parse_ok": resp.parse_ok,
            }
            if gt is not None:
                res["correct"] = res["predicted_is_attack"] == gt["is_attack"]
            yield _sse({"type": "result", "pipeline": "llm_rag", "result": res})

    yield _sse({"type": "done"})


@router.post("/run")
def live_run(req: RunRequest):
    return StreamingResponse(
        _stream(req),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",   # disable proxy buffering so events flush
        },
    )
