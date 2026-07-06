"""
FastAPI backend for the viva demonstration UI.

Serves the CACHED demo data built by demo/build_demo_data.py. It reads three
static JSON files and exposes them over a small REST API. There is no live LLM
and no embedding model here — the backend is intentionally dependency-light and
cannot stall during the viva.

Run (from repo root):
    demo/.venv/bin/uvicorn backend.main:app --app-dir demo --reload --port 8000
"""

import json
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

DATA = Path(__file__).resolve().parent / "data"

app = FastAPI(title="AIT-ADS Triage Demo API", version="1.0")

# The Next.js dev server runs on :3000; allow it (and any localhost) to call us.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Live inference router (real pipelines + SSE streaming). Importing it is cheap;
# heavy deps and Ollama are only touched when a /api/live/* endpoint is hit.
try:
    from backend.live import router as live_router
    app.include_router(live_router)
except Exception as exc:  # pragma: no cover - keeps cached mode working
    print(f"[warn] live router unavailable: {exc}")


@lru_cache(maxsize=8)
def _load(name: str):
    path = DATA / name
    if not path.exists():
        raise HTTPException(
            status_code=503,
            detail=f"{name} not found. Run: demo/.venv/bin/python "
                   f"demo/build_demo_data.py",
        )
    return json.loads(path.read_text())


@app.get("/api/health")
def health():
    ok = all((DATA / f).exists()
             for f in ("overview.json", "phases.json", "alerts.json"))
    return {"status": "ok" if ok else "missing_data", "data_dir": str(DATA)}


@app.get("/api/overview")
def overview():
    return _load("overview.json")


@app.get("/api/phases")
def phases():
    return _load("phases.json")


@app.get("/api/alerts")
def alerts_list():
    """Lightweight list for the triage sidebar — no heavy fields."""
    records = _load("alerts.json")
    out = []
    for r in records:
        out.append({
            "alert_id": r["alert_id"],
            "scenario": r["display"].get("scenario"),
            "log_source": r["display"].get("log_source"),
            "description": r["display"].get("description"),
            "ground_truth": r["ground_truth"],
            "llm_only_correct": r["llm_only"]["correct"],
            "llm_rag_correct": r["llm_rag"]["correct"],
            "tag": r["tag"],
        })
    return out


@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: str):
    for r in _load("alerts.json"):
        if r["alert_id"] == alert_id:
            return r
    raise HTTPException(status_code=404, detail="alert not found")
