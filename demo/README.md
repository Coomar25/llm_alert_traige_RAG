# Viva Demonstration UI

An interactive dashboard for the dissertation demo: **LLM-based intelligent
alert triage and prioritisation for backend microservice security operations**
(AIT-ADS).

It answers one question visually — *does retrieval-augmentation (RAG) help an
LLM triage security alerts?* — and lets you drill into individual alerts to show
exactly where and why RAG changed the decision.

The demo is **fully cached**. It runs off the committed 8B result files plus a
one-time precompute of the RAG retrievals — **no live LLM, no Ollama, no network
at demo time.** Nothing can stall while you are projecting.

---

## Architecture

```
demo/
├── build_demo_data.py     one-time: joins alerts + predictions + REAL retrievals -> JSON
├── backend/               FastAPI, serves the cached JSON (dependency-light)
│   ├── main.py
│   └── data/*.json        overview.json · phases.json · alerts.json  (generated)
├── frontend/              Next.js dashboard (3 pages)
│   └── app/{page, triage, pipeline}
├── run.sh                 launches backend + frontend together
└── .venv/                 python env for the ONE-TIME build only
```

- **Overview** — headline comparison (precision/recall/F1/FPR/latency), the key
  finding callout, and per-attack-phase recall chart.
- **Triage Explorer** — every held-out alert with both pipelines' verdicts side
  by side and the exact KB context RAG retrieved. Filter to **RAG broke** to
  show the regressions.
- **Pipeline** — the four project stages and the "why these choices" viva notes.

Data sources (all cached / committed):

| Data | From |
|------|------|
| 129 test alerts | `data/processed/sample_120.jsonl` |
| LLM-only predictions | `results/llm_only_8b/predictions.jsonl` |
| LLM+RAG predictions | `results/llm_rag_8b/predictions.jsonl` |
| Headline / per-phase | `results/comparison_8b/comparison.json` |
| Retrieved context | recomputed once via `llm.retrieval.Retriever` on `data/kb` |

---

## Run it

```bash
# from the repo root
bash demo/run.sh
```

Then open **http://localhost:3000**. Backend runs on :8077.

### First-time setup (already done on this machine)

```bash
# 1. python env for the one-time build (needs the pipeline's ML deps)
python3 -m venv demo/.venv
demo/.venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu
demo/.venv/bin/pip install sentence-transformers chromadb fastapi "uvicorn[standard]"

# 2. build the cached JSON (downloads the ~80MB embedding model once)
demo/.venv/bin/python demo/build_demo_data.py

# 3. frontend deps
cd demo/frontend && npm install
```

To regenerate the cached data after re-running experiments, just re-run step 2
and restart the backend.

---

## Talking track for the viva (≈8 min)

1. **Overview** — "Same 129 alerts, same 8B model, the only difference is
   retrieval." Read the four stat tiles: F1 fell, but precision rose and false
   positives dropped 20 points at 2× latency.
2. **The key finding** — own it: RAG made the model *more cautious* — fewer
   false alarms but it now dismisses some real attack steps. Point at the
   per-phase chart: no phase improved, six regressed.
3. **Triage Explorer → filter "RAG broke"** — open the `dnsteal` case: LLM-only
   correctly calls it an attack; LLM+RAG says benign **even though the
   DNS-exfiltration runbook was retrieved**. This is your evidence for the
   recall drop, live and concrete.
4. **Contrast with "RAG fixed"** — show a case where retrieval rescued a wrong
   call, so the story is balanced, not one-sided.
5. **Pipeline** — close on the design decisions (local model, source-balanced
   retrieval, no ground-truth leakage).

**If asked "why does RAG hurt recall?"** — the retrieved context (generic CVEs,
operational runbooks) gives the model reasons to explain an alert away, biasing
it toward "benign / known-behaviour"; precision-up / recall-down is the classic
signature of a more conservative decision threshold.
