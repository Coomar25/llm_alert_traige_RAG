#!/usr/bin/env bash
# One-command launcher for the viva demo (backend + frontend).
# Run from the repo root:  bash demo/run.sh
#
# Backend  -> http://localhost:8077   (FastAPI, cached JSON)
# Frontend -> http://localhost:3000   (Next.js — open this in the browser)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BACK_PORT=8077
FRONT_PORT=3000

if [ ! -x "demo/.venv/bin/uvicorn" ]; then
  echo "demo/.venv not found. Create it first:"
  echo "  python3 -m venv demo/.venv"
  echo "  demo/.venv/bin/pip install fastapi 'uvicorn[standard]'"
  exit 1
fi

if [ ! -f "demo/backend/data/alerts.json" ]; then
  echo "Cached data missing. Building it (one-time, needs the ML deps)…"
  demo/.venv/bin/python demo/build_demo_data.py
fi

cleanup() {
  echo; echo "Stopping demo…"
  kill "${BACK_PID:-}" "${FRONT_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Starting backend on :$BACK_PORT …"
demo/.venv/bin/uvicorn backend.main:app --app-dir demo --port "$BACK_PORT" &
BACK_PID=$!

echo "Starting frontend on :$FRONT_PORT …"
( cd demo/frontend && npm run dev -- -p "$FRONT_PORT" ) &
FRONT_PID=$!

echo
echo "  ➜  Demo:    http://localhost:$FRONT_PORT"
echo "  ➜  API:     http://localhost:$BACK_PORT/api/health"
echo "  (Ctrl-C to stop both)"
wait
