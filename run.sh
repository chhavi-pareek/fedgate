#!/usr/bin/env bash
# FedGate quick-start — runs backend + frontend in parallel
# Usage: ./run.sh
# Stop: Ctrl-C (kills both processes)

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"

PYTHON="$ROOT/venv/bin/python"
if [ ! -f "$PYTHON" ]; then
  echo "ERROR: venv not found. Create it with:"
  echo "  python3.11 -m venv venv && venv/bin/pip install -r requirements.txt"
  exit 1
fi

# Generate precomputed experiment data if missing
RESULTS="$ROOT/experiments/results"
mkdir -p "$RESULTS"

if [ ! -f "$RESULTS/epsilon_sweep_latest.json" ]; then
  echo "Generating epsilon sweep data (first run only)..."
  PYTHONPATH="$ROOT" "$PYTHON" "$ROOT/experiments/epsilon_sweep.py"
fi

if [ ! -f "$RESULTS/poison_demo_latest.json" ]; then
  echo "Generating poison demo data (first run only)..."
  PYTHONPATH="$ROOT" "$PYTHON" "$ROOT/experiments/poison_demo.py"
fi

if [ ! -f "$RESULTS/case_study_poison_latest.json" ]; then
  echo "Generating case study data (first run only)..."
  PYTHONPATH="$ROOT" "$PYTHON" "$ROOT/experiments/case_study_poison.py"
fi

# Start backend
echo ""
echo "Starting backend on http://localhost:8000 ..."
PYTHONPATH="$ROOT" "$PYTHON" -m uvicorn api.main:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

# Start frontend
echo "Starting frontend on http://localhost:5173 ..."
cd "$ROOT/frontend" && npm run dev &
FRONTEND_PID=$!

echo ""
echo "  Backend  → http://localhost:8000"
echo "  Frontend → http://localhost:5173"
echo ""
echo "Press Ctrl-C to stop both servers."

cleanup() {
  echo ""
  echo "Stopping servers..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
  wait "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
  echo "Done."
}
trap cleanup INT TERM

wait
