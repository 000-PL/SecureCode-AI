#!/usr/bin/env bash
# One-command start (Linux/macOS): installs dependencies, builds the React app, starts everything on :8000
set -e
cd "$(dirname "$0")"
[ -f backend/.env ] || cp backend/.env.example backend/.env
python3 -m venv backend/.venv 2>/dev/null || true
source backend/.venv/bin/activate
pip install -q -r backend/requirements.txt
if command -v npm >/dev/null 2>&1; then
  (cd frontend && { [ -d node_modules ] || npm install --no-audit --no-fund; } && npm run build)
else
  echo "WARNING: npm not found - install Node.js 18+ to build the frontend."
fi
echo ">>> Open http://localhost:8000"
cd backend && exec uvicorn app.main:app --host 127.0.0.1 --port 8000
