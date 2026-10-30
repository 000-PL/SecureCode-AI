@echo off
REM One-command start (Windows): installs dependencies, builds the React app, starts everything on :8000
cd /d "%~dp0"
if not exist backend\.env copy backend\.env.example backend\.env >nul
if not exist backend\.venv python -m venv backend\.venv
call backend\.venv\Scripts\activate.bat
pip install -q -r backend\requirements.txt
where npm >nul 2>nul
if %errorlevel%==0 (
  pushd frontend
  if not exist node_modules call npm install --no-audit --no-fund
  call npm run build
  popd
) else (
  echo WARNING: npm not found - install Node.js 18+ to build the frontend.
)
echo ^>^>^> Open http://localhost:8000
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000
