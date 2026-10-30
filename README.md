# SecureCode AI – AI-Powered Secure Coding & Vulnerability Remediation Platform

Stack (as in the project document): **React + CSS** frontend · **Python FastAPI** backend · **SAST engine** (built in, Python & JavaScript) ·
**AI module** (built-in knowledge base, optional external LLM) · **MySQL** (SQLite is the zero-setup default).

## The workflow (exactly the order of the sidebar)

| # | Page | What happens |
|---|------|--------------|
| – | **Dashboard** | Real statistics from the database + **New Security Scan** button |
| 1 | **Code Editor** | Write/upload code, language auto-detected, **Save & Scan Code** (and **Run code** for functional testing) |
| 2 | **Scan Results** | “Scan successful / unsuccessful”, security score, **how the score was calculated**, vulnerability table |
| 3 | **AI Fix** | For each vulnerability: what it is, **what caused it**, impact, **how to solve it**, step list |
| 4 | **Remediation** | **Side-by-side** vulnerable code ↔ secure code, **Apply changes** (updates the editor) or **Apply all fixes** |
| 5 | **Fix Validation** | Executes and **re-scans the entire code**; shows score change, resolved / remaining / new issues. Repeat until “Secure code verified” |
| – | **Reports** | Download PDF / HTML / JSON (score, vulnerabilities, remediation, validation history) |
| – | **Scan History** | Every scan + validation, search, filter, open, PDF, delete |
| – | **Settings** | Theme, editor font size, default report format, AI / execution switches |

## Run it (one command)

Requirements: **Python 3.10+** and **Node.js 18+**.

```
Windows :  run.bat
Linux/Mac: ./run.sh
```
Open **http://localhost:8000**, register an account, click **New Security Scan**. The script installs everything, builds the React app and
serves frontend + API from one server (no CORS / “Failed to fetch” problems).

### Development mode (hot reload)
```
cd backend  && python -m venv .venv && . .venv/bin/activate (Windows: .venv\Scripts\activate) && pip install -r requirements.txt
            && uvicorn app.main:app --reload --port 8000
cd frontend && npm install && npm run dev        # http://localhost:5173  (proxies /api -> :8000)
```

## MySQL (optional)
1. `mysql -u root -p < database/schema.sql`
2. In `backend/.env` set `DATABASE_URL=mysql+pymysql://securecode:securecode_pw@localhost:3306/securecode_ai`
3. Restart the backend. (Tables are also auto-created.)

## Security layer
* Passwords: PBKDF2-HMAC-SHA256, 260 000 rounds, per-user salt; constant-time compare; login timing equalised
* JWT (HS256) access tokens; secret auto-generated into `backend/.secret_key` (chmod 600) or set `SECRET_KEY`
* Per-user data isolation (every query is filtered by the logged-in user)
* Input validation (Pydantic): size limits, e-mail/password rules, safe file names
* Rate limiting (stricter on login/register), strict CORS, security headers (CSP, X-Frame-Options, nosniff…)
* SQL only via SQLAlchemy parameters; no secrets in code; audit log table
* Code execution runs in a temp dir, isolated interpreter (`python -I`), minimal environment, timeout, CPU/memory/file-size limits
  (Linux/macOS). Set `ENABLE_CODE_EXECUTION=false` on shared servers – it is still code execution, treat it accordingly.

## SAST rules
SQL injection · OS command injection · eval/exec · insecure deserialization (pickle/yaml) · hardcoded secrets · XSS ·
path traversal · TLS verification disabled · JWT signature disabled · weak hashing (MD5/SHA-1) · weak randomness ·
insecure password comparison · debug mode. Each rule has CWE/OWASP mapping, explanation and a **deterministic secure fix**, so the
scan → fix → re-scan loop converges to code the engine rates 100/100.

**Score** = 100 − (25 × critical + 15 × high + 8 × medium + 3 × low), minimum 0. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.

## Optional external AI
Put `ANTHROPIC_API_KEY` in `backend/.env` to let an LLM rewrite the explanations. Secure code always comes from the
engine's validated fixers, never directly from an LLM.

## Tests
`cd backend && python tests/test_engine.py` (or `pytest`) – covers detection, scoring, fix-loop convergence, executor.

## Project layout
```
securecode-ai/
├─ backend/app/{main.py, models.py, schemas.py, core/(config,database,security), routers/, services/(sast_engine, ai_service, executor, report, ...)}
├─ frontend/src/{pages/, components/, context/, api/, hooks/}
├─ database/schema.sql
└─ run.sh / run.bat
```
Troubleshooting: **“Cannot reach the backend”** → the backend is not running; start it with `run.bat`/`run.sh`.
