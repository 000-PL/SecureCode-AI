"""SecureCode AI - FastAPI application entry point."""
import logging
import shutil
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import text

from . import models  # noqa: F401  (register tables)
from .core.config import settings
from .core.database import Base, SessionLocal, engine
from .core.security import RateLimitMiddleware, SecurityHeadersMiddleware
from .routers import auth, dashboard, reports, scans, settings_router, tools

logger = logging.getLogger("securecode")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    logger.info("Database ready (%s)", "MySQL" if settings.DATABASE_URL.startswith("mysql") else "SQLite")
    yield


app = FastAPI(title=settings.APP_NAME, version="1.0.0", lifespan=lifespan)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], allow_headers=["Authorization", "Content-Type"],
)

for r in (auth.router, scans.router, tools.router, dashboard.router, reports.router, settings_router.router):
    app.include_router(r)


@app.get("/api/health", tags=["system"])
def health():
    db_ok = True
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded", "database": "ok" if db_ok else "error", "sast_engine": "ready",
        "code_execution": settings.ENABLE_CODE_EXECUTION, "node_available": bool(shutil.which("node")),
        "ai": "external" if settings.ANTHROPIC_API_KEY else "built-in",
    }


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse({"detail": "Internal server error. Please try again."}, status_code=500)


# ---- serve the built React app (frontend/dist) from the same server -----------------------------
dist = settings.FRONTEND_DIST


@app.get("/{full_path:path}", include_in_schema=False)
def spa(full_path: str):
    if full_path.startswith("api/"):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    if dist.exists():
        candidate = (dist / full_path).resolve()
        if full_path and candidate.is_file() and str(candidate).startswith(str(dist.resolve())):
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")
    return JSONResponse({
        "message": "SecureCode AI API is running. The frontend is not built yet.",
        "dev": "Run 'npm install && npm run dev' inside /frontend and open http://localhost:5173",
        "production": "Run 'npm run build' inside /frontend, then reload this page.",
        "docs": "/docs",
    })
