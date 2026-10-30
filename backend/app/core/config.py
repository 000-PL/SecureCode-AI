"""Application settings (environment variables / .env file)."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]          # .../backend
PROJECT_DIR = BASE_DIR.parent                           # project root


def _load_dotenv() -> None:
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _secret_key() -> str:
    key = os.getenv("SECRET_KEY", "").strip()
    if key:
        return key
    key_file = BASE_DIR / ".secret_key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_urlsafe(48)
    key_file.write_text(key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return key


class Settings:
    APP_NAME = "SecureCode AI"
    DATABASE_URL = os.getenv("DATABASE_URL", "").strip() or f"sqlite:///{BASE_DIR / 'securecode.db'}"
    SECRET_KEY = _secret_key()
    ALGORITHM = "HS256"
    ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "480"))
    CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8000").split(",") if o.strip()]
    ALLOW_REGISTRATION = _bool("ALLOW_REGISTRATION", True)
    ENABLE_CODE_EXECUTION = _bool("ENABLE_CODE_EXECUTION", True)
    EXECUTION_TIMEOUT = int(os.getenv("EXECUTION_TIMEOUT_SECONDS", "5"))
    RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MINUTE", "240"))
    AUTH_RATE_LIMIT = int(os.getenv("AUTH_RATE_LIMIT_PER_MINUTE", "20"))
    MAX_CODE_CHARS = 200_000
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
    AI_MODEL = os.getenv("AI_MODEL", "claude-sonnet-5-5")
    FRONTEND_DIST = PROJECT_DIR / "frontend" / "dist"


settings = Settings()
