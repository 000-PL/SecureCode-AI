from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..core.config import settings as app_settings
from ..core.database import get_db
from ..core.security import get_current_user
from ..models import User
from ..schemas import DEFAULT_SETTINGS, SettingsIn

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
def read_settings(user: User = Depends(get_current_user)):
    return {
        "settings": {**DEFAULT_SETTINGS, **(user.settings or {})},
        "system": {
            "code_execution": app_settings.ENABLE_CODE_EXECUTION,
            "external_ai_configured": bool(app_settings.ANTHROPIC_API_KEY),
            "database": "MySQL" if app_settings.DATABASE_URL.startswith("mysql") else "SQLite",
            "execution_timeout": app_settings.EXECUTION_TIMEOUT,
        },
    }


@router.put("")
def update_settings(body: SettingsIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    user.settings = body.model_dump()
    db.add(user)
    db.commit()
    return {"settings": user.settings}
