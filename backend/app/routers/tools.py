from fastapi import APIRouter, Depends

from ..core.security import get_current_user
from ..models import User
from ..schemas import DetectIn, RunIn
from ..services import executor
from ..services.language import SUPPORTED, detect_language, display_name

router = APIRouter(prefix="/api", tags=["tools"])


@router.post("/detect-language")
def detect(body: DetectIn, user: User = Depends(get_current_user)):
    lang = detect_language(body.code, body.filename)
    return {"language": lang, "name": display_name(lang), "supported": lang in SUPPORTED}


@router.post("/run")
def run(body: RunIn, user: User = Depends(get_current_user)):
    lang = (body.language or "").lower() or detect_language(body.code, body.filename)
    return {"language": lang, **executor.run_code(body.code, lang, body.stdin)}
