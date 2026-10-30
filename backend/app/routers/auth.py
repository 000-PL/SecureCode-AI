from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.database import get_db
from ..core.security import client_ip, create_token, get_current_user, hash_password, password_problem, verify_password
from ..models import User
from ..schemas import DEFAULT_SETTINGS, LoginIn, RegisterIn
from ..services.scan_service import audit

router = APIRouter(prefix="/api/auth", tags=["auth"])
_DUMMY_HASH = hash_password("dummy-password-1")


def user_dict(u: User) -> dict:
    return {"id": u.id, "name": u.name, "email": u.email, "settings": {**DEFAULT_SETTINGS, **(u.settings or {})}}


@router.post("/register")
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    if not settings.ALLOW_REGISTRATION:
        raise HTTPException(403, "Registration is disabled by the administrator.")
    email = body.email.strip().lower()
    problem = password_problem(body.password)
    if problem:
        raise HTTPException(422, problem)
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "An account with this email already exists.")
    user = User(name=body.name.strip(), email=email, password_hash=hash_password(body.password), settings=dict(DEFAULT_SETTINGS))
    db.add(user)
    db.flush()
    audit(db, user.id, "register", email, client_ip(request))
    db.commit()
    return {"token": create_token(user.id), "user": user_dict(user)}


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not ok:
        audit(db, user.id if user else None, "login_failed", email, client_ip(request))
        db.commit()
        raise HTTPException(401, "Invalid email or password.")
    audit(db, user.id, "login", email, client_ip(request))
    db.commit()
    return {"token": create_token(user.id), "user": user_dict(user)}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user_dict(user)
