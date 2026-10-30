from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from ..core.database import get_db
from ..core.security import client_ip, get_current_user
from ..models import Finding, Scan, User
from ..schemas import DEFAULT_SETTINGS, ApplyFixIn, ScanIn, ValidateIn
from ..serializers import finding_dict, scan_dict
from ..services import ai_service
from ..services.sast_engine import apply_all_fixes, apply_fix
from ..services.scan_service import audit, compare, perform_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _own_scan(db: Session, user: User, scan_id: int) -> Scan:
    scan = db.scalar(select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return scan


@router.post("")
def create_scan(body: ScanIn, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not body.code.strip():
        raise HTTPException(400, "There is no code to scan. Write or upload some code first.")
    scan = perform_scan(db, user, body.code, body.filename, body.language, "scan", None, body.run_code, client_ip(request))
    return scan_dict(_own_scan(db, user, scan.id))


@router.get("")
def list_scans(
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), q: str | None = Query(None, max_length=100),
    status: str | None = Query(None, pattern="^(success|failed)$"),
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    cond = [Scan.user_id == user.id]
    if status:
        cond.append(Scan.status == status)
    if q:
        like = f"%{q.strip()}%"
        cond.append(or_(Scan.filename.like(like), Scan.language.like(like)))
    total = db.scalar(select(func.count()).select_from(Scan).where(*cond)) or 0
    rows = db.scalars(select(Scan).where(*cond).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(limit).offset(offset)).all()
    return {"items": [scan_dict(s, with_findings=False, with_code=False) for s in rows], "total": total}


@router.get("/latest")
def latest_scan(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = db.scalar(select(Scan).options(selectinload(Scan.findings)).where(Scan.user_id == user.id).order_by(Scan.id.desc()).limit(1))
    return scan_dict(scan) if scan else None


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return scan_dict(_own_scan(db, user, scan_id))


@router.delete("/{scan_id}")
def delete_scan(scan_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = _own_scan(db, user, scan_id)
    audit(db, user.id, "scan_deleted", f"scan #{scan.id}", client_ip(request))
    db.delete(scan)
    db.commit()
    return {"deleted": True}


@router.get("/{scan_id}/findings/{finding_id}/ai")
def ai_analysis(scan_id: int, finding_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = _own_scan(db, user, scan_id)
    finding = next((f for f in scan.findings if f.id == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    use_llm = {**DEFAULT_SETTINGS, **(user.settings or {})}["use_external_ai"]
    explanation = ai_service.explain_finding(finding, scan.language, use_llm)
    return {"finding": finding_dict(finding), "explanation": explanation, "remediation": finding.fix, "fixable": finding.fixable}


@router.post("/{scan_id}/apply-fix")
def apply_scan_fix(scan_id: int, body: ApplyFixIn, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = _own_scan(db, user, scan_id)
    code = body.code if body.code is not None and body.code.strip() else scan.code
    if body.apply_all:
        result = apply_all_fixes(code, scan.language)
        applied = result["applied"]
        message = result["message"]
    else:
        finding = next((f for f in scan.findings if f.id == body.finding_id), None)
        if not finding:
            raise HTTPException(404, "Finding not found.")
        result = apply_fix(code, scan.language, finding.rule_id, finding.line, finding.snippet)
        applied, message = result["applied"], result["message"]
    audit(db, user.id, "fix_applied" if applied else "fix_not_applied", f"scan #{scan.id}", client_ip(request))
    db.commit()
    return {"code": result["code"], "applied": applied, "message": message, "count": result.get("count", 1 if applied else 0)}


@router.post("/{scan_id}/validate")
def validate_fix(scan_id: int, body: ValidateIn, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    parent = _own_scan(db, user, scan_id)
    if not body.code.strip():
        raise HTTPException(400, "There is no code to validate.")
    run = body.run_code and {**DEFAULT_SETTINGS, **(user.settings or {})}["run_code_on_validation"]
    new = perform_scan(db, user, body.code, body.filename or parent.filename, body.language or parent.language,
                       "validation", parent, bool(run), client_ip(request))
    new = _own_scan(db, user, new.id)
    return {"scan": scan_dict(new), "comparison": compare(parent, new)}
