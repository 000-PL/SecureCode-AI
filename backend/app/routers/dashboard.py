from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.database import get_db
from ..core.security import get_current_user
from ..models import Finding, Scan, User
from ..serializers import scan_dict

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
def dashboard(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    base = [Scan.user_id == user.id]
    ok = [*base, Scan.status == "success"]
    total_scans = db.scalar(select(func.count()).select_from(Scan).where(*base, Scan.kind == "scan")) or 0
    validations = db.scalar(select(func.count()).select_from(Scan).where(*base, Scan.kind == "validation")) or 0
    failed = db.scalar(select(func.count()).select_from(Scan).where(*base, Scan.status == "failed")) or 0
    week_ago = datetime.utcnow() - timedelta(days=7)
    this_week = db.scalar(select(func.count()).select_from(Scan).where(*base, Scan.created_at >= week_ago)) or 0
    recent_scores = db.scalars(select(Scan.score).where(*ok).order_by(Scan.id.desc()).limit(20)).all()
    avg_score = round(sum(recent_scores) / len(recent_scores)) if recent_scores else None
    secure = db.scalar(select(func.count()).select_from(Scan).where(*ok, Scan.total_findings == 0)) or 0

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_vulns = 0
    for counts, n in db.execute(select(Scan.counts, Scan.total_findings).where(*ok, Scan.kind == "scan")).all():
        total_vulns += n or 0
        for k, v in (counts or {}).items():
            if k in sev:
                sev[k] += v

    top = db.execute(
        select(Finding.title, func.count(Finding.id).label("n")).join(Scan, Scan.id == Finding.scan_id)
        .where(Scan.user_id == user.id, Scan.kind == "scan").group_by(Finding.title).order_by(func.count(Finding.id).desc()).limit(6)
    ).all()

    trend_rows = db.scalars(select(Scan).where(*ok).order_by(Scan.id.desc()).limit(12)).all()
    trend = [{"id": s.id, "score": s.score, "filename": s.filename, "kind": s.kind, "date": s.created_at.isoformat() + "Z"} for s in reversed(trend_rows)]
    recent = db.scalars(select(Scan).where(*base).order_by(Scan.id.desc()).limit(6)).all()

    return {
        "total_scans": total_scans, "validations": validations, "failed_scans": failed, "scans_this_week": this_week,
        "avg_score": avg_score, "secure_scans": secure, "total_vulnerabilities": total_vulns, "severity": sev,
        "top_vulnerabilities": [{"title": t, "count": n} for t, n in top], "score_trend": trend,
        "recent": [scan_dict(s, with_findings=False, with_code=False) for s in recent],
    }
