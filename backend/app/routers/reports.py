from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..core.config import settings
from ..core.database import get_db
from ..core.security import client_ip, get_current_user
from ..models import Scan, User
from ..serializers import finding_dict, scan_dict
from ..services import report
from ..services.scan_service import audit

router = APIRouter(prefix="/api/reports", tags=["reports"])

MIME = {"pdf": "application/pdf", "html": "text/html; charset=utf-8", "json": "application/json"}


@router.get("/{scan_id}")
def download_report(
    scan_id: int, request: Request, format: str = Query("pdf", pattern="^(pdf|html|json)$"),
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    scan = db.scalar(select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not scan:
        raise HTTPException(404, "Scan not found.")
    chain, cur = [scan], scan
    while cur.parent_scan_id:
        cur = db.get(Scan, cur.parent_scan_id)
        if not cur or cur.user_id != user.id:
            break
        chain.append(cur)
    history = [
        {"id": s.id, "kind": s.kind, "iteration": s.iteration, "score": s.score, "total_findings": s.total_findings, "created_at": s.created_at.isoformat()}
        for s in reversed(chain)
    ]
    s = scan_dict(scan, with_findings=False, with_code=False)
    data = {
        "app": settings.APP_NAME, "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), "user_name": user.name,
        "scan": s, "findings": [finding_dict(f) for f in scan.findings], "history": history,
    }
    builder = {"pdf": report.build_pdf, "html": report.build_html, "json": report.build_json}[format]
    content = builder(data)
    audit(db, user.id, "report_downloaded", f"scan #{scan.id} {format}", client_ip(request))
    db.commit()
    stem = "".join(c if c.isalnum() or c in "-_" else "_" for c in scan.filename.rsplit(".", 1)[0]) or "scan"
    return Response(content=content, media_type=MIME[format],
                    headers={"Content-Disposition": f'attachment; filename="security-report-{stem}-{scan.id}.{format}"'})
