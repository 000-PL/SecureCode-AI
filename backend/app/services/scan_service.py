"""Orchestrates: SAST scan -> persist -> (optional) execution -> comparison with the previous scan."""
import time

from sqlalchemy.orm import Session

from ..core.security import safe_filename
from ..models import AuditLog, Finding, Scan, User
from . import executor
from .sast_engine import scan_code


def audit(db: Session, user_id, action: str, detail: str = "", ip: str = "") -> None:
    db.add(AuditLog(user_id=user_id, action=action, detail=detail[:255], ip=ip[:64]))


def perform_scan(db: Session, user: User, code: str, filename: str | None, language: str | None,
                 kind: str = "scan", parent: Scan | None = None, run_code: bool = False, ip: str = "") -> Scan:
    started = time.time()
    result = scan_code(code, language, filename)
    ok = result["status"] == "success"
    lang = result.get("language", "unknown")
    scan = Scan(
        user_id=user.id, filename=safe_filename(filename or (parent.filename if parent else None)), language=lang,
        code=(code or "").replace("\r\n", "\n"), status=result["status"], error=result.get("error"), kind=kind,
        parent_scan_id=parent.id if parent else None, iteration=(parent.iteration + 1) if parent else 1,
    )
    if ok:
        scan.score, scan.grade, scan.rating = result["score"], result["grade"], result["rating"]
        scan.explanation, scan.counts, scan.breakdown = result["explanation"], result["counts"], result["breakdown"]
        scan.total_findings, scan.lines_scanned = len(result["findings"]), result.get("lines_scanned", 0)
    else:
        scan.score, scan.grade, scan.rating, scan.explanation = 0, "-", "Scan failed", result.get("error") or "Scan failed"
        scan.counts, scan.breakdown = {}, []
    if ok and run_code:
        scan.execution = executor.run_code(scan.code, lang)
    scan.duration_ms = int((time.time() - started) * 1000)
    db.add(scan)
    db.flush()
    if ok:
        for f in result["findings"]:
            db.add(Finding(
                scan_id=scan.id, rule_id=f["rule_id"], title=f["title"], severity=f["severity"], cwe=f["cwe"], owasp=f["owasp"],
                line=f["line"], snippet=f["snippet"], message=f["message"], cause=f["cause"], impact=f["impact"],
                how_to_fix=f["how_to_fix"], fixable=f["fixable"], fix=f["fix"],
            ))
    audit(db, user.id, f"{kind}_{'ok' if ok else 'failed'}", f"scan #{scan.id} {scan.filename}", ip)
    db.commit()
    db.refresh(scan)
    return scan


def compare(previous: Scan, current: Scan) -> dict:
    """Describe what changed between the scan that was fixed and the validation re-scan."""
    prev_keys = [(f.rule_id, f.snippet) for f in previous.findings]
    cur_keys = [(f.rule_id, f.snippet) for f in current.findings]
    remaining_same = [k for k in cur_keys if k in prev_keys]
    new_issues = [f for f in current.findings if (f.rule_id, f.snippet) not in prev_keys]
    resolved = max(0, previous.total_findings - len(remaining_same))
    return {
        "previous_scan_id": previous.id, "previous_score": previous.score, "previous_findings": previous.total_findings,
        "current_score": current.score, "current_findings": current.total_findings, "resolved": resolved,
        "remaining": current.total_findings, "new_issues": [{"title": f.title, "line": f.line, "severity": f.severity} for f in new_issues],
        "score_change": current.score - previous.score, "is_secure": current.status == "success" and current.total_findings == 0,
    }
