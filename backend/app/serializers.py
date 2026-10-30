"""ORM -> dict helpers used by the API and reports."""
from .models import Finding, Scan


def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id, "scan_id": f.scan_id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity, "cwe": f.cwe,
        "owasp": f.owasp, "line": f.line, "snippet": f.snippet, "message": f.message, "cause": f.cause, "impact": f.impact,
        "how_to_fix": f.how_to_fix, "fixable": f.fixable, "fix": f.fix,
    }


def scan_dict(s: Scan, with_findings: bool = True, with_code: bool = True) -> dict:
    d = {
        "id": s.id, "filename": s.filename, "language": s.language, "status": s.status, "error": s.error, "kind": s.kind,
        "parent_scan_id": s.parent_scan_id, "iteration": s.iteration, "score": s.score, "grade": s.grade, "rating": s.rating,
        "explanation": s.explanation, "counts": s.counts or {}, "breakdown": s.breakdown or [], "total_findings": s.total_findings,
        "lines_scanned": s.lines_scanned, "execution": s.execution, "duration_ms": s.duration_ms,
        "created_at": s.created_at.isoformat() + "Z" if s.created_at else None,
    }
    if with_code:
        d["code"] = s.code
    if with_findings:
        d["findings"] = [finding_dict(f) for f in s.findings]
    return d
