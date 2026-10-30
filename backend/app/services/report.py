"""Security report generation: JSON, HTML and PDF (all built from one data dictionary)."""
import html
import io
import json
from xml.sax.saxutils import escape as xml_escape

SEV_COLORS = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#64748b"}


def build_json(data: dict) -> bytes:
    return json.dumps(data, indent=2, default=str).encode("utf-8")


def _fix_text(f: dict) -> str:
    fix = f.get("fix")
    if not fix:
        return "No automatic fix available - edit manually."
    out = []
    for e in fix.get("edits", []):
        out.append(f"Line {e['line']}:\n  - {e['before'].strip()}\n  + " + e["after"].strip().replace("\n", "\n    "))
    if fix.get("prelude"):
        out.append("Add at top of file:\n  + " + "\n  + ".join(fix["prelude"]))
    return "\n".join(out)


def build_html(data: dict) -> bytes:
    s = data["scan"]
    e = html.escape
    rows = ""
    for b in s.get("breakdown", []):
        rows += f"<tr><td>{e(b['severity'].title())}</td><td>{b['count']}</td><td>-{b['weight']}</td><td>-{b['deduction']}</td></tr>"
    findings = ""
    for f in data["findings"]:
        color = SEV_COLORS.get(f["severity"], "#64748b")
        findings += f"""
        <div class="card"><h3><span class="badge" style="background:{color}">{e(f['severity'].upper())}</span> {e(f['title'])}
        <small>Line {f['line']} - {e(f['cwe'])}</small></h3>
        <pre>{e(f['snippet'])}</pre>
        <p><b>What:</b> {e(f['message'])}</p><p><b>Cause:</b> {e(f['cause'])}</p>
        <p><b>Impact:</b> {e(f['impact'])}</p><p><b>How to fix:</b> {e(f['how_to_fix'])}</p>
        <p><b>Secure code:</b></p><pre>{e(_fix_text(f))}</pre></div>"""
    if not findings:
        findings = "<p>No vulnerabilities were detected.</p>"
    hist = "".join(
        f"<tr><td>#{h['id']}</td><td>{e(str(h['kind']))} {h['iteration']}</td><td>{h['score']}</td><td>{h['total_findings']}</td><td>{e(str(h['created_at']))}</td></tr>"
        for h in data.get("history", [])
    )
    ex = s.get("execution")
    exec_html = ""
    if ex:
        exec_html = f"<h2>Functional test (execution)</h2><p>Status: <b>{e(str(ex.get('status')))}</b>, exit code: {e(str(ex.get('exit_code')))}</p><pre>{e((ex.get('stdout') or '') + (ex.get('stderr') or ''))}</pre>"
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Security Report #{s['id']}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:30px auto;color:#0f172a;padding:0 16px}}
h1{{margin-bottom:0}}table{{border-collapse:collapse;width:100%;margin:10px 0}}td,th{{border:1px solid #cbd5e1;padding:6px 10px;text-align:left}}
th{{background:#f1f5f9}}pre{{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;white-space:pre-wrap}}
.card{{border:1px solid #cbd5e1;border-radius:8px;padding:10px 16px;margin:12px 0}}.badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px}}
.score{{font-size:48px;font-weight:700}}small{{color:#64748b;font-weight:400}}</style></head><body>
<h1>{e(data['app'])} - Security Report</h1><p>Generated {e(data['generated_at'])} for {e(data['user_name'])}</p>
<table><tr><th>File</th><td>{e(s['filename'])}</td><th>Language</th><td>{e(s['language'])}</td></tr>
<tr><th>Scan</th><td>#{s['id']} ({e(s['kind'])} {s['iteration']})</td><th>Lines scanned</th><td>{s['lines_scanned']}</td></tr></table>
<h2>Security score</h2><p class="score">{s['score']}/100 <small>Grade {e(s['grade'])} - {e(s['rating'])}</small></p>
<p>{e(s['explanation'])}</p>
<table><tr><th>Severity</th><th>Findings</th><th>Weight</th><th>Deduction</th></tr>{rows}</table>
<h2>Vulnerabilities ({s['total_findings']})</h2>{findings}
{exec_html}
<h2>Fix validation history</h2><table><tr><th>Scan</th><th>Type</th><th>Score</th><th>Findings</th><th>Date</th></tr>{hist}</table>
</body></html>"""
    return doc.encode("utf-8")


def build_pdf(data: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

    s = data["scan"]
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    code = ParagraphStyle("code", parent=styles["Code"], fontSize=8, leading=10, backColor=colors.HexColor("#f1f5f9"), borderPadding=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#0f172a"))
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"Security Report #{s['id']}", author=data["app"])

    def P(text, style=body):
        return Paragraph(xml_escape(str(text)), style)

    def wrap_code(text, width=95):
        lines = []
        for ln in str(text).split("\n"):
            while len(ln) > width:
                lines.append(ln[:width])
                ln = "    " + ln[width:]
            lines.append(ln)
        return "\n".join(lines)

    story = [Paragraph(f"{xml_escape(data['app'])} - Security Report", styles["Title"]),
             P(f"Generated {data['generated_at']} for {data['user_name']}"), Spacer(1, 6)]
    meta = [["File", s["filename"], "Language", s["language"]],
            ["Scan", f"#{s['id']} ({s['kind']} {s['iteration']})", "Lines scanned", str(s["lines_scanned"])]]
    t = Table(meta, colWidths=[25 * mm, 62 * mm, 30 * mm, 55 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")), ("FONTSIZE", (0, 0), (-1, -1), 9),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")), ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f1f5f9"))]))
    story += [t, Paragraph("Security score", h2),
              Paragraph(f"<font size=26><b>{s['score']}/100</b></font> &nbsp; Grade {xml_escape(s['grade'])} - {xml_escape(s['rating'])}", body),
              Spacer(1, 4), P(s["explanation"])]
    if s.get("breakdown"):
        rows = [["Severity", "Findings", "Weight", "Deduction"]] + [[b["severity"].title(), b["count"], f"-{b['weight']}", f"-{b['deduction']}"] for b in s["breakdown"]]
        bt = Table(rows, colWidths=[40 * mm, 30 * mm, 30 * mm, 30 * mm])
        bt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("FONTSIZE", (0, 0), (-1, -1), 9)]))
        story += [Spacer(1, 6), bt]
    story.append(Paragraph(f"Vulnerabilities ({s['total_findings']})", h2))
    if not data["findings"]:
        story.append(P("No vulnerabilities were detected."))
    for f in data["findings"]:
        color = SEV_COLORS.get(f["severity"], "#64748b")
        block = [Paragraph(f"<font color='{color}'><b>[{f['severity'].upper()}]</b></font> <b>{xml_escape(f['title'])}</b> - line {f['line']} ({xml_escape(f['cwe'])})", body),
                 Preformatted(wrap_code(f["snippet"]), code),
                 Paragraph(f"<b>What:</b> {xml_escape(f['message'])}", body),
                 Paragraph(f"<b>Cause:</b> {xml_escape(f['cause'])}", body),
                 Paragraph(f"<b>Impact:</b> {xml_escape(f['impact'])}", body),
                 Paragraph(f"<b>How to fix:</b> {xml_escape(f['how_to_fix'])}", body),
                 Paragraph("<b>Secure code:</b>", body), Preformatted(wrap_code(_fix_text(f)), code), Spacer(1, 10)]
        story.append(KeepTogether(block[:3]))
        story += block[3:]
    ex = s.get("execution")
    if ex:
        story += [Paragraph("Functional test (execution)", h2), P(f"Status: {ex.get('status')}   Exit code: {ex.get('exit_code')}"),
                  Preformatted(wrap_code((ex.get("stdout") or "") + (ex.get("stderr") or "") or "(no output)"), code)]
    if data.get("history"):
        story.append(Paragraph("Fix validation history", h2))
        rows = [["Scan", "Type", "Score", "Findings", "Date"]] + [[f"#{h['id']}", f"{h['kind']} {h['iteration']}", h["score"], h["total_findings"], str(h["created_at"])[:19]] for h in data["history"]]
        ht = Table(rows)
        ht.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("FONTSIZE", (0, 0), (-1, -1), 9)]))
        story.append(ht)
    doc.build(story)
    return buf.getvalue()
