import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { downloadFile } from "../api/client.js";
import { useToast } from "../components/Toast.jsx";
import { Empty, ErrorBox, Loading, ScoreRing, SeverityBadge, SEV_ORDER, Stepper, fmtDate, langName } from "../components/Ui.jsx";
import useScan from "../hooks/useScan.js";
import { useAuth } from "../context/AuthContext.jsx";

export default function ScanResults() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { user } = useAuth();
  const { scan, loading, error, reload } = useScan(id);
  const [busy, setBusy] = useState(false);

  if (loading) return <Loading label="Loading scan results..." />;
  if (error) return <ErrorBox message={error} onRetry={reload} />;
  if (!scan) return <Empty icon="🔍" title="No scan results yet" text="Run a security scan first - results appear here." to="/editor" action="Start a new scan" />;

  const failed = scan.status !== "success";
  const fmt = user?.settings?.default_report_format || "pdf";

  async function download(format) {
    setBusy(true);
    try {
      await downloadFile(`/reports/${scan.id}?format=${format}`, `report-${scan.id}.${format}`);
    } catch (e) {
      toast(e.message, "err");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Stepper current="results" scanId={scan.id} />
      <div className="page-head">
        <div>
          <h1>Scan Results <span className="muted">#{scan.id}</span></h1>
          <p>{scan.filename} · {langName(scan.language)} · {fmtDate(scan.created_at)}{scan.kind === "validation" ? ` · Validation re-scan ${scan.iteration}` : ""}</p>
        </div>
        <div className="row">
          <Link to="/editor" className="btn">← Back to editor</Link>
          {!failed && <button className="btn" disabled={busy} onClick={() => download(fmt)}>⬇ Download report</button>}
        </div>
      </div>

      {failed ? (
        <div className="alert bad">
          <div>
            <div className="title">Scan unsuccessful</div>
            <div>{scan.error}</div>
            <div className="small muted" style={{ marginTop: 6 }}>Fix the problem in the editor and run the scan again.</div>
          </div>
        </div>
      ) : (
        <>
          <div className={`alert ${scan.total_findings === 0 ? "ok" : "warn"} mb`}>
            <div>
              <div className="title">Scan successful</div>
              <div>{scan.total_findings === 0 ? "No vulnerabilities were detected in this code." : `The SAST engine found ${scan.total_findings} vulnerabilit${scan.total_findings === 1 ? "y" : "ies"} in ${scan.lines_scanned} lines.`}</div>
            </div>
          </div>

          <div className="card mb">
            <div className="row" style={{ gap: 28, alignItems: "flex-start" }}>
              <ScoreRing score={scan.score} grade={scan.grade} />
              <div className="grow" style={{ minWidth: 260 }}>
                <h2>Security score: {scan.score}/100 <span className="muted" style={{ fontSize: 15 }}>({scan.rating})</span></h2>
                <p><b>How this score was calculated:</b> {scan.explanation}</p>
                {scan.breakdown.length > 0 && (
                  <table className="t">
                    <thead><tr><th>Severity</th><th>Findings</th><th>Points per finding</th><th>Deduction</th></tr></thead>
                    <tbody>
                      {scan.breakdown.map((b) => (
                        <tr key={b.severity}><td><SeverityBadge severity={b.severity} /></td><td>{b.count}</td><td>-{b.weight}</td><td>-{b.deduction}</td></tr>
                      ))}
                      <tr><td colSpan={3}><b>Final score</b></td><td><b>{scan.score}</b></td></tr>
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>

          <div className="card mb">
            <div className="row between mb">
              <h2 style={{ margin: 0 }}>Detected vulnerabilities</h2>
              {scan.total_findings > 0 && <button className="btn primary" onClick={() => navigate(`/ai-fix/${scan.id}`)}>✨ Explain &amp; fix with AI</button>}
            </div>
            {scan.total_findings === 0 ? (
              <p className="muted">Nothing to fix. Download the report or scan another file.</p>
            ) : (
              <div className="table-wrap">
                <table className="t">
                  <thead><tr><th>Severity</th><th>Vulnerability</th><th>Line</th><th>CWE</th><th>Code</th><th /></tr></thead>
                  <tbody>
                    {[...scan.findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || a.line - b.line).map((f) => (
                      <tr key={f.id}>
                        <td><SeverityBadge severity={f.severity} /></td>
                        <td><b>{f.title}</b></td>
                        <td>{f.line}</td>
                        <td>{f.cwe}</td>
                        <td><code className="small">{f.snippet.length > 70 ? f.snippet.slice(0, 70) + "…" : f.snippet}</code></td>
                        <td><Link to={`/ai-fix/${scan.id}?f=${f.id}`}>AI Fix →</Link></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {scan.execution && (
            <div className="card">
              <div className="row between"><h3>Functional test (code execution)</h3><span className={`pill ${scan.execution.status === "passed" ? "ok" : "bad"}`}>{scan.execution.status}</span></div>
              <pre className="output">{(scan.execution.stdout || "") + (scan.execution.stderr ? `\n${scan.execution.stderr}` : "") || "(no output)"}</pre>
            </div>
          )}
        </>
      )}
    </>
  );
}
