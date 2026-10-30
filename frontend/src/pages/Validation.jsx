import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, downloadFile } from "../api/client.js";
import { useToast } from "../components/Toast.jsx";
import { Empty, ErrorBox, Loading, ScoreRing, SeverityBadge, Spinner, Stepper } from "../components/Ui.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useWorkspace } from "../context/WorkspaceContext.jsx";
import useScan from "../hooks/useScan.js";

const key = (f) => `${f.rule_id}|${f.snippet}`;

export default function Validation() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { user } = useAuth();
  const ws = useWorkspace();
  const { scan, loading, error, reload } = useScan(id);
  const [parent, setParent] = useState(null);
  const [busy, setBusy] = useState(false);
  const [dl, setDl] = useState(false);

  useEffect(() => {
    setParent(null);
    if (scan && scan.kind === "validation" && scan.parent_scan_id) {
      api(`/scans/${scan.parent_scan_id}`).then(setParent).catch(() => setParent(null));
    }
  }, [scan]);

  if (loading) return <Loading label="Loading..." />;
  if (error) return <ErrorBox message={error} onRetry={reload} />;
  if (!scan) return <Empty icon="🔁" title="Nothing to validate yet" text="Scan code and apply a fix first. Validation re-scans the corrected code." to="/editor" action="Start a new scan" />;

  const isResult = scan.kind === "validation";
  const editorCode = ws.scanId === scan.id && ws.code ? ws.code : scan.code;
  const unchanged = editorCode === scan.code;

  async function runValidation() {
    setBusy(true);
    try {
      const res = await api(`/scans/${scan.id}/validate`, {
        method: "POST",
        body: { code: editorCode, filename: scan.filename, language: scan.language, run_code: user?.settings?.run_code_on_validation !== false },
      });
      const next = res.scan;
      ws.update({ scanId: next.id, code: next.code, filename: next.filename, language: next.language });
      if (next.status === "success") toast(next.total_findings === 0 ? "Validation passed - no vulnerabilities remain." : `Validation complete - ${next.total_findings} issue(s) remain.`);
      else toast("Validation scan unsuccessful", "err");
      navigate(`/validation/${next.id}`);
    } catch (e) {
      toast(e.message, "err");
    } finally {
      setBusy(false);
    }
  }

  async function download() {
    setDl(true);
    try {
      await downloadFile(`/reports/${scan.id}?format=${user?.settings?.default_report_format || "pdf"}`, `report-${scan.id}`);
    } catch (e) {
      toast(e.message, "err");
    } finally {
      setDl(false);
    }
  }

  // ---------- state 1: ready to validate ----------
  if (!isResult) {
    return (
      <>
        <Stepper current="validation" scanId={scan.id} />
        <div className="page-head">
          <div>
            <h1>Fix Validation</h1>
            <p>The code currently in your editor is executed and scanned again, completely, to verify the fix and catch any new issue.</p>
          </div>
        </div>
        {scan.status !== "success" ? (
          <div className="alert bad"><div>The scan this validation belongs to was unsuccessful: {scan.error}</div></div>
        ) : (
          <div className="card">
            <h2>Code that will be re-scanned</h2>
            {unchanged && (
              <div className="alert warn mb">
                <div>The code is identical to the scanned version. Apply a fix in <Link to={`/remediation/${scan.id}`}>Remediation</Link> (or edit the code) before validating, or validate anyway.</div>
              </div>
            )}
            <pre className="code" style={{ maxHeight: 340, overflow: "auto" }}>{editorCode}</pre>
            <div className="row mt">
              <button className="btn primary" onClick={runValidation} disabled={busy || !editorCode.trim()}>
                {busy ? <Spinner label="Re-scanning entire code..." /> : "🔁 Validate fix (re-scan entire code)"}
              </button>
              <button className="btn" onClick={() => navigate("/editor")}>Edit code</button>
            </div>
          </div>
        )}
      </>
    );
  }

  // ---------- state 2: validation result ----------
  const failed = scan.status !== "success";
  const prevKeys = parent ? new Set(parent.findings.map(key)) : null;
  const curKeys = new Set(scan.findings.map(key));
  const resolved = parent ? parent.findings.filter((f) => !curKeys.has(key(f))) : [];
  const newIssues = prevKeys ? scan.findings.filter((f) => !prevKeys.has(key(f))) : [];
  const secure = !failed && scan.total_findings === 0;

  return (
    <>
      <Stepper current="validation" scanId={scan.id} />
      <div className="page-head">
        <div>
          <h1>Fix Validation <span className="muted">· round {scan.iteration - 1}</span></h1>
          <p>Scan #{scan.id} re-scanned the full code after your changes.</p>
        </div>
      </div>

      {failed ? (
        <div className="alert bad mb"><div><div className="title">Validation scan unsuccessful</div><div>{scan.error}</div></div></div>
      ) : secure ? (
        <div className="alert ok mb">
          <div className="grow"><div className="title">✅ Secure code verified</div><div>The re-scan found no vulnerabilities. The loop is complete - download the final report.</div></div>
          <button className="btn good" onClick={download} disabled={dl}>⬇ Download report</button>
        </div>
      ) : (
        <div className="alert warn mb">
          <div className="grow"><div className="title">Vulnerabilities remain</div><div>{scan.total_findings} issue(s) were detected in the corrected code. Continue the loop: explain, fix and validate again.</div></div>
          <button className="btn primary" onClick={() => navigate(`/ai-fix/${scan.id}`)}>✨ Continue with AI Fix</button>
        </div>
      )}

      {!failed && (
        <div className="grid g3 mb">
          <div className="card row" style={{ gap: 20 }}>
            <ScoreRing score={scan.score} grade={scan.grade} size={130} />
            <div>
              <div className="muted small">Score change</div>
              <div style={{ fontSize: 26, fontWeight: 700 }}>{parent ? `${parent.score} → ${scan.score}` : scan.score}</div>
              {parent && <div className={scan.score >= parent.score ? "pill ok" : "pill bad"}>{scan.score - parent.score >= 0 ? "+" : ""}{scan.score - parent.score} points</div>}
            </div>
          </div>
          <div className="card stat"><div className="label">Vulnerabilities resolved</div><div className="value" style={{ color: "var(--ok)" }}>{parent ? resolved.length : "-"}</div><div className="hint">of {parent ? parent.total_findings : "-"} in the previous scan</div></div>
          <div className="card stat"><div className="label">Remaining / new</div><div className="value" style={{ color: scan.total_findings ? "var(--bad)" : "var(--ok)" }}>{scan.total_findings}</div><div className="hint">{newIssues.length} newly introduced</div></div>
        </div>
      )}

      {!failed && <div className="card mb"><b>Score explanation:</b> {scan.explanation}</div>}

      {scan.execution && (
        <div className="card mb">
          <div className="row between"><h3>Execution check</h3><span className={`pill ${scan.execution.status === "passed" ? "ok" : "bad"}`}>{scan.execution.status}{scan.execution.exit_code != null ? ` (exit ${scan.execution.exit_code})` : ""}</span></div>
          <pre className="output">{(scan.execution.stdout || "") + (scan.execution.stderr ? `\n${scan.execution.stderr}` : "") || "(no output)"}</pre>
        </div>
      )}

      {!failed && scan.findings.length > 0 && (
        <div className="card mb">
          <h2>Remaining issues</h2>
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>Severity</th><th>Vulnerability</th><th>Line</th><th>Origin</th></tr></thead>
              <tbody>
                {scan.findings.map((f) => (
                  <tr key={f.id}><td><SeverityBadge severity={f.severity} /></td><td>{f.title}</td><td>{f.line}</td><td>{prevKeys ? (prevKeys.has(key(f)) ? "Not fixed yet" : "New issue") : "-"}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="row">
        <button className="btn" onClick={() => navigate("/editor")}>Open code in editor</button>
        <button className="btn" onClick={() => navigate(`/results/${scan.id}`)}>Full scan results</button>
        {!secure && !failed && <button className="btn" onClick={runValidation} disabled={busy}>{busy ? <Spinner label="Re-scanning..." /> : "Validate again"}</button>}
      </div>
    </>
  );
}
