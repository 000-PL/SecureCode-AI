import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client.js";
import { Empty, ErrorBox, Loading, SeverityBadge, SEV_ORDER, Stepper } from "../components/Ui.jsx";
import useScan from "../hooks/useScan.js";

export default function AIFix() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const { scan, loading, error, reload } = useScan(id);
  const [ai, setAi] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState("");

  const findings = scan ? [...scan.findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || a.line - b.line) : [];
  const selectedId = Number(params.get("f")) || (findings[0] && findings[0].id) || null;

  useEffect(() => {
    if (!scan || !selectedId) return undefined;
    let alive = true;
    setAiLoading(true);
    setAiError("");
    api(`/scans/${scan.id}/findings/${selectedId}/ai`)
      .then((r) => alive && setAi(r))
      .catch((e) => alive && setAiError(e.message))
      .finally(() => alive && setAiLoading(false));
    return () => {
      alive = false;
    };
  }, [scan, selectedId]);

  if (loading) return <Loading label="Loading analysis..." />;
  if (error) return <ErrorBox message={error} onRetry={reload} />;
  if (!scan) return <Empty icon="✨" title="Nothing to analyse yet" text="Scan some code first, then the AI will explain every vulnerability." to="/editor" action="Start a new scan" />;
  if (scan.status !== "success") return <Empty icon="⚠️" title="This scan was unsuccessful" text={scan.error} to="/editor" action="Back to editor" />;

  return (
    <>
      <Stepper current="ai" scanId={scan.id} />
      <div className="page-head">
        <div>
          <h1>AI Vulnerability Analysis</h1>
          <p>Scan #{scan.id} · {scan.filename} · score {scan.score}/100</p>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="card empty">
          <div className="big">✅</div>
          <h2>No vulnerabilities to explain</h2>
          <p className="muted">This code passed the SAST scan. You can download the report now.</p>
          <Link className="btn primary" to="/reports">Go to reports</Link>
        </div>
      ) : (
        <div className="split">
          <div>
            <div className="small muted mb" style={{ marginBottom: 8 }}>{findings.length} vulnerabilit{findings.length === 1 ? "y" : "ies"} - choose one</div>
            {findings.map((f) => (
              <button key={f.id} className={`list-item ${f.id === selectedId ? "active" : ""}`} onClick={() => setParams({ f: String(f.id) })}>
                <div className="row between"><SeverityBadge severity={f.severity} /><span className="small muted">line {f.line}</span></div>
                <div style={{ fontWeight: 600, marginTop: 6 }}>{f.title}</div>
              </button>
            ))}
          </div>

          <div className="card">
            {aiLoading && <Loading label="AI is analysing this vulnerability..." />}
            {aiError && <ErrorBox message={aiError} />}
            {!aiLoading && !aiError && ai && (
              <>
                <div className="row between">
                  <h2 style={{ margin: 0 }}>{ai.finding.title}</h2>
                  <div className="row"><SeverityBadge severity={ai.finding.severity} /><span className="pill">{ai.finding.cwe}</span></div>
                </div>
                <p className="muted small">{ai.finding.owasp} · line {ai.finding.line} · explanation by {ai.explanation.source === "llm" ? "external AI service" : "built-in AI knowledge base"}</p>

                <h3 className="mt">Vulnerable code</h3>
                <pre className="code">{`${ai.finding.line}  ${ai.finding.snippet}`}</pre>

                <h3 className="mt">What is the problem?</h3>
                <p>{ai.explanation.summary}</p>
                <h3>What caused it?</h3>
                <p>{ai.explanation.cause}</p>
                <h3>What can an attacker do? (impact)</h3>
                <p>{ai.explanation.impact}</p>
                <h3>How to solve it</h3>
                <p>{ai.explanation.how_to_fix}</p>
                <ol className="steps">{ai.explanation.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>

                <div className="row mt">
                  <button className="btn primary" onClick={() => navigate(`/remediation/${scan.id}?f=${selectedId}`)}>
                    🔧 See the secure fix (Remediation)
                  </button>
                  {!ai.fixable && <span className="pill bad">No automatic fix - edit manually</span>}
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}
