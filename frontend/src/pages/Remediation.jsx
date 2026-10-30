import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client.js";
import { useToast } from "../components/Toast.jsx";
import { Empty, ErrorBox, Loading, Spinner, SeverityBadge, SEV_ORDER, Stepper } from "../components/Ui.jsx";
import { useWorkspace } from "../context/WorkspaceContext.jsx";
import useScan from "../hooks/useScan.js";

function SideBySide({ fix }) {
  return (
    <div>
      {fix.edits.map((e) => (
        <div key={e.line} className="mb" style={{ marginBottom: 14 }}>
          <div className="diff">
            <div className="col before">
              <h4>✖ Vulnerable code</h4>
              <div className="lineno">line {e.line}</div>
              <pre>{e.before}</pre>
            </div>
            <div className="col after">
              <h4>✔ Secure code</h4>
              <div className="lineno">replaces line {e.line}</div>
              <pre>{e.after}</pre>
            </div>
          </div>
        </div>
      ))}
      {fix.prelude && fix.prelude.length > 0 && (
        <div className="diff">
          <div className="col before"><h4>Top of file</h4><pre>(nothing required before)</pre></div>
          <div className="col after"><h4>✔ Add at top of file</h4><pre>{fix.prelude.join("\n")}</pre></div>
        </div>
      )}
    </div>
  );
}

export default function Remediation() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const toast = useToast();
  const ws = useWorkspace();
  const { scan, loading, error, reload } = useScan(id);
  const [busy, setBusy] = useState("");
  const [applied, setApplied] = useState({});
  const [lastMsg, setLastMsg] = useState("");

  useEffect(() => {
    setApplied({});
    setLastMsg("");
  }, [id]);

  if (loading) return <Loading label="Loading remediation..." />;
  if (error) return <ErrorBox message={error} onRetry={reload} />;
  if (!scan) return <Empty icon="🔧" title="No remediation yet" text="Scan some code first. Secure fixes are generated for every vulnerability found." to="/editor" action="Start a new scan" />;
  if (scan.status !== "success") return <Empty icon="⚠️" title="This scan was unsuccessful" text={scan.error} to="/editor" action="Back to editor" />;

  const findings = [...scan.findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || a.line - b.line);
  if (findings.length === 0) {
    return (
      <div className="card empty">
        <div className="big">✅</div>
        <h2>Code is secure - nothing to remediate</h2>
        <Link to="/reports" className="btn primary">Download report</Link>
      </div>
    );
  }
  const selected = findings.find((f) => f.id === Number(params.get("f"))) || findings[0];
  const currentCode = ws.scanId === scan.id && ws.code ? ws.code : scan.code;
  const anyApplied = Object.keys(applied).length > 0;

  async function apply(body, key) {
    setBusy(key);
    try {
      const res = await api(`/scans/${scan.id}/apply-fix`, { method: "POST", body: { ...body, code: currentCode } });
      if (res.applied) {
        ws.update({ code: res.code, scanId: scan.id, filename: scan.filename, language: scan.language });
        setApplied((a) => (body.apply_all ? { ...a, all: true } : { ...a, [body.finding_id]: true }));
        setLastMsg(body.apply_all ? `${res.message} The editor now contains the corrected code.` : "Fix applied - the editor now contains the corrected code.");
        toast("Changes applied to the code editor");
      } else {
        toast(res.message, "err");
        setLastMsg(res.message);
      }
    } catch (e) {
      toast(e.message, "err");
    } finally {
      setBusy("");
    }
  }

  return (
    <>
      <Stepper current="remediation" scanId={scan.id} />
      <div className="page-head">
        <div>
          <h1>Remediation</h1>
          <p>Compare the vulnerable code with the secure replacement, then apply it to your editor.</p>
        </div>
        <button className="btn good" disabled={busy !== ""} onClick={() => apply({ apply_all: true }, "all")}>
          {busy === "all" ? <Spinner label="Applying..." /> : "⚡ Apply all fixes"}
        </button>
      </div>

      <div className="split">
        <div>
          {findings.map((f) => (
            <button key={f.id} className={`list-item ${f.id === selected.id ? "active" : ""}`} onClick={() => setParams({ f: String(f.id) })}>
              <div className="row between">
                <SeverityBadge severity={f.severity} />
                <span className="small">{applied[f.id] || applied.all ? <span className="pill ok">applied</span> : <span className="muted">line {f.line}</span>}</span>
              </div>
              <div style={{ fontWeight: 600, marginTop: 6 }}>{f.title}</div>
            </button>
          ))}
        </div>

        <div className="card">
          <div className="row between">
            <h2 style={{ margin: 0 }}>{selected.title}</h2>
            <span className="pill">{selected.cwe}</span>
          </div>
          <p className="muted small">Line {selected.line} · {selected.owasp}</p>
          <p>{selected.how_to_fix}</p>

          <h3 className="mt">Error code vs. corrected code</h3>
          {selected.fixable && selected.fix ? (
            <SideBySide fix={selected.fix} />
          ) : (
            <div className="alert warn"><div>No automatic fix is available for this finding. Edit the highlighted line manually in the editor.</div></div>
          )}

          <div className="row mt">
            <button className="btn primary" disabled={!selected.fixable || busy !== "" || applied[selected.id] || applied.all} onClick={() => apply({ finding_id: selected.id }, `f${selected.id}`)}>
              {busy === `f${selected.id}` ? <Spinner label="Applying..." /> : applied[selected.id] || applied.all ? "✓ Applied to editor" : "Apply changes"}
            </button>
            <Link className="btn" to={`/ai-fix/${scan.id}?f=${selected.id}`}>← Back to AI explanation</Link>
          </div>
        </div>
      </div>

      {(anyApplied || lastMsg) && (
        <div className={`alert ${anyApplied ? "ok" : "warn"} mt`}>
          <div className="grow">
            <div className="title">{anyApplied ? "Changes applied" : "Not applied"}</div>
            <div>{lastMsg}</div>
          </div>
          {anyApplied && (
            <div className="row">
              <button className="btn" onClick={() => navigate("/editor")}>View code in editor</button>
              <button className="btn primary" onClick={() => navigate(`/validation/${scan.id}`)}>Validate fix →</button>
            </div>
          )}
        </div>
      )}
    </>
  );
}
