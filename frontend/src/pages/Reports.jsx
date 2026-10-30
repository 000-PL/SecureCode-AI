import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, downloadFile } from "../api/client.js";
import { useToast } from "../components/Toast.jsx";
import { Empty, ErrorBox, Loading, Spinner, fmtDate, langName } from "../components/Ui.jsx";

export default function Reports() {
  const toast = useToast();
  const [items, setItems] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  const load = () => {
    setError("");
    api("/scans?status=success&limit=100").then((r) => setItems(r.items)).catch((e) => setError(e.message));
  };
  useEffect(load, []);

  async function get(scan, format) {
    const k = `${scan.id}-${format}`;
    setBusy(k);
    try {
      await downloadFile(`/reports/${scan.id}?format=${format}`, `report-${scan.id}.${format}`);
    } catch (e) {
      toast(e.message, "err");
    } finally {
      setBusy("");
    }
  }

  if (error) return <ErrorBox message={error} onRetry={load} />;
  if (!items) return <Loading label="Loading reports..." />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Security Reports</h1>
          <p>Every report contains the security score, vulnerabilities, remediation and validation history. Download as PDF, HTML or JSON.</p>
        </div>
      </div>
      {items.length === 0 ? (
        <Empty icon="📄" title="No reports yet" text="Reports are generated from successful scans." to="/editor" action="Start a new scan" />
      ) : (
        <div className="card">
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>Scan</th><th>File</th><th>Language</th><th>Type</th><th>Score</th><th>Findings</th><th>Date</th><th>Download</th></tr></thead>
              <tbody>
                {items.map((s) => (
                  <tr key={s.id}>
                    <td><Link to={`/results/${s.id}`}>#{s.id}</Link></td>
                    <td>{s.filename}</td>
                    <td>{langName(s.language)}</td>
                    <td>{s.kind === "validation" ? `Validation ${s.iteration - 1}` : "Scan"}</td>
                    <td><b>{s.score}</b> <span className="muted">({s.grade})</span></td>
                    <td>{s.total_findings}</td>
                    <td className="muted small">{fmtDate(s.created_at)}</td>
                    <td>
                      <div className="row" style={{ gap: 6 }}>
                        {["pdf", "html", "json"].map((f) => (
                          <button key={f} className="btn sm" disabled={busy !== ""} onClick={() => get(s, f)}>
                            {busy === `${s.id}-${f}` ? <Spinner /> : f.toUpperCase()}
                          </button>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}
