import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, downloadFile } from "../api/client.js";
import { useToast } from "../components/Toast.jsx";
import { Empty, ErrorBox, Loading, fmtDate, langName } from "../components/Ui.jsx";
import { useWorkspace } from "../context/WorkspaceContext.jsx";

const PAGE = 15;

export default function History() {
  const toast = useToast();
  const ws = useWorkspace();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);

  const load = useCallback(() => {
    setError("");
    const p = new URLSearchParams({ limit: String(PAGE), offset: String(page * PAGE) });
    if (q.trim()) p.set("q", q.trim());
    if (status) p.set("status", status);
    api(`/scans?${p}`).then(setData).catch((e) => setError(e.message));
  }, [q, status, page]);

  useEffect(() => {
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
  }, [load]);

  async function remove(s) {
    if (!window.confirm(`Delete scan #${s.id} (${s.filename})? This cannot be undone.`)) return;
    try {
      await api(`/scans/${s.id}`, { method: "DELETE" });
      if (ws.scanId === s.id) ws.update({ scanId: null });
      toast("Scan deleted");
      load();
    } catch (e) {
      toast(e.message, "err");
    }
  }

  if (error) return <ErrorBox message={error} onRetry={load} />;
  if (!data) return <Loading label="Loading scan history..." />;
  const pages = Math.max(1, Math.ceil(data.total / PAGE));

  return (
    <>
      <div className="page-head">
        <div><h1>Scan History</h1><p>Every scan and validation re-scan you have performed.</p></div>
        <Link to="/editor" className="btn primary">＋ New Security Scan</Link>
      </div>
      <div className="row mb">
        <input type="search" style={{ maxWidth: 280 }} placeholder="Search file or language..." value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} />
        <select style={{ maxWidth: 190 }} value={status} onChange={(e) => { setStatus(e.target.value); setPage(0); }}>
          <option value="">All statuses</option>
          <option value="success">Successful</option>
          <option value="failed">Unsuccessful</option>
        </select>
        <span className="muted small">{data.total} record(s)</span>
      </div>

      {data.items.length === 0 ? (
        <Empty icon="🕘" title="No scans found" text={q || status ? "Try a different search or filter." : "Your scans will be listed here after your first scan."} to={q || status ? undefined : "/editor"} action="Start a new scan" />
      ) : (
        <div className="card">
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>#</th><th>File</th><th>Language</th><th>Type</th><th>Status</th><th>Score</th><th>Findings</th><th>Date</th><th /></tr></thead>
              <tbody>
                {data.items.map((s) => (
                  <tr key={s.id}>
                    <td>{s.id}</td>
                    <td>{s.filename}</td>
                    <td>{langName(s.language)}</td>
                    <td>{s.kind === "validation" ? `Validation ${s.iteration - 1}` : "Scan"}</td>
                    <td><span className={`pill ${s.status === "success" ? "ok" : "bad"}`}>{s.status === "success" ? "Successful" : "Unsuccessful"}</span></td>
                    <td>{s.status === "success" ? <b>{s.score}</b> : "-"}</td>
                    <td>{s.status === "success" ? s.total_findings : "-"}</td>
                    <td className="muted small">{fmtDate(s.created_at)}</td>
                    <td>
                      <div className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
                        <Link className="btn sm" to={`/results/${s.id}`}>Open</Link>
                        {s.status === "success" && (
                          <button className="btn sm" onClick={() => downloadFile(`/reports/${s.id}?format=pdf`, `report-${s.id}.pdf`).catch((e) => toast(e.message, "err"))}>PDF</button>
                        )}
                        <button className="btn sm danger" onClick={() => remove(s)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pages > 1 && (
            <div className="row between mt">
              <button className="btn sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>← Previous</button>
              <span className="muted small">Page {page + 1} of {pages}</span>
              <button className="btn sm" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>Next →</button>
            </div>
          )}
        </div>
      )}
    </>
  );
}
