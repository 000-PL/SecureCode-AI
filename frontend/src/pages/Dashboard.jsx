import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import { ErrorBox, Loading, SEV_COLOR, SEV_ORDER, fmtDate, langName } from "../components/Ui.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useWorkspace } from "../context/WorkspaceContext.jsx";

function TrendChart({ data }) {
  if (data.length < 2) return <p className="muted small">Run at least two scans to see your score trend.</p>;
  const W = 560, H = 170, pad = 28;
  const x = (i) => pad + (i * (W - pad * 2)) / (data.length - 1);
  const y = (s) => H - pad - (s / 100) * (H - pad * 2);
  const pts = data.map((d, i) => `${x(i)},${y(d.score)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Security score trend">
      {[0, 50, 100].map((g) => (
        <g key={g}>
          <line x1={pad} x2={W - pad} y1={y(g)} y2={y(g)} stroke="var(--border)" strokeDasharray="4 4" />
          <text x={4} y={y(g) + 4} fontSize="11" fill="var(--muted)">{g}</text>
        </g>
      ))}
      <polyline points={pts} fill="none" stroke="var(--primary)" strokeWidth="3" strokeLinejoin="round" />
      {data.map((d, i) => (
        <circle key={d.id} cx={x(i)} cy={y(d.score)} r="4.5" fill="var(--primary)">
          <title>{`Scan #${d.id} (${d.filename}): ${d.score}/100`}</title>
        </circle>
      ))}
    </svg>
  );
}

export default function Dashboard() {
  const { user } = useAuth();
  const ws = useWorkspace();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  const load = () => {
    setError("");
    api("/dashboard").then(setData).catch((e) => setError(e.message));
  };
  useEffect(load, []);

  const startNew = () => {
    ws.update({ code: "", filename: "untitled.py", language: "auto", scanId: null });
    navigate("/editor");
  };

  if (error) return <ErrorBox message={error} onRetry={load} />;
  if (!data) return <Loading label="Loading dashboard..." />;

  const sevTotal = SEV_ORDER.reduce((a, k) => a + (data.severity[k] || 0), 0) || 1;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Welcome back, {user.name.split(" ")[0]}</h1>
          <p>Write code, scan it, understand every vulnerability, fix it and verify the fix - all in one workflow.</p>
        </div>
        <button className="btn primary" onClick={startNew}>＋ New Security Scan</button>
      </div>

      <div className="grid g4 mb">
        <div className="card stat"><div className="label">Total scans</div><div className="value">{data.total_scans}</div><div className="hint">{data.scans_this_week} in the last 7 days</div></div>
        <div className="card stat"><div className="label">Average security score</div><div className="value">{data.avg_score ?? "-"}</div><div className="hint">last 20 successful scans</div></div>
        <div className="card stat"><div className="label">Vulnerabilities found</div><div className="value">{data.total_vulnerabilities}</div><div className="hint">across all scans</div></div>
        <div className="card stat"><div className="label">Secure results / validations</div><div className="value">{data.secure_scans} <span className="muted" style={{ fontSize: 18 }}>/ {data.validations}</span></div><div className="hint">{data.failed_scans} unsuccessful scan(s)</div></div>
      </div>

      {data.total_scans === 0 && data.validations === 0 ? (
        <div className="card empty">
          <div className="big">🚀</div>
          <h2>Run your first security scan</h2>
          <p className="muted">Paste or upload Python / JavaScript code and the SAST engine will find vulnerabilities, explain them and show the secure fix.</p>
          <button className="btn primary" onClick={startNew}>＋ New Security Scan</button>
        </div>
      ) : (
        <>
          <div className="grid g2 mb">
            <div className="card">
              <h2>Vulnerabilities by severity</h2>
              {SEV_ORDER.map((k) => (
                <div key={k} className="mb" style={{ marginBottom: 10 }}>
                  <div className="row between small"><span style={{ textTransform: "capitalize" }}>{k}</span><b>{data.severity[k] || 0}</b></div>
                  <div className="bar"><i style={{ width: `${((data.severity[k] || 0) / sevTotal) * 100}%`, background: SEV_COLOR[k] }} /></div>
                </div>
              ))}
            </div>
            <div className="card">
              <h2>Security score trend</h2>
              <TrendChart data={data.score_trend} />
              <h3 className="mt">Most common vulnerabilities</h3>
              {data.top_vulnerabilities.length === 0 ? <p className="muted small">None found yet.</p> : data.top_vulnerabilities.map((t) => (
                <div key={t.title} className="row between small" style={{ padding: "4px 0" }}><span>{t.title}</span><b>{t.count}</b></div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="row between"><h2>Recent scans</h2><Link to="/history">View all →</Link></div>
            <div className="table-wrap">
              <table className="t">
                <thead><tr><th>#</th><th>File</th><th>Language</th><th>Type</th><th>Status</th><th>Score</th><th>Findings</th><th>Date</th><th /></tr></thead>
                <tbody>
                  {data.recent.map((s) => (
                    <tr key={s.id}>
                      <td>{s.id}</td><td>{s.filename}</td><td>{langName(s.language)}</td><td>{s.kind === "validation" ? `Validation ${s.iteration}` : "Scan"}</td>
                      <td><span className={`pill ${s.status === "success" ? "ok" : "bad"}`}>{s.status === "success" ? "Successful" : "Unsuccessful"}</span></td>
                      <td>{s.status === "success" ? <b>{s.score}</b> : "-"}</td><td>{s.status === "success" ? s.total_findings : "-"}</td>
                      <td className="muted small">{fmtDate(s.created_at)}</td>
                      <td><Link to={`/results/${s.id}`}>Open</Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}
