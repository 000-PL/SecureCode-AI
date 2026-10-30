import { Link } from "react-router-dom";

export const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
export const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#60a5fa", info: "#94a3b8" };

export function SeverityBadge({ severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

export function Spinner({ label }) {
  return (
    <span className="row" style={{ gap: 8 }}>
      <span className="spinner" /> {label}
    </span>
  );
}

export function Loading({ label = "Loading..." }) {
  return (
    <div className="empty muted">
      <Spinner label={label} />
    </div>
  );
}

export function ErrorBox({ message, onRetry }) {
  return (
    <div className="alert bad">
      <div className="grow">
        <div className="title">Something went wrong</div>
        <div>{message}</div>
      </div>
      {onRetry && (
        <button className="btn sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Empty({ icon = "🛡️", title, text, to, action }) {
  return (
    <div className="card empty">
      <div className="big">{icon}</div>
      <h2>{title}</h2>
      <p className="muted">{text}</p>
      {to && (
        <Link to={to} className="btn primary">
          {action}
        </Link>
      )}
    </div>
  );
}

export function ScoreRing({ score, grade, size = 170 }) {
  const r = 70;
  const c = 2 * Math.PI * r;
  const color = score >= 90 ? "#22c55e" : score >= 75 ? "#84cc16" : score >= 60 ? "#eab308" : score >= 40 ? "#f97316" : "#ef4444";
  return (
    <div className="ring" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox="0 0 170 170">
        <circle cx="85" cy="85" r={r} fill="none" stroke="var(--panel2)" strokeWidth="14" />
        <circle cx="85" cy="85" r={r} fill="none" stroke={color} strokeWidth="14" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - Math.max(0, Math.min(100, score)) / 100)} />
      </svg>
      <div className="num">
        <b style={{ color }}>{score}</b>
        <span>out of 100 · Grade {grade}</span>
      </div>
    </div>
  );
}

const STEPS = [
  { key: "editor", label: "Code Editor" },
  { key: "results", label: "Scan Results" },
  { key: "ai", label: "AI Fix" },
  { key: "remediation", label: "Remediation" },
  { key: "validation", label: "Fix Validation" },
  { key: "report", label: "Report" },
];

export function Stepper({ current, scanId }) {
  const idx = STEPS.findIndex((s) => s.key === current);
  const href = (k) =>
    k === "editor" ? "/editor" : k === "report" ? "/reports" : scanId ? `/${{ results: "results", ai: "ai-fix", remediation: "remediation", validation: "validation" }[k]}/${scanId}` : null;
  return (
    <div className="stepper">
      {STEPS.map((s, i) => {
        const cls = i < idx ? "done" : i === idx ? "current" : "";
        const inner = (
          <>
            <b>{i < idx ? "✓" : i + 1}</b>
            {s.label}
          </>
        );
        const to = href(s.key);
        return to && i !== idx ? (
          <Link key={s.key} to={to} className={`step ${cls}`}>
            {inner}
          </Link>
        ) : (
          <div key={s.key} className={`step ${cls}`}>
            {inner}
          </div>
        );
      })}
    </div>
  );
}

export function fmtDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export const LANG_NAMES = { python: "Python", javascript: "JavaScript", typescript: "TypeScript", java: "Java", php: "PHP", c: "C", cpp: "C++", csharp: "C#", go: "Go", ruby: "Ruby", rust: "Rust", html: "HTML", sql: "SQL", unknown: "Unknown" };
export const langName = (l) => LANG_NAMES[l] || l || "Unknown";
