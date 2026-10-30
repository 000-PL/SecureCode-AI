import { useEffect, useState } from "react";
import { api } from "../api/client.js";
import { useToast } from "../components/Toast.jsx";
import { ErrorBox, Loading, Spinner } from "../components/Ui.jsx";
import { useAuth } from "../context/AuthContext.jsx";

export default function SettingsPage() {
  const { user, saveSettings } = useAuth();
  const toast = useToast();
  const [form, setForm] = useState(null);
  const [system, setSystem] = useState(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const load = () => {
    setError("");
    api("/settings").then((r) => { setForm(r.settings); setSystem(r.system); }).catch((e) => setError(e.message));
  };
  useEffect(load, []);

  if (error) return <ErrorBox message={error} onRetry={load} />;
  if (!form) return <Loading label="Loading settings..." />;
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  async function save() {
    setSaving(true);
    try {
      await saveSettings({ ...form, editor_font_size: Number(form.editor_font_size) });
      toast("Settings saved");
    } catch (e) {
      toast(e.message, "err");
    } finally {
      setSaving(false);
    }
  }

  const Switch = ({ k, title, text }) => (
    <label className="switch" style={{ color: "var(--text)", fontSize: 15 }}>
      <span><b>{title}</b><br /><span className="muted small">{text}</span></span>
      <input type="checkbox" checked={!!form[k]} onChange={(e) => set(k, e.target.checked)} />
    </label>
  );

  return (
    <>
      <div className="page-head"><div><h1>Settings</h1><p>Personalise the editor, scans and reports.</p></div></div>
      <div className="grid g2">
        <div className="card">
          <h2>Preferences</h2>
          <div className="mb">
            <label htmlFor="theme">Theme</label>
            <select id="theme" value={form.theme} onChange={(e) => set("theme", e.target.value)}>
              <option value="dark">Dark</option>
              <option value="light">Light</option>
            </select>
          </div>
          <div className="mb">
            <label htmlFor="fs">Editor font size (px)</label>
            <input id="fs" type="text" inputMode="numeric" value={form.editor_font_size} onChange={(e) => set("editor_font_size", e.target.value.replace(/\D/g, "").slice(0, 2))} />
          </div>
          <div className="mb">
            <label htmlFor="rf">Default report format</label>
            <select id="rf" value={form.default_report_format} onChange={(e) => set("default_report_format", e.target.value)}>
              <option value="pdf">PDF</option>
              <option value="html">HTML</option>
              <option value="json">JSON</option>
            </select>
          </div>
          <Switch k="auto_detect_language" title="Auto-detect language" text="Detect Python / JavaScript while you type." />
          <Switch k="use_external_ai" title="Use external AI service" text={system.external_ai_configured ? "Explanations are written by the configured LLM." : "No API key configured on the server - the built-in AI knowledge base is used."} />
          <Switch k="run_code_on_validation" title="Execute code during fix validation" text="Runs the corrected code in a sandboxed subprocess before re-scanning." />
          <button className="btn primary mt" onClick={save} disabled={saving}>{saving ? <Spinner label="Saving..." /> : "Save settings"}</button>
        </div>
        <div className="card">
          <h2>Account &amp; system</h2>
          <table className="t">
            <tbody>
              <tr><th>Name</th><td>{user.name}</td></tr>
              <tr><th>Email</th><td>{user.email}</td></tr>
              <tr><th>Database</th><td>{system.database}</td></tr>
              <tr><th>SAST engine</th><td>Built-in rules for Python &amp; JavaScript</td></tr>
              <tr><th>AI module</th><td>{system.external_ai_configured ? "External LLM + built-in" : "Built-in"}</td></tr>
              <tr><th>Code execution</th><td>{system.code_execution ? `Enabled (${system.execution_timeout}s timeout)` : "Disabled by administrator"}</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
