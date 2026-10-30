import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import CodeEditor from "../components/CodeEditor.jsx";
import Icon from "../components/Icons.jsx";
import { useToast } from "../components/Toast.jsx";
import { Spinner, Stepper, langName } from "../components/Ui.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useWorkspace } from "../context/WorkspaceContext.jsx";

const EXT = { python: "py", javascript: "js" };
const SAMPLE = `import sqlite3
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "admin123"

@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(query)
    return "<h1>Hello " + name + "</h1>"

if __name__ == "__main__":
    app.run(debug=True)
`;

export default function EditorPage() {
  const { user } = useAuth();
  const ws = useWorkspace();
  const toast = useToast();
  const navigate = useNavigate();
  const fileRef = useRef(null);
  const [detected, setDetected] = useState({ language: "unknown", supported: false });
  const [manual, setManual] = useState(ws.language && ws.language !== "auto" ? ws.language : "auto");
  const [scanning, setScanning] = useState(false);
  const [running, setRunning] = useState(false);
  const [failure, setFailure] = useState("");
  const [output, setOutput] = useState(null);
  const fontSize = user?.settings?.editor_font_size || 14;
  const autoDetect = user?.settings?.auto_detect_language !== false;
  const uploaded = !/^untitled/i.test(ws.filename || "untitled");

  // live language detection (debounced)
  useEffect(() => {
    if (!ws.code.trim() || !autoDetect) {
      setDetected({ language: "unknown", supported: false });
      return undefined;
    }
    const ctl = new AbortController();
    const t = setTimeout(() => {
      api("/detect-language", { method: "POST", body: { code: ws.code, filename: uploaded ? ws.filename : null }, signal: ctl.signal })
        .then(setDetected)
        .catch(() => {});
    }, 400);
    return () => {
      clearTimeout(t);
      ctl.abort();
    };
  }, [ws.code, ws.filename, uploaded, autoDetect]);

  // vulnerable-line markers from the last scan (fetched once per scan, shown while the code is unchanged)
  const [lastScan, setLastScan] = useState(null);
  useEffect(() => {
    setLastScan(null);
    if (!ws.scanId) return;
    api(`/scans/${ws.scanId}`).then(setLastScan).catch(() => {});
  }, [ws.scanId]);
  const markers = lastScan && lastScan.code === ws.code ? lastScan.findings.map((f) => ({ line: f.line, severity: f.severity })) : [];

  const effectiveLang = manual !== "auto" ? manual : detected.language;
  const saveName = () => {
    if (uploaded) return ws.filename;
    const ext = EXT[effectiveLang] || "txt";
    return `untitled.${ext}`;
  };

  const onFile = (e) => {
    const file = e.target.files && e.target.files[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > 500 * 1024) {
      toast("File is too large (max 500 KB).", "err");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      ws.update({ code: String(reader.result || ""), filename: file.name, scanId: null });
      setManual("auto");
      setFailure("");
      setOutput(null);
      toast(`Loaded ${file.name}`);
    };
    reader.onerror = () => toast("Could not read that file.", "err");
    reader.readAsText(file);
  };

  async function saveAndScan() {
    setFailure("");
    if (!ws.code.trim()) {
      setFailure("There is no code to scan. Write or upload some code first.");
      return;
    }
    setScanning(true);
    try {
      const scan = await api("/scans", {
        method: "POST",
        body: { code: ws.code, filename: saveName(), language: manual === "auto" ? null : manual },
      });
      ws.update({ scanId: scan.id, filename: scan.filename, language: scan.language });
      if (scan.status === "success") {
        toast(`Scan successful - score ${scan.score}/100, ${scan.total_findings} finding(s).`);
        navigate(`/results/${scan.id}`);
      } else {
        setFailure(scan.error || "The scan could not be completed.");
        toast("Scan unsuccessful", "err");
      }
    } catch (e) {
      setFailure(e.message);
      toast("Scan unsuccessful", "err");
    } finally {
      setScanning(false);
    }
  }

  async function runCode() {
    if (!ws.code.trim()) return;
    setRunning(true);
    setOutput(null);
    try {
      const res = await api("/run", { method: "POST", body: { code: ws.code, language: effectiveLang === "unknown" ? null : effectiveLang, filename: uploaded ? ws.filename : null } });
      setOutput(res);
    } catch (e) {
      setOutput({ status: "failed", stderr: e.message, stdout: "" });
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <Stepper current="editor" scanId={ws.scanId} />
      <div className="page-head">
        <div>
          <h1>New Security Scan</h1>
          <p>Write or upload code. The language is detected automatically, then Save &amp; Scan runs the SAST engine.</p>
        </div>
      </div>

      <div className="editor-shell">
        <div className="editor-bar">
          <input type="text" style={{ width: 200 }} value={ws.filename} onChange={(e) => ws.update({ filename: e.target.value })} aria-label="File name" />
          <span className="pill">Detected: <b>{detected.language === "unknown" ? "-" : langName(detected.language)}</b>{detected.language !== "unknown" && !detected.supported && " (not supported)"}</span>
          <select style={{ width: 170 }} value={manual} onChange={(e) => setManual(e.target.value)} aria-label="Language">
            <option value="auto">Auto-detect</option>
            <option value="python">Python</option>
            <option value="javascript">JavaScript</option>
          </select>
          <div className="grow" />
          <input ref={fileRef} type="file" hidden accept=".py,.js,.jsx,.mjs,.cjs,.ts,.txt" onChange={onFile} />
          <button className="btn sm" onClick={() => fileRef.current && fileRef.current.click()}><Icon name="upload" size={15} /> Upload</button>
          <button className="btn sm" onClick={() => ws.update({ code: SAMPLE, filename: "untitled.py", scanId: null })}>Load sample</button>
          <button className="btn sm" onClick={() => { ws.update({ code: "", filename: "untitled.py", scanId: null }); setOutput(null); setFailure(""); }}>Clear</button>
        </div>
        <CodeEditor value={ws.code} onChange={(v) => ws.update({ code: v })} markers={markers} fontSize={fontSize} />
      </div>

      <div className="row mt">
        <button className="btn primary" onClick={saveAndScan} disabled={scanning}>
          {scanning ? <Spinner label="Scanning..." /> : <><Icon name="shield" size={16} /> Save &amp; Scan Code</>}
        </button>
        <button className="btn" onClick={runCode} disabled={running || !ws.code.trim()}>
          {running ? <Spinner label="Running..." /> : <><Icon name="play" size={15} /> Run code (functional test)</>}
        </button>
        <span className="muted small">{ws.code ? `${ws.code.split("\n").length} lines` : "Editor is empty"}</span>
      </div>

      {failure && (
        <div className="alert bad mt">
          <div>
            <div className="title">Scan unsuccessful</div>
            <div>{failure}</div>
          </div>
        </div>
      )}

      {output && (
        <div className="card mt">
          <div className="row between">
            <h3>Execution output</h3>
            <span className={`pill ${output.status === "passed" ? "ok" : "bad"}`}>{output.status}{output.exit_code != null ? ` (exit ${output.exit_code})` : ""}</span>
          </div>
          <pre className="output">{(output.stdout || "") + (output.stderr ? `\n${output.stderr}` : "") || "(no output)"}</pre>
        </div>
      )}
    </>
  );
}
