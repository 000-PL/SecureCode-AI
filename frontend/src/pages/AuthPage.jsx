import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client.js";
import Icon from "../components/Icons.jsx";
import { Spinner } from "../components/Ui.jsx";
import { useAuth } from "../context/AuthContext.jsx";

export default function AuthPage({ mode }) {
  const isLogin = mode === "login";
  const { login, register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [backend, setBackend] = useState("checking");

  useEffect(() => {
    api("/health")
      .then(() => setBackend("ok"))
      .catch(() => setBackend("down"));
  }, []);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (isLogin) await login({ email: form.email, password: form.password });
      else await register({ name: form.name, email: form.email, password: form.password });
      navigate("/");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <div className="card">
        <div className="brand" style={{ padding: 0, marginBottom: 6 }}>
          <Icon name="shield" size={28} /> SecureCode AI
        </div>
        <p className="muted">AI-Powered Secure Coding &amp; Vulnerability Remediation Platform</p>
        {backend === "down" && (
          <div className="alert bad mb">
            <div>
              <div className="title">Backend not reachable</div>
              <div className="small">Start the server with <code>run.bat</code> (Windows) or <code>./run.sh</code> (Linux/Mac), then reload.</div>
            </div>
          </div>
        )}
        <form onSubmit={submit}>
          <h2>{isLogin ? "Log in" : "Create your account"}</h2>
          {!isLogin && (
            <div className="mb">
              <label htmlFor="name">Full name</label>
              <input id="name" type="text" value={form.name} onChange={set("name")} required minLength={2} autoComplete="name" />
            </div>
          )}
          <div className="mb">
            <label htmlFor="email">Email</label>
            <input id="email" type="email" value={form.email} onChange={set("email")} required autoComplete="email" />
          </div>
          <div className="mb">
            <label htmlFor="password">Password {!isLogin && <span className="muted">(min 8 characters, letters and numbers)</span>}</label>
            <input id="password" type="password" value={form.password} onChange={set("password")} required minLength={isLogin ? 1 : 8} autoComplete={isLogin ? "current-password" : "new-password"} />
          </div>
          {error && <div className="alert bad mb"><div>{error}</div></div>}
          <button className="btn primary" style={{ width: "100%" }} disabled={busy || backend === "down"}>
            {busy ? <Spinner label="Please wait..." /> : isLogin ? "Log in" : "Create account"}
          </button>
        </form>
        <p className="small muted center mt">
          {isLogin ? (
            <>No account? <Link to="/register">Register</Link></>
          ) : (
            <>Already registered? <Link to="/login">Log in</Link></>
          )}
        </p>
      </div>
    </div>
  );
}
