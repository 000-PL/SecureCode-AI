import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import Icon from "./Icons.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { useWorkspace } from "../context/WorkspaceContext.jsx";

export default function Layout() {
  const { user, logout } = useAuth();
  const { scanId } = useWorkspace();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const dyn = (base) => (scanId ? `/${base}/${scanId}` : `/${base}`);

  const flow = [
    { to: "/editor", base: "/editor", label: "New Security Scan", icon: "code", n: 1 },
    { to: dyn("results"), base: "/results", label: "Scan Results", icon: "chart", n: 2 },
    { to: dyn("ai-fix"), base: "/ai-fix", label: "AI Fix", icon: "spark", n: 3 },
    { to: dyn("remediation"), base: "/remediation", label: "Remediation", icon: "wrench", n: 4 },
    { to: dyn("validation"), base: "/validation", label: "Fix Validation", icon: "check", n: 5 },
  ];
  const manage = [
    { to: "/reports", base: "/reports", label: "Reports", icon: "file" },
    { to: "/history", base: "/history", label: "Scan History", icon: "clock" },
    { to: "/settings", base: "/settings", label: "Settings", icon: "gear" },
  ];
  const active = (base) => pathname === base || pathname.startsWith(base + "/");

  return (
    <div className="app">
      <aside className="sidebar">
        <Link to="/" className="brand" style={{ color: "inherit" }}>
          <Icon name="shield" size={26} /> SecureCode AI
        </Link>
        <nav className="nav">
          <Link to="/" className={pathname === "/" ? "active" : ""}>
            <Icon name="home" /> Dashboard
          </Link>
          <div className="sep">Secure coding workflow</div>
          {flow.map((i) => (
            <Link key={i.base} to={i.to} className={active(i.base) ? "active" : ""}>
              <span className="num">{i.n}</span> {i.label}
            </Link>
          ))}
          <div className="sep">Manage</div>
          {manage.map((i) => (
            <Link key={i.base} to={i.to} className={active(i.base) ? "active" : ""}>
              <Icon name={i.icon} /> {i.label}
            </Link>
          ))}
        </nav>
        <div className="user">
          <div className="small" style={{ fontWeight: 600 }}>{user?.name}</div>
          <div className="small muted" style={{ wordBreak: "break-all" }}>{user?.email}</div>
          <button
            className="btn sm mt"
            onClick={() => {
              logout();
              navigate("/login");
            }}
          >
            <Icon name="logout" size={15} /> Log out
          </button>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}
