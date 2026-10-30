import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import { Loading } from "./components/Ui.jsx";
import { useAuth } from "./context/AuthContext.jsx";
import AuthPage from "./pages/AuthPage.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import EditorPage from "./pages/EditorPage.jsx";
import ScanResults from "./pages/ScanResults.jsx";
import AIFix from "./pages/AIFix.jsx";
import Remediation from "./pages/Remediation.jsx";
import Validation from "./pages/Validation.jsx";
import Reports from "./pages/Reports.jsx";
import History from "./pages/History.jsx";
import SettingsPage from "./pages/SettingsPage.jsx";

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <Loading label="Checking session..." />;
  return user ? children : <Navigate to="/login" replace />;
}

function Public({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <Loading label="Checking session..." />;
  return user ? <Navigate to="/" replace /> : children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Public><AuthPage mode="login" /></Public>} />
      <Route path="/register" element={<Public><AuthPage mode="register" /></Public>} />
      <Route element={<Protected><Layout /></Protected>}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/editor" element={<EditorPage />} />
        <Route path="/results/:id?" element={<ScanResults />} />
        <Route path="/ai-fix/:id?" element={<AIFix />} />
        <Route path="/remediation/:id?" element={<Remediation />} />
        <Route path="/validation/:id?" element={<Validation />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/history" element={<History />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
