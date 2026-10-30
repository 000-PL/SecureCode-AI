import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, getToken, setToken } from "../api/client.js";

const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(!!getToken());

  useEffect(() => {
    let alive = true;
    if (getToken()) {
      api("/auth/me")
        .then((u) => alive && setUser(u))
        .catch(() => alive && setUser(null))
        .finally(() => alive && setLoading(false));
    }
    const onLogout = () => setUser(null);
    window.addEventListener("sc-logout", onLogout);
    return () => {
      alive = false;
      window.removeEventListener("sc-logout", onLogout);
    };
  }, []);

  // apply theme
  useEffect(() => {
    const theme = (user && user.settings && user.settings.theme) || localStorage.getItem("sc_theme") || "dark";
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("sc_theme", theme);
  }, [user]);

  const authenticate = useCallback(async (mode, payload) => {
    const data = await api(`/auth/${mode}`, { method: "POST", body: payload });
    setToken(data.token);
    setUser(data.user);
    return data.user;
  }, []);

  const logout = useCallback(() => {
    setToken("");
    setUser(null);
  }, []);

  const saveSettings = useCallback(async (settings) => {
    const res = await api("/settings", { method: "PUT", body: settings });
    setUser((u) => (u ? { ...u, settings: res.settings } : u));
    return res.settings;
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login: (p) => authenticate("login", p), register: (p) => authenticate("register", p), logout, saveSettings }}>
      {children}
    </AuthContext.Provider>
  );
}
