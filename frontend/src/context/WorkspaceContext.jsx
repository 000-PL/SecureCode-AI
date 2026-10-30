import { createContext, useCallback, useContext, useEffect, useState } from "react";

// Holds the code being worked on so the whole workflow (editor -> scan -> fix -> validate) shares one source of truth.
const KEY = "sc_workspace";
const Ctx = createContext(null);
export const useWorkspace = () => useContext(Ctx);

const EMPTY = { code: "", filename: "untitled.py", language: "auto", scanId: null };

function load() {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) || "null");
    return raw && typeof raw === "object" ? { ...EMPTY, ...raw } : EMPTY;
  } catch {
    return EMPTY;
  }
}

export function WorkspaceProvider({ children }) {
  const [ws, setWs] = useState(load);

  useEffect(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(ws));
    } catch {
      /* storage full or blocked - the workspace simply is not persisted */
    }
  }, [ws]);

  const update = useCallback((patch) => setWs((w) => ({ ...w, ...patch })), []);
  const reset = useCallback(() => setWs(EMPTY), []);
  return <Ctx.Provider value={{ ...ws, update, reset }}>{children}</Ctx.Provider>;
}
