import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client.js";
import { useWorkspace } from "../context/WorkspaceContext.jsx";

// Loads a scan by route id (or the latest one). Keeps the shared workspace in sync with the scan being viewed.
export default function useScan(routeId) {
  const ws = useWorkspace();
  const wsRef = useRef(ws);
  wsRef.current = ws;
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const s = await api(routeId ? `/scans/${routeId}` : "/scans/latest");
      setScan(s);
      if (s && wsRef.current.scanId !== s.id) {
        wsRef.current.update({ scanId: s.id, code: s.code, filename: s.filename, language: s.language });
      }
    } catch (e) {
      setScan(null);
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [routeId]);

  useEffect(() => {
    load();
  }, [load]);

  return { scan, loading, error, reload: load };
}
