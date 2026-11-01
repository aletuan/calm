import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { getLocationStatus, getNetworkOverview, requestLocation, type GraphSnapshot, type NetworkProfile } from "../lib/ipc";

interface ProfileCtx {
  profile: NetworkProfile | null;
  /** Derived from the same collection as `profile`. */
  graph: GraphSnapshot | null;
  loading: boolean;
  error: string | null;
  waitingForPrompt: boolean;
  refresh: () => Promise<void>;
  /** Consent-first: only triggered by an explicit user action. */
  requestAccess: () => Promise<void>;
}

const Ctx = createContext<ProfileCtx | null>(null);

export function ProfileProvider({ children }: { children: ReactNode }) {
  const [profile, setProfile] = useState<NetworkProfile | null>(null);
  const [graph, setGraph] = useState<GraphSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [waitingForPrompt, setWaiting] = useState(false);
  const polling = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const o = await getNetworkOverview();
      setProfile(o.profile);
      setGraph(o.graph);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const requestAccess = useCallback(async () => {
    await requestLocation();
    setWaiting(true);
    const started = Date.now();
    if (polling.current) window.clearInterval(polling.current);
    polling.current = window.setInterval(async () => {
      const status = await getLocationStatus().catch(() => "unavailable" as const);
      if (status !== "not_determined" || Date.now() - started > 60_000) {
        if (polling.current) window.clearInterval(polling.current);
        polling.current = null;
        setWaiting(false);
        await refresh();
      }
    }, 1000);
  }, [refresh]);

  useEffect(() => {
    void refresh();
    return () => {
      if (polling.current) window.clearInterval(polling.current);
    };
  }, [refresh]);

  const value = useMemo(
    () => ({ profile, graph, loading, error, waitingForPrompt, refresh, requestAccess }),
    [profile, graph, loading, error, waitingForPrompt, refresh, requestAccess],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useProfile(): ProfileCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useProfile outside ProfileProvider");
  return v;
}
