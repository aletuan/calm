import { useEffect, useState } from "react";
import { checksStatus, scopeList } from "../lib/assess";

export type AssessMode = "passive" | "scoped" | "running";

/** Pure: what the context bar says about active probing. */
export function assessMode(running: boolean, usableScope: boolean): AssessMode {
  if (running) return "running";
  return usableScope ? "scoped" : "passive";
}

/**
 * The context bar's "Mode": passive, scope approved (probes only on Run),
 * or checks running. Polls the run status; re-reads scopes when the session
 * or screen changes.
 */
export function useAssessMode(sessionId: string | null, screen: string): AssessMode {
  const [running, setRunning] = useState(false);
  const [scoped, setScoped] = useState(false);
  useEffect(() => {
    let alive = true;
    void scopeList()
      .then((l) => alive && setScoped(l.some((v) => !v.revoked && !v.expired)))
      .catch(() => alive && setScoped(false));
    return () => {
      alive = false;
    };
  }, [sessionId, screen]);
  useEffect(() => {
    const tick = () =>
      void checksStatus()
        .then((p) => setRunning(p?.running ?? false))
        .catch(() => setRunning(false));
    tick();
    const h = window.setInterval(tick, 1000);
    return () => window.clearInterval(h);
  }, []);
  return assessMode(running, scoped);
}
