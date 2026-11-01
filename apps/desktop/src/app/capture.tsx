import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { captureProbe, captureSetAutosave, captureStart, captureStop, captureView, type Availability, type CaptureProbe, type CaptureView } from "../lib/ipc";

interface CaptureCtx {
  probe: CaptureProbe | null;
  view: CaptureView | null;
  running: boolean;
  busy: boolean;
  startError: Availability | null;
  recheck: () => Promise<void>;
  start: () => Promise<void>;
  stop: () => Promise<void>;
  /** "On stop or quit, save to the active session" (per viewer, default on). */
  autoSave: boolean;
  setAutoSave: (v: boolean) => void;
}

const AUTOSAVE_KEY = "calm.capture.autosave";

function readAutoSave(): boolean {
  try {
    return window.localStorage.getItem(AUTOSAVE_KEY) !== "off";
  } catch {
    return true;
  }
}

const Ctx = createContext<CaptureCtx | null>(null);

/** Local capture state shared by Traffic, Topology and the context bar. Polls once a second while running. */
export function CaptureProvider({ children }: { children: ReactNode }) {
  const [probe, setProbe] = useState<CaptureProbe | null>(null);
  const [view, setView] = useState<CaptureView | null>(null);
  const [busy, setBusy] = useState(false);
  const [startError, setStartError] = useState<Availability | null>(null);
  const running = view?.running ?? false;
  const [autoSave, setAutoSaveState] = useState(readAutoSave);
  const setAutoSave = useCallback((v: boolean) => {
    setAutoSaveState(v);
    try {
      window.localStorage.setItem(AUTOSAVE_KEY, v ? "on" : "off");
    } catch {
      /* per-viewer convenience only */
    }
  }, []);
  // The shell needs it too: it saves on quit (Cmd+Q) while capturing.
  useEffect(() => {
    void captureSetAutosave(autoSave).catch(() => undefined);
  }, [autoSave]);

  const recheck = useCallback(async () => {
    try {
      setProbe(await captureProbe());
    } catch (e) {
      setProbe({ interface: null, availability: { state: "error", detail: String(e) } });
    }
  }, []);

  const start = useCallback(async () => {
    setBusy(true);
    setStartError(null);
    try {
      setView(await captureStart());
    } catch (e) {
      setStartError((e as Availability)?.state ? (e as Availability) : { state: "error", detail: String(e) });
    } finally {
      setBusy(false);
    }
  }, []);

  const stop = useCallback(async () => {
    setBusy(true);
    try {
      setView(await captureStop());
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void recheck();
    void captureView().then(setView).catch(() => undefined);
  }, [recheck]);

  useEffect(() => {
    if (!running) return;
    const id = window.setInterval(() => {
      void captureView().then(setView).catch(() => undefined);
    }, 1000);
    return () => window.clearInterval(id);
  }, [running]);

  const value = useMemo(
    () => ({ probe, view, running, busy, startError, recheck, start, stop, autoSave, setAutoSave }),
    [probe, view, running, busy, startError, recheck, start, stop, autoSave, setAutoSave],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useCapture(): CaptureCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useCapture outside CaptureProvider");
  return v;
}
