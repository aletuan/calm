import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { addressDeltas, stepActivity, stepFirstSeen, type Activity } from "../lib/activity";
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
  /** Live activity per remote address (bytes moved recently, by direction). */
  activity: Activity;
  /** When each remote address first appeared in this capture. */
  firstSeen: Map<string, number>;
  /** Graph nodes the user has looked at (clears their "new" marker). */
  seenByUser: Set<string>;
  markSeen: (nodeId: string) => void;
  /** New nodes whose attention pulse already played, so it plays once. */
  pulsed: Set<string>;
  markPulsed: (nodeIds: string[]) => void;
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

  // Activity and "new device" state follow the capture, not the Topology screen,
  // so a device that appears while another screen is open is still announced.
  const [activity, setActivity] = useState<Activity>(new Map());
  const [firstSeen, setFirstSeen] = useState<Map<string, number>>(new Map());
  const [seenByUser, setSeenByUser] = useState<Set<string>>(new Set());
  const [pulsed, setPulsed] = useState<Set<string>>(new Set());
  const last = useRef<{ start: number; at: number; flows: CaptureView["snapshot"]["flows"] } | null>(null);
  useEffect(() => {
    if (!view?.running) return;
    const now = Date.now();
    const prev = last.current && last.current.start === view.started_at_ms ? last.current : null;
    if (!prev) {
      setActivity(new Map());
      setFirstSeen(new Map());
      setSeenByUser(new Set());
      setPulsed(new Set());
    }
    const flows = view.snapshot.flows;
    setActivity((a) => stepActivity(prev ? a : new Map(), addressDeltas(prev?.flows ?? null, flows), now, prev ? now - prev.at : 1000));
    setFirstSeen((f) => stepFirstSeen(prev ? f : new Map(), flows, now));
    last.current = { start: view.started_at_ms, at: now, flows };
  }, [view]);
  const markSeen = useCallback((id: string) => setSeenByUser((s) => (s.has(id) ? s : new Set(s).add(id))), []);
  const markPulsed = useCallback((ids: string[]) => setPulsed((s) => (ids.every((i) => s.has(i)) ? s : new Set([...s, ...ids]))), []);

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
    () => ({ probe, view, running, busy, startError, recheck, start, stop, autoSave, setAutoSave, activity, firstSeen, seenByUser, markSeen, pulsed, markPulsed }),
    [probe, view, running, busy, startError, recheck, start, stop, autoSave, setAutoSave, activity, firstSeen, seenByUser, markSeen, pulsed, markPulsed],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useCapture(): CaptureCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useCapture outside CaptureProvider");
  return v;
}
