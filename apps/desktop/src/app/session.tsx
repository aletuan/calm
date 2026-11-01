import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  sessionActivate,
  sessionCreate,
  sessionDelete,
  sessionList,
  snapshotDelete,
  snapshotList,
  snapshotOpen,
  snapshotSaveImport,
  snapshotSaveLive,
  storeOpen,
  storeSetAside,
  type SessionInput,
  type SessionSummary,
  type SnapshotKind,
  type SnapshotSummary,
  type StoreError,
  type StoreStatus,
} from "../lib/ipc";
import { useImport } from "./imported";

interface SessionCtx {
  status: StoreStatus | null;
  sessions: SessionSummary[];
  active: SessionSummary | null;
  snapshots: SnapshotSummary[];
  busy: boolean;
  error: StoreError | null;
  /** Save progress and result, shown next to the save button. */
  /** What is being saved right now, if anything. */
  saving: SnapshotKind | null;
  lastSaved: { snapshot: SnapshotSummary; sessionName: string; at: number } | null;
  saveError: StoreError | null;
  lastFailedKind: SnapshotKind | null;
  /** Opens the encrypted store (touches the Keychain); called by the Session screen. */
  open: () => Promise<void>;
  setAside: () => Promise<void>;
  create: (input: SessionInput) => Promise<void>;
  remove: (id: string) => Promise<void>;
  activate: (id: string | null) => Promise<void>;
  saveLive: () => Promise<void>;
  saveImport: () => Promise<void>;
  view: (id: string) => Promise<void>;
  removeSnapshot: (id: string) => Promise<void>;
}

const Ctx = createContext<SessionCtx | null>(null);

const asStoreError = (e: unknown): StoreError =>
  (e as StoreError)?.kind ? (e as StoreError) : { kind: "io", detail: String(e) };

export function SessionProvider({ children }: { children: ReactNode }) {
  const imp = useImport();
  const [status, setStatus] = useState<StoreStatus | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [active, setActive] = useState<SessionSummary | null>(null);
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<StoreError | null>(null);
  const reload = useCallback(async (activeId: string | null) => {
    const list = await sessionList();
    setSessions(list);
    const a = list.find((s) => s.id === activeId) ?? null;
    setActive(a);
    setSnapshots(a ? await snapshotList(a.id) : []);
  }, []);

  const [saving, setSaving] = useState<SnapshotKind | null>(null);
  const [lastSaved, setLastSaved] = useState<SessionCtx["lastSaved"]>(null);
  const [saveError, setSaveError] = useState<StoreError | null>(null);
  const [lastFailedKind, setLastFailedKind] = useState<SnapshotKind | null>(null);

  const save = useCallback(
    async (kind: SnapshotKind, f: () => Promise<SnapshotSummary>) => {
      setSaving(kind);
      setSaveError(null);
      try {
        const snap = await f();
        setLastSaved({ snapshot: snap, sessionName: active?.meta.name ?? "", at: Date.now() });
        await reload(active?.id ?? null);
      } catch (e) {
        setSaveError(asStoreError(e));
        setLastFailedKind(kind);
      } finally {
        setSaving(null);
      }
    },
    [active, reload],
  );


  const run = useCallback(async (f: () => Promise<string | null | undefined | void>) => {
    setBusy(true);
    setError(null);
    try {
      const next = await f();
      await reload(next === undefined ? (active?.id ?? null) : next);
    } catch (e) {
      setError(asStoreError(e));
    } finally {
      setBusy(false);
    }
  }, [active, reload]);

  const applyStatus = useCallback(
    async (s: StoreStatus) => {
      setStatus(s);
      if (s.state === "ready") await reload(s.active_session?.id ?? null);
    },
    [reload],
  );

  const open = useCallback(async () => {
    setBusy(true);
    try {
      await applyStatus(await storeOpen());
    } catch (e) {
      setError(asStoreError(e));
    } finally {
      setBusy(false);
    }
  }, [applyStatus]);

  const setAside = useCallback(async () => {
    setBusy(true);
    try {
      await applyStatus(await storeSetAside());
    } catch (e) {
      setError(asStoreError(e));
    } finally {
      setBusy(false);
    }
  }, [applyStatus]);

  // Open the encrypted store at launch (local file + Keychain only; no network),
  // so the remembered session is active and saving works right away.
  useEffect(() => {
    void open();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value = useMemo<SessionCtx>(
    () => ({
      status,
      sessions,
      active,
      snapshots,
      busy,
      error,
      open,
      setAside,
      create: (input) => run(async () => (await sessionCreate(input)).id),
      remove: (id) =>
        run(async () => {
          await sessionDelete(id);
          if (imp.saved?.snapshot.session_id === id) imp.closeSaved();
          return active?.id === id ? null : undefined;
        }),
      activate: (id) => run(async () => (await sessionActivate(id))?.id ?? null),
      saving,
      lastSaved,
      saveError,
      lastFailedKind,
      saveLive: () => save("live", () => snapshotSaveLive()),
      saveImport: () => save("import", () => snapshotSaveImport()),
      view: (id) =>
        run(async () => {
          imp.showSaved(await snapshotOpen(id));
        }),
      removeSnapshot: (id) =>
        run(async () => {
          await snapshotDelete(id);
          if (imp.saved?.snapshot.id === id) imp.closeSaved();
        }),
    }),
    [status, sessions, active, snapshots, busy, error, saving, lastSaved, saveError, lastFailedKind, save, open, setAside, run, imp],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): SessionCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}

/** Session context; the store is opened by the provider at launch. */
export function useStoreOpened() {
  return useSession();
}
