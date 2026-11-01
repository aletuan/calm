import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { importClear, importPick, importView, type ImportError, type ImportView, type RecordedView } from "../lib/ipc";
import type { Source } from "../lib/source";

export type { Source };

interface ImportCtx {
  view: ImportView | null;
  busy: boolean;
  error: ImportError | null;
  /** A saved snapshot opened for viewing (M1.5). */
  saved: RecordedView | null;
  /** Which data Traffic and Topology show. Sources never mix. */
  source: Source;
  setSource: (s: Source) => void;
  pick: () => Promise<void>;
  clear: () => Promise<void>;
  showSaved: (v: RecordedView) => void;
  closeSaved: () => void;
}

const Ctx = createContext<ImportCtx | null>(null);

export function ImportProvider({ children }: { children: ReactNode }) {
  const [view, setView] = useState<ImportView | null>(null);
  const [saved, setSaved] = useState<RecordedView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ImportError | null>(null);
  const [source, setSource] = useState<Source>("live");

  const pick = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setView(await importPick());
      setSource("imported");
    } catch (e) {
      const err = (e as ImportError)?.kind ? (e as ImportError) : { kind: "unreadable" as const, detail: String(e) };
      if (err.kind !== "cancelled") setError(err);
    } finally {
      setBusy(false);
    }
  }, []);

  const clear = useCallback(async () => {
    await importClear();
    setView(null);
    setSource((s) => (s === "imported" ? "live" : s));
  }, []);

  const showSaved = useCallback((v: RecordedView) => {
    setSaved(v);
    setSource("saved");
  }, []);

  const closeSaved = useCallback(() => {
    setSaved(null);
    setSource((s) => (s === "saved" ? "live" : s));
  }, []);

  useEffect(() => {
    void importView().then(setView).catch(() => undefined);
  }, []);

  const effective: Source = source === "imported" && !view ? "live" : source === "saved" && !saved ? "live" : source;
  const value = useMemo(
    () => ({ view, busy, error, saved, source: effective, setSource, pick, clear, showSaved, closeSaved }),
    [view, busy, error, saved, effective, pick, clear, showSaved, closeSaved],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useImport(): ImportCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useImport outside ImportProvider");
  return v;
}
