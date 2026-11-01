import { useEffect, useState } from "react";
import { useImport } from "../app/imported";
import { useSession } from "../app/session";
import { useI18n } from "../i18n";
import type { MessageKey } from "../i18n/en";
import { saveErrorDetail } from "../lib/errorMessage";
import { fmtLocalTime } from "../lib/format";
import { SAVED_FLASH_MS, saveUi } from "../lib/saveState";

/** Re-renders once the "Saved" confirmation has expired. */
function useFlashClock(at: number | null): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    setNow(Date.now());
    if (at == null) return;
    const left = at + SAVED_FLASH_MS - Date.now();
    if (left <= 0) return;
    const id = window.setTimeout(() => setNow(Date.now()), left + 50);
    return () => window.clearTimeout(id);
  }, [at]);
  return now;
}

const LABEL: Record<string, MessageKey> = {
  opening: "save.opening",
  no_session: "session.saveTo",
  viewing_saved: "session.saveTo",
  saving: "save.saving",
  saved: "save.saved",
  failed: "save.retry",
};

/**
 * "Save to session" with visible progress: Saving… → ✓ Saved (a few seconds),
 * or Save again after a failure. `kind` picks what is saved; by default the
 * source on screen (this Mac, or the imported file).
 */
export function SaveButton({ kind, label }: { kind?: "live" | "import"; label?: string }) {
  const { t } = useI18n();
  const imp = useImport();
  const s = useSession();
  const now = useFlashClock(s.lastSaved?.at ?? null);
  const what = kind ?? (imp.source === "imported" ? "import" : "live");
  const busyElsewhere = s.saving != null && s.saving !== what;
  const ui = saveUi({
    storeReady: s.status?.state === "ready",
    hasActive: s.active != null,
    source: kind ? (kind === "import" ? "imported" : "live") : imp.source,
    // Each button reports only its own save.
    saving: s.saving === what,
    lastSavedAt: s.lastSaved?.snapshot.kind === what ? s.lastSaved.at : null,
    failed: s.saveError != null && s.lastFailedKind === what,
    now,
  });
  const noImport = what === "import" && !imp.view;
  const text =
    ui.state === "ready" || ui.state === "no_session" || ui.state === "viewing_saved"
      ? (label ?? (s.active ? `${t("session.saveTo")} “${s.active.meta.name}”` : t("session.saveTo")))
      : t(LABEL[ui.state]!);
  const title =
    ui.state === "no_session"
      ? t("session.saveNeedsActive")
      : ui.state === "viewing_saved"
        ? t("save.viewingSaved")
        : noImport
          ? t("session.saveImport.none")
          : undefined;
  return (
    <button
      className={`chip save-chip ${ui.state}`}
      disabled={ui.disabled || noImport || busyElsewhere}
      title={title}
      aria-live="polite"
      onClick={() => void (what === "import" ? s.saveImport() : s.saveLive())}
    >
      {ui.state === "saving" && <span className="spinner" aria-hidden />}
      {text}
    </button>
  );
}

/** One line under the buttons: what was saved where and when, or why it failed. */
export function SaveStatusLine() {
  const { t } = useI18n();
  const s = useSession();
  if (s.saveError) {
    return (
      <p className="save-line failed" role="alert">
        {t("save.failedLine")} <span className="meta">{t("error.detail")}: <span className="mono">{saveErrorDetail(s.saveError)}</span></span>
      </p>
    );
  }
  if (!s.lastSaved) return null;
  const l = s.lastSaved;
  return (
    <p className="save-line ok" role="status">
      ✓ {t("save.savedLine")} “{l.snapshot.label}” → “{l.sessionName}” · {fmtLocalTime(l.at)}. {t("save.where")}
    </p>
  );
}
