import { useImport } from "../app/imported";
import { useStoreOpened } from "../app/session";
import { useI18n } from "../i18n";
import type { MessageKey } from "../i18n/en";
import { fmtBytes } from "../lib/format";
import type { ImportError } from "../lib/ipc";
import { SaveButton, SaveStatusLine } from "./SaveStatus";

function errorText(e: ImportError, t: (k: MessageKey) => string): string {
  switch (e.kind) {
    case "not_a_capture":
      return t("import.err.notCapture");
    case "too_large":
      return `${t("import.err.tooLarge")} (${fmtBytes(e.size_bytes)} > ${fmtBytes(e.limit_bytes)})`;
    case "unreadable":
      return `${t("import.err.unreadable")}: ${e.detail}`;
    default:
      return "";
  }
}

/**
 * Source switch shared by Traffic and Topology: this Mac's live data, one
 * imported capture file, or one saved snapshot. They are never shown mixed.
 */
export function SourceBar() {
  const { t } = useI18n();
  const { view, busy, error, source, setSource, pick, clear, saved, closeSaved } = useImport();
  // Opening the store here too, so saving works without visiting Session setup first.
  useStoreOpened();
  return (
    <>
      <div className="source-bar" role="group" aria-label={t("import.source")}>
        <span className="meta">{t("import.source")}:</span>
        <div className="seg-chips">
          <button className="chip" aria-pressed={source === "live"} onClick={() => setSource("live")}>
            {t("import.source.live")}
          </button>
          {view && (
            <button className="chip" aria-pressed={source === "imported"} onClick={() => setSource("imported")}>
              {t("import.source.file")}: <span className="mono">{view.file_name}</span>
            </button>
          )}
          {saved && (
            <button className="chip" aria-pressed={source === "saved"} onClick={() => setSource("saved")}>
              {t("session.source.saved")}: {saved.snapshot.label}
            </button>
          )}
        </div>
        <span className="push" />
        <SaveButton />
        {saved && source === "saved" && (
          <button className="chip" onClick={closeSaved}>
            {t("session.closeSaved")}
          </button>
        )}
        <button className="chip" onClick={() => void pick()} disabled={busy}>
          {busy ? t("import.reading") : view ? t("import.replace") : t("import.pick")}
        </button>
        {view && (
          <button className="chip" onClick={() => void clear()} disabled={busy}>
            {t("import.clear")}
          </button>
        )}
      </div>
      <SaveStatusLine />
      {error && (
        <div className="notice" role="alert">
          <strong>{t("import.err.title")}</strong>
          <p>{errorText(error, t)}</p>
        </div>
      )}
    </>
  );
}
