import { useImport } from "../app/imported";
import { useStoreOpened } from "../app/session";
import { useI18n } from "../i18n";
import { importErrorMessage } from "../lib/errorMessage";
import { ErrorText } from "./ErrorText";
import { SaveButton, SaveStatusLine } from "./SaveStatus";

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
      {error && importErrorMessage(error) && (
        <div className="notice" role="alert">
          <strong>{t("import.err.title")}</strong>
          <ErrorText message={importErrorMessage(error)!} />
        </div>
      )}
    </>
  );
}
