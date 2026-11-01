import { useEffect, useState } from "react";
import { useI18n, type Locale } from "../i18n";
import { applyDensity, DENSITIES, readDensity, saveDensity, type Density } from "../lib/density";
import { getAppInfo, type AppInfo } from "../lib/ipc";

/** Three spaced lines (comfortable) or four tight ones (compact). */
export function DensityIcon({ compact }: { compact: boolean }) {
  const ys = compact ? [2, 5, 8, 11] : [2.5, 6.5, 10.5];
  return (
    <svg width="14" height="13" viewBox="0 0 14 13" aria-hidden focusable="false">
      {ys.map((y) => (
        <line key={y} x1="1.5" x2="12.5" y1={y} y2={y} stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      ))}
    </svg>
  );
}

const LOCALES: { id: Locale; name: string }[] = [
  { id: "en", name: "English" },
  { id: "vi", name: "Tiếng Việt" },
];

/** Settings: display preferences, the privacy defaults in effect, and version. */
export function SettingsScreen() {
  const { t, locale, setLocale } = useI18n();
  const [density, setDensity] = useState<Density>(readDensity);
  const [info, setInfo] = useState<AppInfo | null>(null);
  useEffect(() => {
    getAppInfo().then(setInfo).catch(() => setInfo(null));
  }, []);
  const pick = (d: Density) => {
    setDensity(d);
    applyDensity(d);
    saveDensity(d);
  };
  return (
    <>
      <header className="screen-header">
        <h1>{t("nav.settings")}</h1>
        <p>{t("settings.desc")}</p>
      </header>

      <section className="settings-section" aria-labelledby="set-display">
        <h2 className="section-title" id="set-display">
          {t("settings.display")}
        </h2>
        <div className="setting-row">
          <div className="setting-text">
            <strong>{t("footer.language")}</strong>
            <span className="meta small">{t("settings.languageHint")}</span>
          </div>
          <div className="seg" role="group" aria-label={t("footer.language")}>
            {LOCALES.map((l) => (
              <button key={l.id} lang={l.id} aria-pressed={locale === l.id} onClick={() => setLocale(l.id)}>
                {l.name}
              </button>
            ))}
          </div>
        </div>
        <div className="setting-row">
          <div className="setting-text">
            <strong>{t("footer.density")}</strong>
            <span className="meta small">{t("settings.densityHint")}</span>
          </div>
          <div className="seg" role="group" aria-label={t("footer.density")}>
            {DENSITIES.map((d) => (
              <button key={d} aria-pressed={density === d} onClick={() => pick(d)}>
                <DensityIcon compact={d === "compact"} />
                {t(d === "comfortable" ? "footer.comfortable" : "footer.compact")}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="settings-section" aria-labelledby="set-privacy">
        <h2 className="section-title" id="set-privacy">
          {t("settings.empty.title")}
        </h2>
        <p className="meta">{t("settings.empty.body")}</p>
      </section>

      <section className="settings-section" aria-labelledby="set-about">
        <h2 className="section-title" id="set-about">
          {t("settings.about")}
        </h2>
        <dl className="file-facts">
          <dt>{t("settings.version")}</dt>
          <dd className="mono">{info ? `v${info.version}` : "…"}</dd>
          <dt>{t("settings.stage")}</dt>
          <dd>{t("footer.skeleton")}</dd>
          <dt>{t("settings.schema")}</dt>
          <dd className="mono">{info?.schemaVersion ?? "…"}</dd>
        </dl>
      </section>
    </>
  );
}
