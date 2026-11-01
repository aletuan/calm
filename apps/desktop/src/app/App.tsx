import { useEffect, useState } from "react";
import { useI18n } from "../i18n";
import { applyDensity, readDensity } from "../lib/density";
import { getAppInfo, type AppInfo } from "../lib/ipc";
import { navKey, screens } from "./nav";
import { useCapture } from "./capture";
import { useImport } from "./imported";
import { useSelection } from "./selection";
import { useSession } from "./session";
import { useProfile } from "./profile";
import { useAssessMode } from "./assessMode";
import { Screen } from "../screens/Screen";
import calmIcon from "../assets/calm-mark.png";

export function App() {
  const { source: importSource } = useImport();
  const { active: activeSession } = useSession();
  const { t } = useI18n();
  const { screen: active, setScreen: setActive } = useSelection();
  const [info, setInfo] = useState<AppInfo | null>(null);
  const { profile } = useProfile();
  const { running: capturing, view: captureView } = useCapture();
  const mode = useAssessMode(activeSession?.id ?? null, active);
  const networkLabel = (() => {
    if (!profile) return t("context.notConnected");
    const ssid = profile.wifi.ssid.value;
    const gw = profile.default_gateway.value;
    const name = ssid ?? (profile.wifi.channel.value != null ? t("context.ssidHidden") : t("context.notConnected"));
    return gw ? `${name} · gw ${gw}` : name;
  })();

  useEffect(() => {
    getAppInfo().then(setInfo).catch(() => setInfo(null));
  }, []);

  // The saved density applies from the first frame; Settings changes it.
  useEffect(() => applyDensity(readDensity()), []);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <img className="brand-icon" src={calmIcon} alt="" aria-hidden />
          Calm
        </div>
        <nav aria-label="Primary">
          {screens.map((id) => (
            <button
              key={id}
              className="nav-item"
              aria-current={active === id ? "page" : undefined}
              onClick={() => setActive(id)}
            >
              <span className="nav-mark" aria-hidden />
              {t(navKey(id))}
            </button>
          ))}
        </nav>
        <footer className="sidebar-foot">
          <div className="foot-version" title={t("footer.skeleton")}>
            {info ? `v${info.version}` : "…"} · {t("footer.stage")}
          </div>
        </footer>
      </aside>

      <main className="main">
        <div className="context-bar">
          <span>
            {t("context.network")}: <strong>{networkLabel}</strong>
          </span>
          <span>
            {t("context.mode")}: <strong className={mode === "running" ? "mode-active" : undefined}>{t(mode === "running" ? "context.checksRunning" : mode === "scoped" ? "context.scoped" : "context.passive")}{capturing ? ` · ${t("context.capturing")} ${captureView?.interface ?? ""}` : ""}</strong>
          </span>
          <span>
            {t("context.vantage")}: <strong>{t("context.vantageValue")}</strong>
            {importSource === "imported" && <strong> · {t("context.viewingImport")}</strong>}
            {importSource === "saved" && <strong> · {t("context.viewingSaved")}</strong>}
          </span>
          <span>
            {t("context.session")}: <strong>{activeSession?.meta.name ?? t("context.noSession")}</strong>
          </span>
        </div>
        <Screen id={active} />
      </main>
    </div>
  );
}
