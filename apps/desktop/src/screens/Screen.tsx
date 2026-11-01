import { useI18n } from "../i18n";
import { descKey, emptyBodyKey, emptyTitleKey, navKey, type ScreenId } from "../app/nav";
import { AssessmentScreen } from "./AssessmentScreen";
import { FindingsScreen } from "./FindingsScreen";
import { OverviewScreen } from "./OverviewScreen";
import { SessionScreen } from "./SessionScreen";
import { SettingsScreen } from "./SettingsScreen";
import { TopologyScreen } from "./TopologyScreen";
import { TrafficScreen } from "./TrafficScreen";

/** One primary surface per screen; empty states always explain (design §4). */
export function Screen({ id }: { id: ScreenId }) {
  const { t } = useI18n();
  if (id === "setup") return <SessionScreen />;
  if (id === "overview") return <OverviewScreen />;
  if (id === "topology") return <TopologyScreen />;
  if (id === "traffic") return <TrafficScreen />;
  if (id === "assessment") return <AssessmentScreen />;
  if (id === "findings") return <FindingsScreen />;
  if (id === "settings") return <SettingsScreen />;
  return (
    <>
      <header className="screen-header">
        <h1>{t(navKey(id))}</h1>
        <p>{t(descKey(id))}</p>
      </header>
      <section className="surface" aria-live="polite">
        <div className="empty">
          <h2>{t(emptyTitleKey(id))}</h2>
          <p>{t(emptyBodyKey(id))}</p>
        </div>
      </section>
    </>
  );
}
