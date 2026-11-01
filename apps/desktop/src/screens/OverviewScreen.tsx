import { useProfile } from "../app/profile";
import { useI18n } from "../i18n";
import type { MessageKey } from "../i18n/en";
import type { IpAddress, NetworkProfile, Sourced } from "../lib/ipc";

type T = (k: MessageKey) => string;
type Row = { label: MessageKey; field: Sourced<unknown>; format?: (v: never, t: T) => string };

const dbm = (v: number) => `${v} dBm`;
const mbps = (v: number) => `${v} Mbps`;
const ips = (v: IpAddress[]) =>
  v.map((a) => `${a.address}${a.prefix != null ? `/${a.prefix}` : ""}${a.flags.length ? ` (${a.flags.join(", ")})` : ""}`).join("\n");
const list = (v: string[]) => v.join("\n");
const privacy = (v: boolean, t: T) => t(v ? "value.macPrivate" : "value.macUniversal");
const scope = (v: string, t: T) => t(`value.ipv6.${v}` as MessageKey);

function sections(p: NetworkProfile): { title: MessageKey; rows: Row[] }[] {
  const w = p.wifi;
  return [
    {
      title: "overview.section.wifi",
      rows: [
        { label: "field.ssid", field: w.ssid },
        { label: "field.bssid", field: w.bssid },
        { label: "field.security", field: w.security },
        { label: "field.channel", field: w.channel },
        { label: "field.band", field: w.band },
        { label: "field.width", field: w.channel_width },
        { label: "field.rssi", field: w.rssi_dbm, format: dbm as (v: never) => string },
        { label: "field.noise", field: w.noise_dbm, format: dbm as (v: never) => string },
        { label: "field.phy", field: w.phy_mode },
        { label: "field.txrate", field: w.tx_rate_mbps, format: mbps as (v: never) => string },
        { label: "field.country", field: w.country_code },
        { label: "field.interface", field: w.interface },
      ],
    },
    {
      title: "overview.section.addressing",
      rows: [
        { label: "field.ipv4", field: p.ipv4, format: ips as (v: never) => string },
        { label: "field.ipv6", field: p.ipv6, format: ips as (v: never) => string },
        { label: "field.ipv6Scope", field: p.ipv6_scope, format: scope as (v: never, t: T) => string },
        { label: "field.hw", field: p.hardware_address },
        { label: "field.hwKind", field: p.hardware_address_private, format: privacy as (v: never, t: T) => string },
      ],
    },
    {
      title: "overview.section.routing",
      rows: [
        { label: "field.gateway", field: p.default_gateway },
        { label: "field.routeIf", field: p.default_route_interface },
        { label: "field.dns", field: p.dns_servers, format: list as (v: never) => string },
      ],
    },
  ];
}

function PermissionNotice({ p }: { p: NetworkProfile }) {
  const { t } = useI18n();
  const { requestAccess, waitingForPrompt } = useProfile();
  if (p.demo) return <div className="notice">{t("perm.demo")}</div>;
  if (!p.bundled_app)
    return (
      <div className="notice">
        <strong>{t("perm.unbundled.title")}</strong>
        <p>{t("perm.unbundled.body")}</p>
      </div>
    );
  if (p.location_authorization === "not_determined")
    return (
      <div className="notice">
        <strong>{t("perm.notDetermined.title")}</strong>
        <p>{t("perm.notDetermined.body")}</p>
        <button className="button-primary" onClick={() => void requestAccess()} disabled={waitingForPrompt}>
          {waitingForPrompt ? t("perm.waiting") : t("perm.button")}
        </button>
      </div>
    );
  if (p.location_authorization === "denied" || p.location_authorization === "restricted")
    return (
      <div className="notice">
        <strong>{t("perm.denied.title")}</strong>
        <p>{t("perm.denied.body")}</p>
      </div>
    );
  return null;
}

function noteKey(note: string | null): MessageKey {
  const known = [
    "location_permission_not_granted",
    "location_permission_denied",
    "unbundled_dev_build_cannot_get_location",
    "not_associated_or_hidden",
    "not_associated",
    "no_wifi_interface",
    "unsupported_platform",
    "no_default_route",
    "no_ipv4_address",
    "no_ipv6_address",
    "no_default_resolver",
    "locally_administered",
    "universally_administered",
  ];
  return (note && known.includes(note) ? `note.${note}` : "note.unknown") as MessageKey;
}

export function OverviewScreen() {
  const { t } = useI18n();
  const { profile, loading, error, refresh } = useProfile();

  return (
    <>
      <header className="screen-header screen-header-row">
        <div>
          <h1>{t("nav.overview")}</h1>
          <p>{t("overview.desc")}</p>
        </div>
        <button className="chip" onClick={() => void refresh()} disabled={loading}>
          {t("overview.refresh")}
        </button>
      </header>

      {error && <div className="notice">{t("overview.error")}: <span className="mono">{error}</span></div>}
      {profile && <PermissionNotice p={profile} />}

      {profile && (
        <div className="kv-sections">
          {sections(profile).map((s) => (
            <section key={s.title}>
              <h2 className="section-title">{t(s.title)}</h2>
              <table className="kv-table">
                <thead>
                  <tr>
                    <th>{t("overview.col.field")}</th>
                    <th>{t("overview.col.value")}</th>
                    <th>{t("overview.col.status")}</th>
                    <th>{t("overview.col.source")}</th>
                  </tr>
                </thead>
                <tbody>
                  {s.rows.map((r) => {
                    const known = r.field.value !== null;
                    const shown = known ? (r.format ? r.format(r.field.value as never, t) : String(r.field.value)) : "—";
                    const statusText = !known
                      ? `${t("status.unknown")} — ${t(noteKey(r.field.note))}`
                      : r.field.status === "inferred"
                        ? `${t("status.inferred")} — ${t(noteKey(r.field.note))}`
                        : t("status.observed");
                    const mark = !known ? "unknown" : r.field.status === "inferred" ? "inferred" : "observed";
                    return (
                      <tr key={r.label} data-status={r.field.status}>
                        <td>{t(r.label)}</td>
                        <td className="mono value">{shown}</td>
                        <td>
                          <span className={`status-mark ${mark}`} aria-hidden />
                          {statusText}
                        </td>
                        <td className="mono meta" title={r.field.source}>
                          {r.field.source}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </section>
          ))}
          <p className="footnote">
            {t("overview.footnote")}{" "}
            <span className="mono">{t("overview.observedAt")}: {new Date(profile.observed_at).toLocaleString()}</span>
          </p>
        </div>
      )}
    </>
  );
}
