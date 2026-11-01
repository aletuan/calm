import type { SessionSummary } from "./ipc";

export type SessionTab = "current" | "all";

/** Without an active session there is nothing to show in "Current". */
export const defaultTab = (hasActive: boolean): SessionTab => (hasActive ? "current" : "all");

/** Case- and accent-insensitive match on name, site and operator; every word must match. */
export function filterSessions(list: SessionSummary[], query: string): SessionSummary[] {
  const fold = (s: string) =>
    s
      .normalize("NFD")
      .replace(/[̀-ͯ]/g, "")
      .replace(/đ/g, "d")
      .replace(/Đ/g, "D")
      .toLowerCase();
  const words = fold(query).split(/\s+/).filter(Boolean);
  if (words.length === 0) return list;
  return list.filter((x) => {
    const hay = fold(`${x.meta.name} ${x.meta.site} ${x.meta.operator}`);
    return words.every((w) => hay.includes(w));
  });
}
