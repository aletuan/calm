import type { MessageKey } from "../i18n/en";

/** Screen inventory (docs/product/04-user-journeys.md). Evidence detail is a drill-down, not a nav item. */
export const screens = [
  "setup",
  "overview",
  "topology",
  "traffic",
  "assessment",
  "findings",
  "plugins",
  "reports",
  "settings",
] as const;

export type ScreenId = (typeof screens)[number];

export const navKey = (id: ScreenId) => `nav.${id}` as MessageKey;
export const descKey = (id: ScreenId) => `${id}.desc` as MessageKey;
export const emptyTitleKey = (id: ScreenId) => `${id}.empty.title` as MessageKey;
export const emptyBodyKey = (id: ScreenId) => `${id}.empty.body` as MessageKey;
