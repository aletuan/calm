/**
 * The detail of one finding always has the same six parts, in this order
 * (docs/design/02-voice-and-terminology.md, "Finding detail"): what Calm saw,
 * what this shows, what it does not show, what to do, the evidence, and the
 * method with its limits. "What to do" is never empty: a failure gets the
 * check's fix; anything else says what would change or confirm the result.
 */
import type { MessageKey } from "../i18n/en";
import type { CheckResult } from "./assess";

export const DETAIL_SECTIONS = ["saw", "shows", "notShows", "todo", "evidence", "method"] as const;
export type DetailSection = (typeof DETAIL_SECTIONS)[number];

export function todoKey(r: CheckResult): MessageKey {
  switch (r.status) {
    case "fail":
    case "warning":
      return `check.${r.check}.action` as MessageKey;
    case "pass":
    case "informational":
      return "finding.todo.pass";
    default:
      return `finding.todo.${r.reason}` as MessageKey;
  }
}
