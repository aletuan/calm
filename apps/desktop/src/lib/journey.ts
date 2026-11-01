import type { ScreenId } from "../app/nav";

/**
 * The four steps of an assessment, as the Sessions screen shows them:
 * session → scope → run checks → read findings. Pure, so the checklist
 * says the same thing the app enforces.
 */
export type StepId = "session" | "scope" | "run" | "findings";
export type StepState = "done" | "current" | "todo";

export interface JourneyFacts {
  hasSession: boolean;
  /** A usable (approved, not revoked, not expired) scope exists. */
  hasScope: boolean;
  /** Stored check runs in the active session. */
  runs: number;
}

export interface Step {
  id: StepId;
  state: StepState;
  /** Where the step is done. */
  screen: ScreenId;
}

const ORDER: { id: StepId; screen: ScreenId; done: (f: JourneyFacts) => boolean }[] = [
  { id: "session", screen: "setup", done: (f) => f.hasSession },
  { id: "scope", screen: "assessment", done: (f) => f.hasSession && f.hasScope },
  { id: "run", screen: "assessment", done: (f) => f.hasSession && f.runs > 0 },
  // Reading findings is never "done": it becomes the current step once a run exists.
  { id: "findings", screen: "findings", done: () => false },
];

export function journey(f: JourneyFacts): Step[] {
  let currentGiven = false;
  return ORDER.map(({ id, screen, done }) => {
    if (done(f)) return { id, screen, state: "done" as const };
    if (currentGiven) return { id, screen, state: "todo" as const };
    currentGiven = true;
    return { id, screen, state: "current" as const };
  });
}
