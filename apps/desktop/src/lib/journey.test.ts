import { describe, expect, it } from "vitest";
import { journey } from "./journey";

const states = (f: Parameters<typeof journey>[0]) => journey(f).map((s) => `${s.id}:${s.state}`);

describe("assessment journey", () => {
  it("starts at the session", () => {
    expect(states({ hasSession: false, hasScope: false, runs: 0 })).toEqual(["session:current", "scope:todo", "run:todo", "findings:todo"]);
  });
  it("asks for a scope once a session exists", () => {
    expect(states({ hasSession: true, hasScope: false, runs: 0 })).toEqual(["session:done", "scope:current", "run:todo", "findings:todo"]);
  });
  it("then the run, then the findings", () => {
    expect(states({ hasSession: true, hasScope: true, runs: 0 })).toEqual(["session:done", "scope:done", "run:current", "findings:todo"]);
    expect(states({ hasSession: true, hasScope: true, runs: 2 })).toEqual(["session:done", "scope:done", "run:done", "findings:current"]);
  });
  it("an expired or revoked scope after a run asks for a new scope, keeping the run done", () => {
    expect(states({ hasSession: true, hasScope: false, runs: 1 })).toEqual(["session:done", "scope:current", "run:done", "findings:todo"]);
  });
  it("without a session nothing else counts as done", () => {
    expect(states({ hasSession: false, hasScope: true, runs: 3 })).toEqual(["session:current", "scope:todo", "run:todo", "findings:todo"]);
  });
  it("points each step at its screen", () => {
    expect(journey({ hasSession: true, hasScope: false, runs: 0 }).map((s) => s.screen)).toEqual(["setup", "assessment", "assessment", "findings"]);
  });
});
