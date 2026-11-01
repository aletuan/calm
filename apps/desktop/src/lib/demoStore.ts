import type { SessionInput, SessionSummary, SnapshotKind, SnapshotSummary } from "./ipc";

const DAY_MS = 86_400_000;

type Stored = { summary: SnapshotSummary; payload: unknown };

/**
 * In-memory stand-in for `calm-store`, used only by the browser preview.
 * Same rules as the Rust store and the desktop commands: creating a session
 * activates it, saving needs an active session and touches it, deleting the
 * active session clears it, retention counts from the last change. No
 * encryption: nothing here ever reaches a disk.
 */
export class DemoStore {
  private sessions = new Map<string, SessionSummary>();
  private snaps = new Map<string, Stored>();
  private activeId: string | null = null;
  private seq = 0;

  constructor(private readonly now: () => number) {}

  private newId(): string {
    this.seq += 1;
    return `demo${String(this.seq).padStart(28, "0")}`;
  }

  private notFound(): never {
    throw { kind: "not_found" };
  }

  get(id: string): SessionSummary {
    const s = this.sessions.get(id);
    if (!s) this.notFound();
    const snaps = [...this.snaps.values()].filter((x) => x.summary.session_id === id);
    return { ...s, snapshot_count: snaps.length, stored_bytes: snaps.reduce((a, x) => a + x.summary.size_bytes, 0) };
  }

  list(): SessionSummary[] {
    return [...this.sessions.keys()]
      .map((id) => this.get(id))
      .sort((a, b) => b.created_at_ms - a.created_at_ms || (b.id > a.id ? 1 : -1));
  }

  create(input: SessionInput): SessionSummary {
    const id = this.newId();
    const t = this.now();
    this.sessions.set(id, {
      id,
      meta: { ...input.meta },
      created_at_ms: t,
      updated_at_ms: t,
      retention_days: input.retention_days,
      snapshot_count: 0,
      stored_bytes: 0,
    });
    this.activeId = id;
    return this.get(id);
  }

  remove(id: string): void {
    if (!this.sessions.delete(id)) this.notFound();
    for (const [k, v] of this.snaps) if (v.summary.session_id === id) this.snaps.delete(k);
    if (this.activeId === id) this.activeId = null;
  }

  active(): SessionSummary | null {
    return this.activeId ? this.get(this.activeId) : null;
  }

  activate(id: string | null): SessionSummary | null {
    if (id !== null && !this.sessions.has(id)) this.notFound();
    this.activeId = id;
    return this.active();
  }

  save(kind: SnapshotKind, label: string, payload: unknown): SnapshotSummary {
    const sid = this.activeId;
    if (!sid || !this.sessions.has(sid)) this.notFound();
    const t = this.now();
    const summary: SnapshotSummary = {
      id: this.newId(),
      session_id: sid,
      kind,
      label,
      created_at_ms: t,
      size_bytes: JSON.stringify(payload ?? null).length,
    };
    this.snaps.set(summary.id, { summary, payload: structuredClone(payload) });
    this.sessions.get(sid)!.updated_at_ms = t;
    return summary;
  }

  snapshots(sessionId: string): SnapshotSummary[] {
    return [...this.snaps.values()]
      .filter((x) => x.summary.session_id === sessionId)
      .map((x) => x.summary)
      .sort((a, b) => b.created_at_ms - a.created_at_ms || (b.id > a.id ? 1 : -1));
  }

  open(id: string): Stored {
    const s = this.snaps.get(id);
    if (!s) this.notFound();
    return { summary: s.summary, payload: structuredClone(s.payload) };
  }

  removeSnapshot(id: string): void {
    const s = this.snaps.get(id);
    if (!s) this.notFound();
    this.snaps.delete(id);
    const sess = this.sessions.get(s.summary.session_id);
    if (sess) sess.updated_at_ms = this.now();
  }

  /** Deletes sessions idle for longer than their retention. */
  purge(): number {
    const t = this.now();
    let n = 0;
    for (const s of [...this.sessions.values()]) {
      if (s.retention_days != null && s.updated_at_ms + s.retention_days * DAY_MS < t) {
        this.remove(s.id);
        n += 1;
      }
    }
    return n;
  }
}
