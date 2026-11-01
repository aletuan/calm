import { describe, expect, it } from "vitest";
import { CHECKS, POSITIONS, TARGET_ROLES } from "../lib/assess";
import { FLOW_COLUMNS } from "../lib/columns";
import { DRAFT_ERROR_KINDS } from "../lib/scopeForm";
import { CAPABILITIES, NSE_ALLOWLIST } from "../lib/capabilities";
import { PURPOSES } from "../lib/flowPurpose";
import { RETENTION_CHOICES, parseSessionForm, emptyForm, type FormError } from "../lib/sessionForm";
import { en } from "./en";
import { vi } from "./vi";

const keys = Object.keys(en) as (keyof typeof en)[];

describe("i18n", () => {
  it("Vietnamese has a non-empty text for every English key", () => {
    for (const k of keys) expect(vi[k]?.trim(), k).toBeTruthy();
    expect(Object.keys(vi).sort()).toEqual([...keys].sort());
  });

  it("keys built at runtime exist", () => {
    const dynamic = [
      ...["this_mac", "capture_host", "access_point_radio", "default_gateway", "dns_resolver", "local_peer", "external_destinations", "unknown"].map((r) => `role.${r}`),
      ...["not_a_capture", "truncated", "bad_length", "length_mismatch", "unknown_interface", "bad_capture_length", "io"].map((r) => `import.reason.${r}`),
      ...(["name_required", "name_too_long", "field_too_long", "notes_too_long", "retention_invalid"] satisfies FormError[]).map((e) => `session.err.${e}`),
      ...["observed", "inferred", "validated", "unverified"].map((s) => `status.${s}`),
      ...["low", "medium", "high"].map((c) => `confidence.${c}`),
      ...["capture:flows", "capture:link-binding", "import:flows", "import:link-binding", "import:vantage", "import:forwarding", "profile:corewlan", "profile:route", "profile:scutil-dns", "profile:ifconfig"].map((e) => `ev.${e}`),
      ...TARGET_ROLES.flatMap((r) => [`scope.role.${r}`, `scope.roleHint.${r}`]),
      ...["active", "revoked", "expired"].map((x) => `scope.state.${x}`),
      ...DRAFT_ERROR_KINDS.map((k) => `scope.err.${k}`),
      ...POSITIONS.flatMap((p) => [`position.${p}`, `position.from.${p}`]),
      ...["session", "scope", "run", "findings"].flatMap((x) => [`journey.${x}`, `journey.${x}.hint`]),
      ...["done", "current", "todo"].map((x) => `journey.state.${x}`),
      ...["ASSOCIATED_WITH", "DEFAULT_ROUTE_VIA", "RESOLVES_VIA", "FLOW_OBSERVED", "other"].map((x) => `relation.${x}`),
      ...["not_an_address", "unspecified", "loopback", "multicast", "broadcast", "link_local", "not_private"].map((r) => `scope.err.address.${r}`),
      ...["hours", "rate", "timeout_s"].map((f) => `scope.err.number.${f}`),
      ...["active_exists", "no_active_session", "store", "invalid"].map((k) => `scope.err.${k}`),
      ...["already_running", "no_active_session", "no_scope", "network_changed", "store"].map((k) => `assess.err.${k}`),
      ...CHECKS.flatMap((c) => ["title", "short", "action", "limits"].map((x) => `check.${c}.${x}`)),
      ...["pass", "fail", "warning", "inconclusive", "not_tested", "informational"].map((x) => `finding.status.${x}`),
      ...["info", "low", "medium", "high", "critical"].map((x) => `finding.severity.${x}`),
      ...["connected", "all_refused", "reset_from_listener", "silent_confirmed_listener", "silent_unconfirmed", "silent", "local_error", "denied", "stopped", "no_target"].map((x) => `finding.reason.${x}`),
      ...["tcp_accepted", "tcp_reset", "no_reply", "listener_confirmed_by_user", "login_or_auth_bypass", "access_to_management_data", "service_identity", "listener_was_running", "blocked_on_other_ports", "blocked_for_other_devices"].map((x) => `finding.claim.${x}`),
      ...["connected", "refused", "timed_out", "unreachable", "denied", "cancelled"].map((x) => `probe.outcome.${x}`),
      ...["no_grant", "revoked", "expired", "level_exceeded", "target_not_allowed", "port_not_allowed", "network_unknown", "network_changed", "address_not_allowed", "capability_not_granted"].map((x) => `probe.denied.${x}`),
      ...PURPOSES.flatMap((p) => [`purpose.${p}`, `purpose.${p}.why`]),
      ...FLOW_COLUMNS.map((c) => `traffic.col.${c}`),
      ...["capture_host", "local_peer", "external_destinations"].flatMap((r) => [`explain.${r}.what`, `explain.${r}.not`]),
      // ADR-011 scope form (lib/capabilities).
      ...CAPABILITIES.flatMap((c) => [`capability.${c}`, `capability.${c}.sends`]),
      ...["L1", "L2"].map((l) => `scope.level.${l}`),
      ...NSE_ALLOWLIST.map((n) => `nse.${n}`),
      // "What to do" for results that are not a failure (lib/findingDetail.todoKey).
      ...["pass", "silent_unconfirmed", "silent", "local_error", "denied", "stopped", "no_target"].map((x) => `finding.todo.${x}`),
    ];
    for (const k of dynamic) expect(en, k).toHaveProperty([k]);
  });

  it("every retention choice can be submitted", () => {
    for (const r of RETENTION_CHOICES) expect(parseSessionForm({ ...emptyForm(), name: "x", retention: r }).ok).toBe(true);
  });

  it("product claims stay honest in both languages", () => {
    // The user attests to the capabilities they ticked, not a fixed sentence (ADR-011).
    for (const d of [en, vi]) expect(d["scope.confirm"]).toContain("{caps}");
    // Imported data must never be described as observed by this Mac.
    expect(en["import.banner.title"]).toMatch(/not observed by this Mac/);
    expect(vi["import.banner.title"]).toMatch(/không phải do Mac này quan sát/);
    // A reachable admin port is never described as a login (AT-08).
    expect(en["check.S01.limits"]).toMatch(/does not show that anyone can log in/);
    expect(vi["check.S01.limits"]).toMatch(/Không cho thấy ai đăng nhập được/);
    // Where the Mac stood is filled in, never assumed to be Guest Wi-Fi.
    for (const d of [en, vi]) for (const k of ["check.S01.title", "check.N01.title", "check.S01.short", "check.N03.short", "check.N01.short", "finding.claim.tcp_accepted", "check.N03.action", "check.N01.action"] as const) expect(d[k], k).toContain("{from}");
    for (const d of [en, vi]) for (const [k, v] of Object.entries(d)) if (k.startsWith("check.")) expect(/Guest Wi-Fi|Wi-Fi khách|SSID khách|guest SSID/.test(v), `${k}: ${v}`).toBe(false);
  });

  it("result texts claim no more than the evidence", () => {
    // A reset means packets got through to something: never "nothing reachable".
    expect(en["finding.reason.all_refused"]).not.toMatch(/nothing reachable/i);
    expect(vi["finding.reason.all_refused"]).not.toMatch(/không tới được gì/i);
    // A reset may come from a firewall in front of the host.
    expect(en["finding.reason.all_refused"]).toMatch(/firewall/);
    // Silence with a confirmed receiver is likely blocking, not proven blocking (inferred).
    expect(en["finding.reason.silent_confirmed_listener"]).toMatch(/likely/);
    expect(vi["finding.reason.silent_confirmed_listener"]).toMatch(/nhiều khả năng/);
    // calm_bpf grants read AND write on /dev/bpf* (spike nmap-bpf, F5): the setup text must say it can also send.
    expect(en["traffic.perm.note"]).toMatch(/send/);
    expect(vi["traffic.perm.note"]).toMatch(/gửi/);
    expect(en["traffic.perm.body"]).not.toMatch(/read access/);
    // Snapshots can be saved to a session, so capture consent must not promise "nothing on disk".
    expect(en["traffic.consent.memory"]).not.toMatch(/Nothing is written to disk/);
    expect(vi["traffic.consent.memory"]).not.toMatch(/Chưa ghi gì ra đĩa/);
  });
  // Voice and terminology rules (docs/design/02-voice-and-terminology.md).
  describe("voice rules", () => {
    const entries = (d: Record<string, string>) => Object.entries(d);
    /** The user's own attestations are the only first-person strings. */
    const ATTESTATIONS = new Set(["scope.confirm", "assess.receiverConfirm"]);
    const BUTTONS = ["session.create", "session.use", "session.delete", "session.confirmDelete", "session.new", "session.saveLive", "session.saveImport", "session.view", "session.open", "session.cancel", "scope.approve", "scope.revoke", "scope.revokeConfirm", "scope.addTarget", "scope.removeTarget", "assess.run", "assess.stop", "assess.openFindings", "assess.goScope", "inspector.traffic.open", "inspector.close", "import.pick", "topology.reset", "store.setAside", "import.clear", "import.replace", "perm.button", "session.closeSaved", "save.retry"] as const;

    it("Vietnamese addresses the user as \"bạn\", never anh/chị, and avoids blaming words", () => {
      const wordAt = (w: string) => new RegExp(`(^|[\\s("“])${w}(?=[\\s,.;:)"”]|$)`, "i");
      for (const [k, v] of entries(vi)) {
        expect(wordAt("anh").test(v), k).toBe(false);
        expect(wordAt("chị").test(v), k).toBe(false);
        expect(/vui lòng|không hợp lệ|thất bại/i.test(v), k).toBe(false);
        if (!ATTESTATIONS.has(k)) expect(wordAt("tôi").test(v), k).toBe(false);
      }
    });

    it("English avoids blame, filler and internal build words; first person only in attestations", () => {
      for (const [k, v] of entries(en)) {
        expect(/\b(invalid|failed|please|simply|obviously|skeleton|alpha|stub|fatal)\b/i.test(v), k).toBe(false);
        if (!ATTESTATIONS.has(k)) expect(/\b(I|my|My)\b/.test(v), k).toBe(false);
      }
    });

    it("buttons are short and in sentence case", () => {
      const PROPER = /^(Mac|Calm|Location|PCAP|PCAPNG|Wi-Fi|DNS|IP|TCP|Findings|Traffic|Topology|Sessions|Assessment|S0\d|N0\d|\/)…?$/;
      for (const k of BUTTONS) {
        for (const d of [en, vi]) {
          const words = d[k].split(/\s+/);
          expect(words.length, `${k}: ${d[k]}`).toBeLessThanOrEqual(4);
          expect(d[k].endsWith("."), k).toBe(false);
          for (const w of words.slice(1)) if (w[0] !== w[0]!.toLowerCase()) expect(PROPER.test(w), `${k}: "${w}" in "${d[k]}"`).toBe(true);
        }
      }
    });

    it("kept-English terms stay English in Vietnamese, and evidence words stay Vietnamese", () => {
      for (const [k, v] of entries(vi)) {
        // Session is kept in English; "phiên bản" (version) is a different word.
        expect(/phiên(?! bản)/i.test(v), k).toBe(false);
        // Epistemic statuses are translated everywhere, legends included.
        expect(/\b(Observed|Inferred|Unverified)\b/.test(v), k).toBe(false);
      }
    });

    it("the stop control has one name everywhere", () => {
      for (const d of [en, vi]) for (const [k, v] of entries(d)) expect(/Emergency Stop/.test(v), k).toBe(false);
    });

    it("Vietnamese uses one spelling for the same word (uỷ, hoá, khoá, xoá)", () => {
      for (const [k, v] of entries(vi)) expect(/ủy|(h|kh|x)óa/i.test(v), `${k}: ${v}`).toBe(false);
    });

    it("one term per concept: \"mã uỷ quyền\", \"suy luận\", \"packet\", \"tóm tắt flow\"", () => {
      for (const [k, v] of entries(vi)) {
        expect(/tham chiếu/i.test(v), `${k}: ${v}`).toBe(false);
        expect(/suy ra/i.test(v), `${k}: ${v}`).toBe(false);
        // Packet stays English like flow and capture; "flow summary" is translated.
        expect(/gói tin|flow summary/i.test(v), `${k}: ${v}`).toBe(false);
      }
    });

    it("buttons, field labels and columns stay close to the English length", () => {
      // VI runs longer by nature; where width is fixed, at most 1.3× (or 6 characters on very short labels).
      const fixedWidth = (k: string) => (BUTTONS as readonly string[]).includes(k) || /\.(col|field)\./.test(k) || k.startsWith("nav.");
      for (const k of Object.keys(en) as (keyof typeof en)[]) {
        if (!fixedWidth(k)) continue;
        expect(vi[k].length, `${k}: ${en[k]} → ${vi[k]}`).toBeLessThanOrEqual(Math.max(en[k].length * 1.3, en[k].length + 6));
      }
    });

    it("an input error says what is accepted, as a full sentence with nothing hidden in parentheses", () => {
      for (const d of [en, vi])
        for (const [k, v] of entries(d)) {
          if (!/^(scope|session|assess)\.err\./.test(k)) continue;
          expect(v[0] !== v[0]!.toLowerCase(), `${k} starts with a capital: ${v}`).toBe(true);
          expect(v.endsWith("."), `${k} ends with a period: ${v}`).toBe(true);
          expect(v.includes("("), `${k}: ${v}`).toBe(false);
        }
    });

    it("a system error names what Calm could not do", () => {
      for (const d of [en, vi]) for (const k of ["store.locked.title", "import.err.title", "scope.err.store", "save.failedLine", "traffic.error.title", "overview.error", "assess.err.store"] as const) expect(d[k], k).toMatch(/^Calm /);
    });

    it("text uses periods, not dashes, and no internal milestone or level names", () => {
      // The release stage in the footer ("Beta M2") is the one place a milestone name is shown on purpose.
      for (const d of [en, vi])
        for (const [k, v] of entries(d)) {
          expect(v.includes(" — "), `${k}: ${v}`).toBe(false);
          expect(/\bL\d\b/.test(v), `${k}: ${v}`).toBe(false);
          if (!k.startsWith("footer.")) expect(/\bM\d(\.\d)?\b/.test(v), `${k}: ${v}`).toBe(false);
        }
    });

    it("Vietnamese never shouts and keeps statuses in Vietnamese", () => {
      for (const [k, v] of entries(vi)) {
        expect(/\b(KHÔNG|CHƯA|ĐÃ)\b/u.test(v), `${k}: ${v}`).toBe(false);
        expect(/\b(pass|unverified|inferred|validated)\b/i.test(v), `${k}: ${v}`).toBe(false);
      }
    });

    it("the mode shown in the context bar uses one word for passive", () => {
      expect(vi["context.passive"]).toMatch(/^Thụ động/);
      expect(vi["context.scoped"]).toMatch(/^Thụ động/);
    });
  });
});
