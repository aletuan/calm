# ADR-010: Scope grants and L1 probes (M2)

**Status:** Accepted for beta
**Date:** 2026-10-31
**Refines:** ADR-001 (vantage and scope), ADR-005 (safety and privileges)

## Context
M2 adds the first traffic Calm *sends*: S01 (admin interface reachability), N03 (POS test endpoint isolation) and N01 (cooperative client isolation). Being connected to Guest Wi-Fi does not authorize probing anything (methodology §Ethical baseline). FR-006/NFR-05 ask for an allowlist that cannot be bypassed; AT-02/03/07/08/11 fix the behaviour.

## Decision
- **Scope grant** (`calm_domain::Scope`), approved once in Session setup and never edited; a change is *revoke, then approve a new one*. One usable scope per session.
  - Targets are **literal IP addresses** with their own port lists and a role (admin interface, test POS, receiver, gateway, other). No hostnames (DNS could redirect), no ranges (no accidental sweeps), at most 16 targets × 16 ports.
  - **Private space only:** RFC 1918, 100.64/10, IPv6 ULA. Loopback, link-local, multicast, broadcast and every public address are refused — a public address may belong to someone else.
  - Required: authorization reference, who gave permission, who runs the tests, and an explicit "I hold written permission" confirmation. Validity ≤ 7 days. Budget: 1–10 probes/s (default 5), timeout 0.5–5 s (default 3), one target at a time. Level fixed at L1.
  - **Bound to the network** it was approved on: default gateway, IPv4 subnet, and SSID when macOS lets us read it. Elsewhere, nothing runs.
- **Integrity:** the scope is a sealed record in the encrypted session store (ADR-009); AES-GCM authentication rejects any modified byte. Revocation is an audit event. No PKI signature in M2 — plugin signing arrives with M4.
- **Enforcement per probe:** `calm_orchestrator::authorize` runs immediately before every connection: scope present, not revoked, not expired, level, address policy (again), exact target and port, same network (re-read at most every 5 s). It returns a `Grant` that only it can construct; the probe runner accepts nothing else.
- **Probe = one TCP connect, closed at once.** No payload, no banner read, no raw sockets, no privileges. Outcomes: accepted / reset / no reply / local error / denied / cancelled.
- **Emergency Stop** cancels every probe not yet sent (a connect in flight ends at its timeout) and stops the capture; audited.
- **Decision table** (`checks::result`), deterministic and exhaustively tested:
  - accepted → Fail (S01 medium, N01/N03 high), confidence high; never claims login, data access or service identity (AT-08).
  - S01: resets on every port → Pass, medium, "for these ports only"; silence → Inconclusive (no pass from silence).
  - N01/N03: silence → Pass only if the user confirmed the listener was running at run time, else Inconclusive (AT-07); a reset → N01 Fail (medium), N03 Warning (low, a firewall may answer).
  - no target → Not tested; denied or stopped → Not tested; local error → Inconclusive.
- **Evidence:** each run (`ChecksRun`: every probe record + results) is a sealed `findings` record. The audit trail logs `scope_approved/revoked`, `checks_started/finished`, `probe_allowed/denied`, `emergency_stop` by **id only** — never an address.

## Reasons
Deny-by-default at the last possible moment means no UI path, future plugin or stale state can widen what is probed. Literal private addresses and TCP-connect-only keep the blast radius to what an owner can picture and approve.

## Consequences & trade-offs
- No UDP, ICMP or service fingerprinting yet; N02/N04/N05/S02 come later with their own rules.
- A connect already in flight cannot be interrupted; Emergency Stop takes effect within one timeout (≤ 5 s).
- A user who wrongly confirms "receiver running" can produce a false N01/N03 pass; the claim is labelled as the user's, and the result stays medium confidence.

## Validation / revisit trigger
Tests: `crates/orchestrator` (scope, probe, checks — mutation-checked), `apps/desktop/src-tauri` (scopes, assess). Revisit when plugins (M4) need grants, or when a cooperative receiver app can confirm itself.

## Revision 2026-11-01 — first field run
A real run (home network, one admin target, S01 Fail) showed three gaps, now closed:
- **Where the Mac stands is stated, not assumed.** The scope records `vantage: guest | main | unknown` (required in the form; "not sure" is allowed). Each run copies it. Titles and claims say "reachable from Guest Wi-Fi / the main network / this network". Scopes and runs stored earlier read as `unknown`.
- **Targets outside the Mac's subnet are flagged in preflight** (`PlanItem.outside_subnet`, `calm_orchestrator::in_subnet`). They are still allowed (private address, explicit scope), but the user sees that the probe is routed through the gateway to another device.
- **Not tested has no confidence.** `CheckResult.confidence` is `None` whenever status is Not tested; the UI shows "—", also for older runs that stored "high".

## Revision 2026-11-01 — capability scopes (ADR-011, accepted)
ADR-011 (accepted for beta) replaces three points above; everything else stands:
- **Targets:** private CIDR `ranges` (at most /24, with required `exclusions`) are allowed next to literal addresses. Public addresses stay refused.
- **Level:** no longer fixed at L1. A scope lists capabilities (`tcp_connect`, `host_discovery`, `reverse_dns`, `syn_scan`, `service_detection`, `os_detection`, `nse`), each ticked by the owner.
- **Enforcement:** Nmap runs are authorized per run plan (every target, port, flag and script) instead of per probe. Calm's own TCP-connect runner keeps per-probe authorization.
