# Calm

**Calm** is a macOS-first, local-first security auditor for Guest Wi-Fi. One Mac joins the network, observes passively, and runs only the active checks that the network owner has authorized. It then explains the results in plain language. Product docs call it "WiFi Security Auditor".

> **Invariant.** Calm only claims what this Mac observed or what an authorized test validated. Everything else is `inferred`, `unverified`, `inconclusive` or `not_tested`, and never `pass`.

| | |
|---|---|
| Status | **M2 beta**: passive observation and capture, encrypted sessions, scope grants, first authorized checks (S01, N03, N01) |
| Platform | macOS 14+ (Sonoma), Apple Silicon first |
| Stack | Tauri 2 · Rust (workspace of crates) · React 19 + TypeScript · Swift (experiments) |
| Bundle ID | `com.aletuan.calm` |
| Languages | English and Vietnamese UI (English keys are the source) |

## What it does

1. **Sessions.** Each assessment is a session. Everything saved in it is encrypted on this Mac with a per-session AES-256-GCM key, and the master key lives in the Keychain. Deleting a session shreds its key.
2. **Network.** Wi-Fi, IP, route and DNS facts. Each fact carries its value, status and source. SSID and BSSID are read only with the user's Location consent and are never guessed.
3. **Topology.** An evidence-based logical graph, not the physical network. Line style shows how something is known: solid = observed or validated, dashed = inferred, dotted = unverified.
4. **Traffic.** Header-only local capture (snaplen 96, no promiscuous mode, memory only) or PCAP/PCAPNG import. Flows come with a plain-language Purpose column.
5. **Assessment.** Three steps:
   - **Scope grant:** literal private IPs, ports, roles, authorization, at most 7 days, bound to the network.
   - **Preflight:** what will be probed, and from which network.
   - **Run:** TCP connect only. Each probe is re-authorized just before it is sent. Emergency Stop is always available.
6. **Findings.** Status, severity and confidence are separate fields. Each finding lists what was verified, what was not, and the probes behind it.

## Quick start

Prerequisites: Xcode Command Line Tools (Swift 5.9+), Rust stable (`rust-toolchain.toml` pins components), Node 22+ and pnpm 10 (`corepack enable`).

```sh
pnpm install
pnpm dev            # Tauri app, unbundled: UI work (no Location prompt, SSID/BSSID stay unknown)
pnpm dev:bundle     # signed debug .app: needed for Wi-Fi identity (Location permission)
pnpm web:dev        # UI only, in a browser, with simulated data (no network access)
pnpm bpf:install    # one-time: capture without root (group calm_bpf + boot daemon)
```

## Quality gates

```sh
pnpm test           # vitest (UI logic) + cargo test (all crates)
pnpm check          # typecheck + vitest + rustfmt + clippy -D warnings + cargo test   ← run before every commit
pnpm coverage       # vitest --coverage + cargo llvm-cov
```

CI runs on `macos-14` and covers Rust (fmt, clippy, test), the frontend (typecheck, coverage) and Swift (build, test). See `.github/workflows/ci.yml`.

## Architecture

```text
React UI (apps/desktop/src)            screens are thin; decisions live in src/lib (pure, tested)
   │  Tauri IPC (typed commands)
Tauri shell (apps/desktop/src-tauri)   wiring only: state, threads, commands
   │
Rust crates (crates/*)                 domain logic, no UI, no Tauri
   domain ── canonical types and vocabularies (status / severity / confidence / epistemic)
   orchestrator ── scope engine (deny-by-default), probe runner, checks
   net-profile · capture · flow-engine · graph-engine · store · reporting · extension-sdk
```

The safety boundary is `calm_orchestrator::authorize`. It runs before every probe and returns a `Grant` that only it can construct. The probe runner accepts nothing else.

## Repository layout

```text
apps/desktop/          Tauri 2 shell (src-tauri/) + React/TS UI (src/)
  src/lib/             pure UI logic (tested): formatting, view models, demo/preview mirrors
  src/screens/         one component per screen
  src/styles/          tokens.css (design tokens, spacing roles) + global.css
  src/i18n/            en.ts (source) + vi.ts
crates/                Rust workspace members (see Architecture)
native/                macos-bridge (Swift experiments), capture-helper (stub)
extensions/            first-party adapters (manifests only)
rules/ knowledge/      deterministic checks; concept cards (VI/EN)
schemas/               JSON Schema mirrors of crates/domain
fixtures/              synthetic golden inputs (documentation IP ranges only)
docs/                  product, architecture + ADRs, security, design, delivery, engineering
scripts/               dev bundle, BPF access, coverage
```

## Status by milestone

| Milestone | Scope | State |
|---|---|---|
| WP1 | Platform spike: Wi-Fi identity in-process, BPF via group, notarization | Done |
| M1.1–M1.5 | Network profile, evidence topology, capture, PCAP import, encrypted sessions | Done |
| M2.1–M2.4 | Scope grant, probe runner, checks S01 · N03 · N01, Assessment and Findings screens | Done, field-tested once |
| M2 (rest) | Nmap adapter; checks N02, N04, N05, S02 | Next |
| M3–M5 | Explanations at three levels, reports, plugin SDK, intel feeds | Later |

## Documentation map

| Need | Read |
|---|---|
| Why the product exists, scope | `docs/product/01-vision-and-scope.md`, `02-product-requirements.md` |
| How it is built | `docs/architecture/01-system-architecture.md`, `02-data-and-evidence-model.md` |
| Decisions and their reasons | `docs/architecture/adr/` (ADR-001 … ADR-010) |
| Safety rules for testing | `docs/security/01-assessment-methodology.md`, ADR-005, ADR-010 |
| Privacy of stored data | `docs/security/02-product-security-and-privacy.md`, ADR-009 |
| UI tokens, spacing roles, components | `docs/design/01-calm-technical-ui-guidelines.md` |
| Tests and coverage | `docs/engineering/02-testing-and-coverage.md` |
| Acceptance tests (AT-xx) | `docs/delivery/03-acceptance-and-test-plan.md` |
| Words used in the app | `docs/reference/glossary.md` |

## Use responsibly

Run active checks only on networks you are authorized to test, within a scope the owner approved. Calm enforces the scope you enter. It cannot verify that the permission you record is real.

## Contributing

Read [`CLAUDE.md`](CLAUDE.md) first. It holds the development rules (TDD, design principles, safety invariants, definition of done) for both people and coding agents.
