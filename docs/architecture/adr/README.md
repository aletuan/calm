# Architecture Decision Records

| ADR | Decision | State |
|---|---|---|
| [001](ADR-001-vantage-and-scope.md) | One authorized Guest Wi-Fi vantage | Accepted baseline |
| [002](ADR-002-macos-stack.md) | macOS-first Tauri/React/Rust, Swift bridge | Proposed |
| [003](ADR-003-evidence-graph.md) | Evidence-based graph, no invented topology | Accepted principle |
| [004](ADR-004-open-extensions.md) | Standards-first adapters, canonical model | Proposed |
| [005](ADR-005-safety-and-privileges.md) | No root UI, active checks gated | Accepted principle |
| [006](ADR-006-explainability.md) | Rules decide findings; AI explains | Accepted principle |
| [007](ADR-007-storage.md) | Local SQLite + separate capture artifacts | Proposed |
| [008](ADR-008-scaffold-conventions.md) | Codename Calm, bundle ID `com.aletuan.calm`, unified vocabulary | Accepted baseline |
| [009](ADR-009-storage-encryption.md) | Session storage: per-session AES-256-GCM, Keychain master key, crypto-shredding | Accepted for alpha |
| [010](ADR-010-scope-grants-and-probes.md) | Scope grants (literal private IPs, network-bound, immutable), per-probe authorization, TCP-connect L1 checks S01/N03/N01 | Accepted for beta |
| [011](ADR-011-capability-scopes-and-nmap.md) | Capability scopes (ranges, exclusions, L1/L2 capabilities); Nmap runs authorized per plan, raw packets via calm_bpf, no root | Proposed |
| [012](ADR-012-nmap-bundling-and-license.md) | Bundle Nmap in Calm.app; release Calm under the NPSL 0.95 | Proposed |

`Accepted baseline/principle` reflects decisions in this conversation; `Proposed` needs engineering spike or review before implementation.
