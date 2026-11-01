# Risk Register, Constraints & Open Questions

| ID | Risk / blocker | Likelihood | Impact | Mitigation | Owner (proposed) |
|---|---|---|---|---|---|
| R01 | Managed-mode Mac cannot capture other guest clients' unicast flows | Certain baseline | High for promises | Label local vantage, import sensor data only as external; no full-traffic claim | Product + Security |
| R02 | Can't reconstruct physical topology/VLANs from guest | High | High | Evidence/inference/unknown graph model, no fabricated physical links | Architecture |
| R03 | macOS Wi-Fi APIs / private permissions vary | High | Medium | Early CoreWLAN/NetworkManager-equivalent spike, documented support matrix | Native |
| R04 | libpcap/BPF permissions, capture helper distribution | High | High | Signed minimal helper, privilege separation, field testing | Native/Security |
| R05 | Tool active checks impact POS/CCTV/business uptime | Medium | Critical | ROE, allowlist, low probe budget, mock POS targets, emergency stop | Security |
| R06 | Can't truly enforce network scope for arbitrary executable plugin | High | Critical | Reviewed signed adapters, no arbitrary community binaries, OS/network containment study | Security |
| R07 | Version fingerprint/CVE false positives | High | High | Candidate vs verified state, evidence, backport caveats and review | Security |
| R08 | Big PCAP/graph performance and storage | Medium | High | Flow aggregation, backpressure, quotas, efficient time index | Core |
| R09 | Sensitive payload/PII in capture/AI | High | High | Metadata default, raw opt-in, encryption, redaction, local LLM option | Privacy |
| R10 | Plugin OSS licenses and binary distribution | Medium | Medium | SPDX/SBOM, license review, optional external tool install | Legal/Eng |
| R11 | Extension formats are not lossless | High | Medium | Canonical model + raw evidence + companion JSON, contract tests | Integration |
| R12 | AI hallucinates causal/exploit findings | Medium | High | Deterministic rule decisions, strict grounding, unverified claim labels | AI/Security |
| R13 | Not enough reference endpoints to prove isolation | High | Medium | Inconclusive + optional cooperative probe kit | Product |
| R14 | Legal permission/owner authority unclear | Medium | Critical | Written authorization, scope expiry, refusal path | Delivery |
| R15 | Wi-Fi client MAC randomization, DHCP changes | High | Medium | temporal identity, no automatic merge without evidence | Data |
| R16 | Internet intel feeds unavailable/stale | Medium | Medium | timestamped local cache, stale indicator, offline mode | Integration |
| R17 | macOS notary/signing/ARM/Intel packaging friction | Medium | Medium | dedicated distribution spike, support matrix | Release |

## Open questions requiring decisions
1. Minimum macOS version and hardware support matrix? Intel at launch?
2. Should non-privileged capture be fallback if helper install declined? Which functions degrade?
3. What exact network scan categories are permitted for first commercial deployment?
4. How is authorization proven, signed and expired? Who approves L2/L3?
5. What are supported network sizes, capture throughput and PCAP limits?
6. Which local report languages and redaction defaults are required?
7. Which plugin distribution strategy: bundled signed only, private registry, reviewed marketplace?
8. Does an optional cooperative second client/test fixture belong to the product kit?
9. Does a remote AI provider receive any identifiers or traffic data, or is it strictly local?
10. Which licenses permit packaging and commercial distribution of chosen OSS tools?
11. Can future remote sensor provenance be visually separated from local-mac observed data?
12. What is acceptable latency/cost of CVE/EPSS feed refreshing and enrichment?

## Assumptions to verify with prototypes
A. `iw`/Linux-specific commands from earlier design do **not** apply natively to macOS; use Swift/CoreWLAN and OS utilities.
B. RF monitor mode may disconnect association and is hardware/version dependent, so **not P0**.
C. Arbitrary signed subprocesses are not truly sandboxed solely by signing or JSON-RPC.
D. SARIF captures findings, but not full traffic/topology without extensions.
