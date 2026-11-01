# Product Requirements Document (PRD)

## Baseline and priority
- Target: macOS arm64 first, Intel compatibility assessed; Linux optional future.
- Assessment modes: passive observation **default**; scoped safe validation gated; deeper validation by separate authorization, ideally lab.
- Requirements IDs stable for backlog/test traceability.

## Functional requirements
| ID | Pri | Requirement | Acceptance summary |
|---|---|---|---|
| FR-001 | P0 | Detect connected Wi-Fi SSID/BSSID/interface, security capability, IP/routing/DNS, IPv4/IPv6 | Clearly distinguish advertised and negotiated properties |
| FR-002 | P0 | Capture local interface packets and aggregate flows by time/protocol/endpoint | Correctly scoped 'observed from this Mac' label |
| FR-003 | P0 | Import/export PCAPNG/PCAP and replay flow timeline | Replay without external network access |
| FR-004 | P0 | Build interactive logical topology from facts/inferences | Each node/edge exposes evidence + confidence |
| FR-005 | P0 | Show traffic time-series, protocol mix, top talkers, flow drill-down | Visible sync between selected node and flows |
| FR-006 | P0 | Explicit assessment authorization and target allowlist | Refuse out-of-scope execution |
| FR-007 | P0 | Authorized host/service discovery on approved targets only | Rate limits, cancellation, audit log |
| FR-008 | P0 | Check reachability of designated gateway/admin/test targets | Transport reachability not confused with login success |
| FR-009 | P0 | Isolation testing with designated cooperative endpoint | Without reference endpoint -> Inconclusive |
| FR-010 | P0 | Status/confidence/severity and evidence for findings | Supports Pass/Fail/Warning/Inconclusive/Not Tested/Informational |
| FR-011 | P0 | Contextual network/security explanations (basic/technical/deep) | Text tied to claims and evidence |
| FR-012 | P0 | Local session store and HTML/Markdown/PDF export | Reports include limitations and method |
| FR-013 | P0 | Plugin manifest + schema-validated adapter subprocess | Versioned contract + rejection of unsupported capabilities |
| FR-014 | P0 | Nmap XML and structured scan import | Source and tool version retained |
| FR-015 | P0 | Vulnerability intelligence lookup & cache (CVE/KEV/EPSS) | Candidate match never auto-promoted to verified |
| FR-016 | P0 | SARIF 2.1.0 export for compatible findings | No assumption all network data fits SARIF |
| FR-017 | P1 | Nuclei restricted template adapter | Template review & policy enforcement |
| FR-018 | P1 | Zeek JSON / Suricata EVE import | Imported telemetry labeled as external provenance |
| FR-019 | P1 | AI Q&A using evidence context and glossary | Clearly separate fact, inference and unknown |
| FR-020 | P1 | Session comparison and remediation recheck | Stable finding identities and diff |
| FR-021 | P1 | DefectDojo and standards adapters | Export/import schema compatibility tests |
| FR-022 | P2 | Optional RF monitor mode and second adapter | Hardware/OS capability detection; no promise macOS generic support |
| FR-023 | P2 | Greenbone/OpenVAS remote connector | Optional server in permitted topology, not bundled as native scanner |
| FR-024 | P2 | MCP read-only server for assistant | Active operations require separate explicit policy |
| FR-025 | P2 | Multi-site dashboard and cloud sync | Opt-in, tenant isolation, data minimization |

## Non-functional requirements
| ID | Requirement | Acceptance approach |
|---|---|---|
| NFR-01 | macOS native-feeling UI, no privileged UI process | Privilege separation test |
| NFR-02 | Local first, offline baseline scan/report | Air-gapped functional run |
| NFR-03 | Safe by default; no active scan on app launch | End-to-end outbound traffic test |
| NFR-04 | Crash/restart preserves session and logs | Forced-process termination test |
| NFR-05 | Target scope cannot be bypassed by adapter inputs | Denylist/allowlist negative tests |
| NFR-06 | Evidence integrity, timestamps, raw source linkage | Tamper detection test |
| NFR-07 | Encryption at rest for secrets and sensitive captures | Threat model and security review |
| NFR-08 | Privacy consent/retention controls | Retention deletion test |
| NFR-09 | Import/export formats must be versioned | Compatibility contract test suite |
| NFR-10 | UI does not infer certainty from aesthetics | UX audit of inferred/unknown edges |
| NFR-11 | Reasonable responsiveness under large PCAP | Benchmark with agreed dataset sizes (TBD) |
| NFR-12 | Accessibility, keyboard support, contrast | Accessibility QA |

## Scope boundaries
P0 includes topology **of observed/reachable assets**, local traffic only, nonintrusive service checking and deterministic explanations. P1/P2 items shall not block field MVP.

## Risks to user interpretation
- `No response` ≠ `No device`.
- `Port reachable` ≠ `Authenticated / compromised`.
- `Possible CVE` ≠ `Vulnerable`.
- `Guest isolation not verified` ≠ `Isolation working`.
- AP ≠ gateway ≠ router unless corroborated.

## Open decisions
See [risk register](../delivery/02-risks-and-open-questions.md) and [ADR index](../architecture/adr/README.md).
