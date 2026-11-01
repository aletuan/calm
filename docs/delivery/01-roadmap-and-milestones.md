# Product Roadmap, Priorities & Milestones

The milestones below are **sequenced phases, not promised delivery dates**. Calibrate staffing, duration and scope after technical spikes.

## M0 Discovery & feasibility
Deliverable: validate macOS network APIs, capture permissions, arm64/intel viability, limitation demonstrations, legal ROE template, interaction prototypes. Exit: all P0 platform blockers resolved or architecture adapted; 3 representative Wi-Fi test environments available.

## M1 Passive Visibility Alpha
Deliverable: macOS shell, connected Wi-Fi profile, IP/DNS/route, local traffic capture, basic PCAP replay and topology with observed/inferred distinction. Exit: offline demo on test network; cannot misstate local-only capture as network-wide.

## M2 Network Assessment Beta
Deliverable: scope grants, rate-limited Nmap adapter, approved connectivity checks, reference isolation test, evidence links, severity/confidence/status model, emergency stop. Exit: out-of-scope test suite passes; no automatic high-impact actions.

## M3 Explain & Report MVP
Deliverable: 3-level knowledge cards, explainable findings, traffic drill-down, export Markdown/HTML/PDF and canonical JSON, baseline session compare by evidence. Exit: usability tests for general engineers and signed-off sample reports.

## M4 Open Extension Foundation
Deliverable: JSON-RPC manifest/SDK, pinned plugin registry, NVD/KEV/EPSS cache, SARIF/GraphML export, golden-fixture compatibility tests, signed distribution candidate. Exit: 2 independent adapters can be replaced without core change.

## M5 Advanced Optional Integrations
Deliverable: Nuclei vetted templates, Zeek/Suricata import, DefectDojo, OSV, remote scanner backend, AI evidence assistant, MCP read-only endpoint; later enhanced RF capture. Exit: each integration has permission/scope review, integration test and supported macOS matrix.

## Priority discipline
P0: local Wi-Fi profiling, capture, bounded topology, core checks, evidence model, conceptual explanations, basic standards/export.
P1: advanced imports, safer template scanning, comparison, optional AI, deeper flows.
P2: optional RF adapter, MSP multi-site, cloud sync, deep external scanning backend.

## Team roles (illustrative)
Product/UX, macOS/native/Rust engineer, network security SME, frontend visualization engineer, QA automation, optional AI engineer. For small team, combine roles but assign security sign-off independent of feature implementer.

## Release quality gates
- Architecture risk review and permission model test.
- Functional test on multiple AP vendors and isolation configurations.
- Privacy/data retention review and offline tests.
- Tool licenses + pinned versions + signed Mac app packaging.
- User study: correct comprehension of unknown vs vulnerable.
