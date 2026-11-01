# Canonical Data Model & Evidence Semantics

## Why canonical
Nmap, Zeek, PCAP, Nuclei, KEV and AI use different representations. All adapter outputs map to a stable internal domain; raw source is retained when legal/safe. Do not treat this model as an external standard.

## Core entities
| Entity | Key fields |
|---|---|
| AssessmentSession | id, site, operator, permissions, ssid/bssid, vantage, start/end, version |
| Scope | approved targets/ports/protocols/check classes, approval reference, validity, rate budget |
| InterfaceSnapshot | interface, IPs, routes, resolver, SSID, BSSID, timestamp |
| Asset | stable id, observed identifiers, role hypothesis, first/last_seen, confidence |
| Service | asset_id, transport, port, banner, version hypothesis, evidence_refs |
| ConnectionFlow | src/dst, ports, transport, timestamps, packets, bytes, direction, capture source |
| TopologyEdge | source, target, relation_type, epistemic_status, confidence, evidence_ids |
| Finding | rule id, entity refs, status, severity, confidence, verified/unverified claims, remediation |
| VulnerabilityReference | CVE/CWE/CPE, CVSS, KEV flag, EPSS score/date, sources |
| Evidence | evidence id, type, source tool+version, record/file pointer, hash, capture time, scope |
| PluginExecution | plugin version, permissions, job scope, start/end, exit, raw output, provenance |
| Explanation | claim refs, audience level, factual basis, uncertainty, model/prompt version if LLM |

## Status semantics
- `pass`: bounded test confirms expected control under specified conditions.
- `fail`: bounded test confirms undesirable condition.
- `warning`: noteworthy condition without conclusive control failure.
- `inconclusive`: test attempted but evidence insufficient.
- `not_tested`: not attempted or prerequisites missing.
- `informational`: observation not assessed as risk.
These are orthogonal to severity; confidence levels High/Medium/Low report evidence reliability, not intrinsic hazard.

## Vulnerability evidence states
`candidate` (possible match) → `likely_affected` (product/version/prereqs credible) → `verified_vulnerable` (non-destructive authorized check confirms) → `exploit_validated` (separately approved controlled exploitation). No upgrade without new supporting evidence. Disputed/false-positive resolutions retained.

## Graph semantic rules
- `ASSOCIATED_WITH`: Wi-Fi association from interface metadata.
- `DEFAULT_ROUTE_VIA`: routing configuration; does not prove same physical AP.
- `CONNECTIVITY_CONFIRMED`: successful protocol-specific test; annotate L4 vs L7.
- `FLOW_OBSERVED`: observed packet/flow; record capture origin and time.
- `POSSIBLE_MEMBERSHIP`: hypothesis; use dashed edge, not physical connectivity.
- `AFFECTED_BY`: links asset/service to confirmed or candidate vulnerability; display evidence level.
- No automatic physical topology or VLAN assignment from IP similarity alone.

## Stable identity & dedup
MAC randomization, DHCP churn, NAT, shared IPs, roaming, multi-AP SSIDs and proxying can cause false merges. Maintain `observed_identifiers[]` with timestamp/source; default to separate nodes until corroborated. Show merge confidence and undo history.

## Lineage & integrity
Every normalized object has `source_record_id`, `parser_version`, `session_id`, `observed_at`, `ingested_at`, `scope_id`, evidence artifact path/hash. Hash raw artifacts (SHA-256); capture contextual metadata; use monotonic time for local sequence plus wall-clock for reporting. Hash != trusted chain of custody without signing/access controls.

## Import/export strategy
- External formats preserved; canonical JSON + versioned JSON Schema exported.
- SARIF maps applicable findings, but cannot losslessly express all graph/flow semantics; attach structured property bag or companion JSON.
- GraphML is graph exchange, not a standardized vulnerability semantics format.
- PCAPNG for packet artifact; Zeek/Suricata schema-aware import; source provenance `imported_sensor` not `observed_by_mac`.

## Data lifecycle
Capture and logs → parse/normalize → evidence store → correlate → explain → report. Deleted sessions remove stored artifacts and clear derived cache per retention rules; signed reports may remain separate only when user explicitly exports them.
