# Product Security, Privacy & Threat Model

## Assets to protect
Authorization letters; customer topology/IP/MAC details; DNS and traffic metadata; raw PCAP; vulnerability findings; API credentials; plugin binaries; report exports; local database; OS capture privileges.

## Threat actors
Malicious plugin author, compromised OSS distribution, malicious Wi-Fi endpoint returning crafted packets/banners, untrusted local user, adversarial uploaded PCAP, compromised threat intel provider, prompt-injection in reports/tool logs, theft of laptop.

## Primary threats and mitigations
| Threat | Controls |
|---|---|
| Out-of-scope network scan | Immutable allowlist, signed job grants, bounded targets, UI approval, auditing; avoid relying solely on plugin promises |
| Plugin arbitrary execution | Reviewed signed plugins, pinned hashes, least privilege, no arbitrary shell, capability registry, isolate tool subprocess; platform restrictions subject to feasibility |
| Parser exploit via malformed PCAP/XML/JSON | Fuzz tests, memory-safe parser, strict schema, data size limits, sandbox if available |
| Data exfiltration via plugin/LLM | Default offline, per-provider network permissions, redaction, consent, minimum necessary egress, disable arbitrary plugins |
| Exposure of raw packet payloads | Raw capture opt-in, metadata default, encryption at rest, retention/quota, secure deletion limitations documented |
| False-positive vulnerability claim | Explicit confidence/evidence states, deterministic rule conclusions, human review for exploitation claims |
| Privilege escalation via capture | Dedicated privileged helper, narrow interface, no root desktop, OS signing/notarization review |
| Compromised update | Signed releases/plugins, trusted source, version lock, rollback path, SBOM |
| Prompt injection | Treat tool outputs as untrusted, strict grounding, model cannot directly execute active checks |
| Tenant/client crossover | Separate local session scopes, export access controls; multi-tenant isolation future audit |

## Privacy controls
Before capture: show what is collected, purpose, storage location, retention, raw payload toggle. Defaults: flow summaries only; redact personal identifiers in presentation as configured; keep secret material in Keychain; no silent cloud upload. Separate opt-in for AI remote calls; support local AI/offline knowledge cards.

## Compliance & legal
Guest consent and property owner permission are separate concerns; assess local applicable computer security, privacy and logging requirements before real deployments. Payment networks may impose PCI-related constraints; do not assert certification. Privacy regulations apply based on geography and processing, not app label.

## Secure build
Dependency/license inventory, SCA, code signing, reproducible build feasibility, secret scan, audit log integrity, release artifact provenance, macOS OS version support test, external dependency license review.

## Incident response
Logs contain plugin ID, version, grant, targets, output path/hash, stop time and escalation. Support revoke plugin, delete sensitive capture, export evidence subset, freeze assessment and rollback update.
