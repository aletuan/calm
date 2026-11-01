# Open Extension Platform & Interoperability

## Design intent
An open **ports-and-adapters** architecture where OSS tools are independently versioned, optional and sandboxed as far as platform allows. Plugin architecture is our contract built **using** standards, not itself an external industry standard.

## Layers and contracts
1. **Native input formats**: Nmap XML, Nuclei JSONL, TShark structured JSON, PCAP/PCAPNG, Zeek JSON, Suricata EVE JSON, Greenbone GMP responses, ZAP API/Automation Framework.
2. **Adapter RPC**: JSON-RPC 2.0 over stdio for plugin subprocess; handshake for `plugin.info`, `capabilities`, `input_schema`, `output_schema` and permission tiers. Tool execution wrapper invokes known CLI/API; tools do not need to implement JSON-RPC themselves.
3. **Canonical domain**: Versioned JSON Schema for Asset, Flow, Finding, Evidence, Session (see data model).
4. **External API**: OpenAPI 3.x for optional local HTTP service; plugin runner may be internal; exports: SARIF, JSON, PCAPNG, GraphML.
5. **AI integrations**: Optional MCP **read-only** tools; active scan actions remain explicitly gated by core policy.

## External standards matrix
| Standard | Use | Caveat |
|---|---|---|
| JSON Schema / OpenAPI | validation & public API | not tool execution isolation |
| JSON-RPC 2.0 | local process RPC | own handshake/cancellation/version contract |
| SARIF 2.1.0 | findings interchange | static-analysis oriented, lossy for network topology |
| CVE/CWE/CPE/CVSS | vulnerability normalization | CPE/banner matching prone to error |
| CISA KEV / FIRST EPSS | observed exploitation/prioritization signals | EPSS forecast != certain exploit |
| STIX 2.1 / TAXII 2.1 | CTI objects and feeds | not an all-purpose topology protocol |
| CSAF 2.0 / VEX (e.g., OpenVEX) | advisories/product impact | not equivalent to vulnerability test result |
| CycloneDX / SPDX | SBOM import when available | guest vantage rarely has authoritative SBOM |
| PCAP/PCAPNG | packets | privacy, disk size, capture limits |
| Zeek logs / Suricata EVE | network events | import provenance always preserved |
| OTLP | application/plugin telemetry | not replacement for packet capture |
| GraphML | topology export | semantic extensions need custom attributes |
| MCP | LLM tool/resource access | not universal plugin runtime standard |

## Initial adapters
- P0: macOS network information, capture/PCAPNG, Nmap XML, vulnerability feed cache (NVD/KEV/EPSS), SARIF export.
- P1: Nuclei (restricted templates; review template source), Zeek JSON import, Suricata EVE import, DefectDojo adapter, OSV API, ZAP for expressly scoped web apps.
- P2: Greenbone GMP via separate server backend; STIX/TAXII; MCP; richer RF hardware.

## Plugin manifest (draft)
See [example manifest](../examples/plugin-manifest.yaml). Required: id, semantic version, supported contract versions, tool runtime/dependencies, platform, declared capabilities, inputs/outputs, network/file privileges, safety level, resource budgets, signature and publisher metadata.

## RPC message principles
Request envelope: `job_id`, `plugin_id`, `scope_id`, immutable allowed targets, approved checks, user authorization, rate/timeout, input payload schema version. Result envelope: status, normalized records, immutable evidence refs, errors, tool/parser versions, executed target set. No undocumented auto scope expansion.

## Plugin lifecycle
Discover → trust/signature review → dependency & architecture compatibility → permissions review → install → capability negotiation → controlled execution → parse/validate → retain evidence → uninstall/revoke.

## Platform safety details
- **JSON-RPC / subprocess is NOT sandboxing**. Use code signing, minimal OS permissions, controlled environment, resource limits, approved tool lists, and where enforceable system/network controls. Explicitly flag limitations on macOS egress enforcement for arbitrary third-party binaries.
- For initial release, restrict to reviewed signed adapters; arbitrary community binaries are disabled.
- Network restrictions in YAML alone do not contain a malicious plugin. Risky tools should run in separately controlled environment, not through unrestricted shell.
- Plugin output treated as untrusted input (including prompt injection in descriptions/logs).
- No self-updating templates without review/pinning; manage tool licenses, binaries, SBOM/provenance.

## Contract testing
Golden fixtures per format/version, schema validation, malformed record fuzz, parser version regressions, cancellation, timeouts, high-volume limits, out-of-scope refusals, malicious textual content, duplicate finding behavior, downgrade compatibility.

## Export guarantees
Preserve origin/tool/version, tool execution scope, evidence IDs, timestamps and caveats. A format that cannot represent a field gets an explicit companion JSON, never silently invent data.
