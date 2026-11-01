# Engineering Implementation Plan

## Suggested technology stack (proposal, validate with spikes)
- **Desktop/UI:** Tauri 2 + React + TypeScript; Cytoscape.js graph; ECharts time series/heatmap; lightweight state management.
- **Core:** Rust orchestrator, domain model, event bus, scope engine, parser adapters; IPC to Tauri UI.
- **macOS bridge:** Swift/CoreWLAN or native bindings for Wi-Fi details; OS `networksetup`, `scutil`, `route`, `ifconfig` fallback with tested output parsers; inspect macOS version differences.
- **Packet capture:** libpcap/BPF via narrowly privileged helper; TShark optional decoder (license/package review); PCAPNG artifact store.
- **Discovery:** Nmap XML adapter, no manual parsing of prose output.
- **Storage:** SQLite (schema migration), local blob/artifacts with SHA-256; encrypted sensitive artifacts.
- **Plugin SDK:** JSON-RPC 2.0 over stdio + JSON Schema; optional local OpenAPI service; manifest/signed adapter registry.
- **Report:** Markdown/HTML baseline; PDF export.

## Suggested repository
```text
wifi-security-auditor/
  apps/desktop/              # Tauri + React views
  crates/domain/             # canonical entities, statuses
  crates/orchestrator/       # sessions, jobs, scope controller
  crates/graph-engine/       # evidence-backed graph
  crates/flow-engine/        # telemetry and replay
  crates/extension-sdk/      # schemas, RPC, capability handshake
  crates/reporting/          # reports and export
  native/macos-bridge/       # Swift CoreWLAN + OS integration
  native/capture-helper/     # minimal privilege boundary
  extensions/nmap-adapter/
  extensions/intel-adapters/
  rules/                     # verified, versioned checks
  knowledge/                 # glossary and explanation cards
  schemas/                   # json schema definitions
  fixtures/                  # PCAPNG/XML/JSON and golden findings
  docs/                      # this documentation suite
  tests/e2e/
```

## Work packages
**WP1 Platform spike:** validate macOS versions/ARM+Intel, OS Wi-Fi metadata, libpcap permissions, signed helper, Tauri packaging, peak parsing throughput. Record findings before committing architecture.

**WP2 Canonical domain:** session/scope/evidence/asset/flow/finding/graph schemas with strict unknown semantics, SQLite migrations, fixtures.

**WP3 Passive collector:** interface snapshots, local capture, flow aggregation, timestamp alignment and PCAPNG replay.

**WP4 Visualizations:** Cytoscape views, click-to-filter, uncertainty styling, time sync, graph layout performance.

**WP5 Authorized checks:** safe target runner, approved Nmap XML adapter, cooperative reachability/isolation test, finding/evidence engine.

**WP6 Explainability:** curated network glossary, deterministic templates, evidence lookup and uncertainty explanations.

**WP7 Extension platform:** signed registry, schema-contract tests, intel feeds, SARIF/GraphML export, versioned adapters.

**WP8 Hardening/reporting:** threat-model review, fuzzing, privacy controls, field reports, onboarding, compatibility.

## API boundaries (conceptual)
- `Assessment.startPassive(sessionId)`
- `Assessment.authorizeAndRun(scopeGrant, checks)`
- `Capture.start(interfaceId, policy)` / `stop(captureId)`
- `Graph.snapshot(sessionId, timestamp, filter)`
- `Traffic.listFlows(sessionId, timeRange, filter)`
- `Findings.list(sessionId, status, confidence)`
- `Explain.describe(subjectId, level)`
- `Extension.capabilities(pluginId)` / `Extension.execute(jobGrant)`
- `Export.create(sessionId, format, redactionProfile)`
Names are internal design examples, **not committed public API**.

## Engineering practices
ADR review, schema-first development, contract fixtures, unit + integration + E2E tests, property testing/fuzzing for untrusted parsers, signed test binaries, reproducible minimal example environment and security review on each active adapter.

## Performance choices
Separate capture/parsing UI process to avoid frame drops; bounded channels/backpressure; aggregate flows instead of rendering every packet node; graph clustering at scale; paginate finding tables. Benchmark goals TBD after representative PCAP files and test Mac models.
