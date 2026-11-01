# ADR-008: Scaffold conventions and vocabulary reconciliation

**Status:** Accepted baseline  
**Date:** 2026-10-31

## Context
Starting the code skeleton exposed naming decisions that are expensive to change after the first signed build, and a few vocabulary mismatches between documents.

## Decision
**Identity**
- Codename / product name in code: **Calm**. Docs title "WiFi Security Auditor" remains descriptive.
- Bundle identifier: `com.aletuan.calm` (consistent with `com.aletuan.citycrew`). Helper label: `com.aletuan.calm.capture-helper`. Extension IDs: `com.aletuan.calm.ext.<name>`.
- Manifest `apiVersion` / schema `$id` namespace: `calm.aletuan.com` (stable identifier; need not resolve).
- Minimum macOS 14 (Sonoma), Apple Silicon first; Intel deferred (open question #1).

**Vocabulary (canonical, supersedes conflicting wording in other docs)**
- Epistemic status: `observed | validated | inferred | unverified`. Edge style: observed/validated = solid, inferred = dashed, unverified = dotted. ("unknown" in earlier text = `unverified`.)
- Routing edge: `DEFAULT_ROUTE_VIA` (replaces `ROUTES_VIA`).
- Finding status: six values — `pass | fail | warning | inconclusive | not_tested | informational`.
- Check IDs follow the feature spec: `S01` web admin interface reachability, `S02` safe TLS/configuration checks.

**Repository**
- pnpm workspace + Cargo workspace in one repo; docs under `docs/`.
- Capture helper written in Rust.
- **Wi-Fi/Location (revised after WP1 S1/S1b, 2026-10-31):** read in the **Calm main process** from Rust via `objc2-core-location` / `objc2-core-wlan`. macOS grants Location per signed executable, and child processes do not inherit it, so a sidecar CLI cannot read SSID/BSSID. The Swift sidecar is rejected for identity fields; `native/macos-bridge` is kept only as an experiment harness. Fallback if needed: an embedded LSUIElement helper app.
- Without Location, Calm still reads channel/RSSI/noise/PHY/security, and the UI marks SSID/BSSID as `unverified: location permission`, never guessed.
- Wi-Fi features are developed against a **bundled debug build**; `tauri dev` runs an unbundled binary that never receives the Location prompt.
- UI i18n: English + Vietnamese from day one; English keys are the source.

## Reasons
Bundle ID is bound to TCC permissions (Location, Local Network), helper code-signing requirements, Keychain items and the Application Support path; changing it after release forces users to re-grant everything and loses encrypted data.

## Consequences & trade-offs
The affected docs (feature specs, ADR-003, UI guidelines, methodology, PRD FR-010) were updated to match; this ADR wins on any remaining conflict.

## Validation / revisit trigger
Revisit identity before first notarized build. Bridge transport settled by WP1 (see `docs/spikes/WP1-findings.md`).
