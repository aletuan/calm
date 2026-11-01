# WP1 platform spike — findings

**Status:** S1 + S1b done; S2 variant A done (variant B pending); S3 done (manual quarantine check pending) | **Runbook:** `spikes/wp1/README.md`

## Known before running (external sources)
- macOS 14+: `CWInterface.ssid()` returns `nil` unless Location Services is on and the *calling app* is authorized (Apple DTS, developer forums thread 732431).
- macOS 26: a LaunchAgent with Location authorization was still reported to get a redacted SSID while BSSID/channel were available; DTS suggests authorizing in the container app and installing the agent via `SMAppService`, unverified (thread 816619).
- VMs generally do not virtualize Wi-Fi: S1 must run on hardware.
- Mac App Store distribution is likely incompatible with BPF capture/privileged helper (App Sandbox) → Developer ID + notarization assumed.

## Environment
macOS 26.6.2 (25G83), Apple M3 Pro, Xcode + Swift 6.3.3, rustc 1.94.0, SIP enabled. Two `Apple Development` certificates share one display name (signing must use SHA-1 hash). No `Developer ID Application` certificate yet. User is in group `access_bpf`, but `/dev/bpf*` are `root:wheel 600` (ChmodBPF not active).

## S1 — Wi-Fi identity & Location
Run on a real Mac, Guest-like WPA2-Personal 2.4 GHz network. Prompt answered **Allow** for both apps; both finished with `finish_reason=decided`.

| Variant | Auth | SSID | BSSID | Channel/RSSI/Security | Notes |
|---|---|---|---|---|---|
| terminal-cli | notDetermined | no | no | yes | Terminal is the responsible process |
| app-in-process (GUI app) | authorizedAlways | **yes** | **yes** | yes | asked When-In-Use, macOS reports Always |
| app-child-cli (spawned by authorized app) | **notDetermined** | **no** | **no** | yes | authorization does NOT pass to child |
| agent-in-process (LSUIElement) | authorizedAlways | **yes** | **yes** | yes | prompt still appears for Dock-less app |
| agent-child-cli | notDetermined | no | no | yes | same as app-child-cli |
| `ipconfig getsummary` | — | `<redacted>` | `<redacted>` | security only | |
| `networksetup -getairportnetwork` | — | — | — | — | wrongly reports "not associated" |
| `system_profiler SPAirPortDataType` | — | (masked in run) | no line | PHY/channel/signal/noise/security | |

**Findings**
1. Location authorization is per signed executable; it is not inherited by child processes. A sidecar CLI cannot read SSID/BSSID.
2. A Dock-less helper `.app` can obtain its own authorization (works, but adds a second identity in Location settings).
3. Without Location: channel, RSSI, noise, PHY and security type are still available via CoreWLAN — W01 degrades gracefully; only network identity is lost.
4. Built-in CLIs are redacted or wrong on macOS 26.6 — not a fallback.

**Decision (proposed):** read Wi-Fi metadata **in the Calm main process** (`com.aletuan.calm`) via Rust bindings to CoreLocation/CoreWLAN (`objc2-*` crates or Swift static lib via `swift-rs`). Fallback: embedded LSUIElement helper app. Sidecar CLI rejected for identity fields. Needs a small Tauri confirmation test.

## S1b — Tauri app, in-process (Rust → CoreLocation/CoreWLAN via `objc2`)
Bundle built and signed by the Tauri CLI (`tauri build --debug --bundles app`, `APPLE_SIGNING_IDENTITY` = Apple Development hash). No Swift and no Objective-C delegate: authorization status is polled on the main thread.

| Variant | Auth | SSID | BSSID | Finish |
|---|---|---|---|---|
| bundle, before auth | notDetermined | no | no | — |
| **bundle, after Allow** | **authorizedAlways** | **yes** | **yes** | decided |
| unbundled binary from terminal (= `tauri dev`) | notDetermined | no | no | timeout 90 s, no prompt shown |

**Findings**
1. A Tauri app reads SSID/BSSID in its own Rust process after one Location prompt. This confirms the in-process design.
2. The Tauri CLI merged `Info.plist` usage strings, applied the `location` entitlement and hardened runtime, and signed with Team `JZNARFKAH2`. No manual re-signing was needed.
3. **`tauri dev` / `pnpm dev` cannot exercise Wi-Fi identity:** the unbundled binary has no `Info.plist`, so no prompt appears and the status stays `notDetermined`. Wi-Fi features need a bundled debug build for development and testing.
4. Crates verified: `tauri 2.12.5`, `objc2 0.6.5`, `objc2-core-location 0.3.2`, `objc2-core-wlan 0.3.2`.

## S2 — Capture
Headers only (snaplen 96), 30 s per run, en0, WPA2 2.4 GHz at about -72 dBm.

| Run | Opened? | pps | Mbps (wire) | Drops | Notes |
|---|---|---|---|---|---|
| unpriv | no | — | — | — | `/dev/bpf0: Permission denied` (expected) |
| sudo | yes | 72 | 0.29 | 0 | baseline |
| sudo + load (re-run) | yes | 1409 | 13.72 | 0 | load verified: 50 MB downloaded, 13.3 Mbps avg |
| group (ChmodBPF-style, no root) | yes | 69 | 0.18 | 0 | group membership took effect in the same shell, no new Terminal needed |
| group + load (re-run) | yes | 1318 | 12.64 | 0 | load verified: 50 MB downloaded, 13.3 Mbps avg |

**Findings so far**
1. A ChmodBPF-style group grant is enough to capture without root at runtime.
2. Headers-only capture is enforced by snaplen on macOS (`max_caplen` = 96) — supports AT-15.
3. Zero drops (kernel and interface) both at idle and under a verified ~13 Mbps load. Captured wire bytes (51.4 MB / 47.4 MB) match the 50 MB downloaded. Root and group capture behave the same.
4. The load ceiling here was the Wi-Fi link (2.4 GHz, -72 dBm), not the capture path, so this does not stress-test NFR-11. A higher-rate test (5 GHz near the AP, or iperf) is still needed for large-PCAP benchmarks. Realistic Guest Wi-Fi rates are covered.
5. The first load attempt (a single 200 MB request) silently transferred nothing; the script now verifies load. Grant and revoke both worked cleanly, and `/dev/bpf*` is back to `root:wheel 600`.

**Security trade-off (A vs B):** the group grant lets *any* process run by a group member sniff every interface, for the whole session. That is acceptable for dev and alpha, but weak for a security product. `SMAppService` daemon + XPC limited to callers signed as `com.aletuan.calm` narrows this. Variant B has not been built yet.

**Decision:** _TBD after load re-run and variant B. Leaning: A for M1 alpha/dev, B for release._

## S3 — Signing & notarization
**Prerequisites (2026-10-31)**
| Item | State |
|---|---|
| Apple Developer Program | Individual, Team ID `JZNARFKAH2`, Account Holder, expires 2027-08-29 |
| Program License Agreement | **New version must be accepted before 2026-11-14** (blocks certificates and App Store Connect API, City Crew included) |
| Certificates | iOS Distribution; 2× Apple Development (both "Andy's MacBook Pro", created 2026-10-05 and 2026-10-07; same display name); **Developer ID Application created 2026-10-31** (Team `JZNARFKAH2`, SHA-1 `2CBBA4C4…F33F2`) |
| Notary API key | Team key `calm-notary`, Key ID `LNVU77LYWS`, access Developer; `.p8` downloaded once (keep it out of the repo) |
| Keychain profile `calm-notary` | stored and validated by `notarytool` (2026-10-31 14:07); `.p8` kept in `~/.private_keys/`, outside the repo |

Local signing with Apple Development is already proven by S1: the nested bundle was signed with hardened runtime, and the Location grant persists across rebuilds.

**Run (2026-10-31 14:14)**
| Check | Result |
|---|---|
| Developer ID signing, hardened runtime, secure timestamp | OK. The nested `probe-cli` is signed with its own identifier and the runtime flag |
| `notarytool submit --wait` | **Accepted** in 24 s (submission `9fc35a70-…`) |
| `stapler staple` / `validate` | OK. The ticket is embedded, so Gatekeeper can verify offline |
| `spctl -a -t exec` | **accepted**, `source=Notarized Developer ID`, `origin=Developer ID Application: Tuan Anh Le (JZNARFKAH2)` |
| Quarantined copy opened on another account/Mac | _pending (manual)_ |

**Findings**
1. The full pipeline works for a bundle with a nested, separately signed helper: inside-out signing and no `--deep` are enough. Notarization takes seconds, not minutes, at this size.
2. A Developer ID signature is a different code identity from Apple Development. TCC/Location grants made to the dev build will very likely not carry over to the release build (not tested). Dev and release builds should be treated as separate apps for permission testing.
3. Notarization is needed only for distribution. Local-only use can stay on Apple Development.

## ADR impact
- **ADR-008 updated:** Wi-Fi/Location run in the Calm main process (Rust + `objc2`). The Swift sidecar is rejected for identity fields.
- **Dev workflow:** add a bundled-debug run path (`tauri build --debug --bundles app` + `open`) for Wi-Fi work. `pnpm dev` stays for UI work.
- **Capture:** ChmodBPF-style group grant for M1 alpha; `SMAppService` daemon + XPC still to evaluate before release (S2 variant B).
- **Distribution:** Developer ID + notarization pipeline proven; required only when distributing.
- **Open questions answered:** #1 partly (macOS 26.6 on Apple Silicon verified); #2 (without helper/Location: capture unavailable, Wi-Fi identity unavailable, but channel/RSSI/security still readable).
