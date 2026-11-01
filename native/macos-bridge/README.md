> **Superseded for Wi-Fi identity (ADR-008, WP1):** a sidecar CLI cannot read SSID/BSSID because Location is granted per executable. Production reads Wi-Fi in the Calm main process via Rust `objc2`. This package is kept only as an experiment harness.

# macos-bridge

Swift package reading macOS Wi-Fi/interface metadata (CoreWLAN, SystemConfiguration) and emitting canonical JSON.

```sh
swift build
swift run calm-wifi-probe   # prints an InterfaceSnapshot (all "not_implemented" in skeleton)
swift test
```

WP1 spike: CoreWLAN fields available per macOS version, Location permission flow for SSID/BSSID, `scutil`/`route` fallbacks, sidecar vs FFI.
