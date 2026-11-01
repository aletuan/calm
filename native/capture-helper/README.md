# capture-helper

Minimal privileged helper for libpcap/BPF capture. Written in Rust (memory-safe parsing boundary).

Status: **stub** — exits without capturing.

> **M1.3 alpha decision:** capture runs in the Calm process (`crates/capture`) on a background thread, with BPF read access granted by the `calm_bpf` group (`scripts/bpf-access.sh`). Calm itself never runs as root (NFR-01 holds). The trade-off: the group grant lets any process of this user read traffic, and packet parsing shares the app process. The parser is memory-safe Rust and tested on every truncation length. Before a distributed release, this helper becomes an `SMAppService` daemon + XPC limited to callers signed as `com.aletuan.calm` (WP1 S2 variant B). Design questions for WP1 spike:
- `SMAppService` daemon vs. BPF device permissions (`/dev/bpf*` group, like Wireshark's ChmodBPF).
- XPC vs. Unix socket between app and helper; caller code-signing validation.
- Degraded mode when the user declines helper install (open question #2).
