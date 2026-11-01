# Testing and coverage

Every crate and every piece of pure UI logic has unit tests. New behaviour is written test-first: the store (M1.5), the SPB timestamp fix and the session form were driven by failing tests.

## Run

```sh
pnpm test          # vitest (UI logic) + cargo test (all crates)
pnpm check         # typecheck + vitest + fmt + clippy + cargo test
pnpm coverage      # vitest --coverage + scripts/coverage.sh (cargo llvm-cov)
cargo test -p calm-store -- --ignored keychain   # real Keychain, Mac only
```

`scripts/coverage.sh` needs `cargo install cargo-llvm-cov` and `rustup component add llvm-tools-preview` once.

## What is covered (2026-10-31, M1.5)

| Area | Tests | Line coverage |
|---|---|---|
| `calm-flow-engine` (PCAP/PCAPNG reader, import, flows, parse) | 27 unit + 7 integration (golden AT-04, damaged files AT-16, fuzz-style truncation and bit flips) | 98 % |
| `calm-graph-engine` | 10 (AT-05, AT-06, dual-stack merge, imported graph) | 98 % |
| `calm-store` | 5 crypto + 22 integration (no plaintext on disk, wrong key, row swap, shredding, retention, schema, permissions) | 93–94 % |
| `calm-capture` | 5, including a real loopback capture where the user may capture | 88 % |
| `calm-net-profile` parsers, `calm-orchestrator` (AT-02, AT-03) | existing | 98–99 % |
| Desktop shell `records.rs` + storage state logic | 14 | 100 % / 47 % for `lib.rs` |
| UI logic `src/lib/*` (format, series, flow labels, topology model, source selection, session form, preview store, IPC fallbacks, i18n completeness) | 81 (vitest) | 94 % |
| **Rust total** | 106 | **88 %** |

## Known gaps

- Tauri command wrappers in `apps/desktop/src-tauri/src/lib.rs` (file picker, main-thread CoreLocation, live capture start/stop) need the app runtime or a Mac; their logic was moved into functions that are tested, the wrappers are checked by running the app.
- macOS-only code (CoreWLAN/CoreLocation in `calm-net-profile`, the Keychain provider) is compiled and linted for `aarch64-apple-darwin` but only runs on a Mac.
- React components are not unit-tested; they hold no decisions (those live in `src/lib`) and are checked with browser-preview screenshots. Component tests (jsdom + Testing Library) are a candidate for M2 when forms with scope rules arrive.
