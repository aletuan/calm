# ADR-009: Session storage encryption (M1.5)

**Status:** Accepted for alpha
**Date:** 2026-10-31
**Refines:** ADR-007 (local SQLite)

## Context
Saved sessions hold customer topology: SSIDs, BSSIDs, IP and MAC addresses, DNS servers, flows. NFR-07 asks for encryption at rest; the threat model lists laptop theft and an untrusted local user. Deleting sensitive captures must be real (NFR-08), but SQLite and APFS snapshots / Time Machine keep old bytes around.

## Decision
- **One SQLite file** in the app's data folder (`~/Library/Application Support/com.aletuan.calm/calm.sqlite3`), folder `0700`, file `0600`.
- **Envelope encryption in the application** (AES-256-GCM, RustCrypto `aes-gcm`), not SQLCipher.
  - Master key: 256 random bits, a generic password in the login Keychain (`com.aletuan.calm.storage` / `master-key-v1`). Never in the file or in logs.
  - Each session has its own data key, stored only *wrapped* by the master key.
  - Every sealed value is bound to its row by associated data (`calm/v1/<field>/<session>/<snapshot>/<kind>`): a blob moved to another row or session does not decrypt.
  - A canary sealed with the master key detects a wrong or replaced key; Calm then refuses to open (and can move the file aside, never delete it).
- **In clear:** ids (random 128-bit), timestamps, sizes, snapshot kind, retention days, audit actions. **Sealed:** session name, site, operator, authorization reference, notes, snapshot labels and payloads (profiles, flows, bindings, graphs, imported file name and SHA-256).
- **Deletion = crypto-shredding:** deleting a session deletes its wrapped key, so copies in backups are unreadable. `PRAGMA secure_delete = ON` also zeroes freed pages.
- **Retention:** per session (7 / 30 / 90 days since last change, or keep); expired sessions are deleted when the store opens. The audit trail records `session_expired`.
- **Never stored:** packet payloads (AT-15) and imported capture files themselves.

## Reasons
- Pure Rust, no OpenSSL/SQLCipher build on two platforms; every property is unit-tested on Linux CI and macOS (tamper, row swap, wrong key, no plaintext on disk, freed pages, retention).
- Per-session keys make deletion meaningful despite backups, which whole-database encryption alone does not.

## Consequences & trade-offs
- Metadata leaks: someone with the file sees how many sessions and snapshots exist, when, and how big. No network data.
- No SQL queries over encrypted content; fine for M1 (small number of snapshots, read whole).
- Losing the Keychain item loses the data (by design). Keychain prompts can appear for unsigned dev builds whose code identity changes.

## Alternatives considered
- SQLCipher (whole-file encryption): hides metadata but needs a crypto backend build per platform and does not give per-session shredding. Revisit if metadata exposure becomes a requirement.
- macOS Data Protection Keychain: needs keychain-access-groups entitlement and a provisioning profile; revisit with the signed release.

## Validation
`crates/store/tests/store.rs` (22 tests) and `crates/store/src/crypto.rs`. Opt-in Keychain test on a Mac: `cargo test -p calm-store -- --ignored keychain`.
