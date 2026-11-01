//! Calm capture helper — privilege boundary (ADR-005, R04).
//!
//! Target design (WP1 spike decides details):
//! - Installed only after explicit consent via `SMAppService` as a launchd
//!   daemon labelled `com.aletuan.calm.capture-helper`.
//! - Accepts connections only from a caller whose code-signing requirement
//!   matches bundle id `com.aletuan.calm` + Team ID.
//! - Exposes a tiny command set: list interfaces, start/stop filtered capture,
//!   stream metadata (payload off by default, AT-15).
//!
//! Skeleton: refuses to do anything.

fn main() {
    eprintln!("calm-capture-helper: not implemented (skeleton). No capture performed.");
    std::process::exit(64);
}
