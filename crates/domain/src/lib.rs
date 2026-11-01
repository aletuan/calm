//! Canonical domain model for Calm.
//!
//! Source of truth: `docs/architecture/02-data-and-evidence-model.md` and
//! ADR-008 (scaffold conventions). JSON Schemas in `/schemas` mirror these
//! types; keep both in sync (a test deserialises the documented examples).
//!
//! Skeleton stage: types and invariants only, no business logic.

pub mod entities;
pub mod profile;
pub mod scope;
pub mod semantics;

pub use entities::*;
pub use profile::*;
pub use scope::*;
pub use semantics::*;

/// Schema family version for canonical JSON exports.
pub const CANONICAL_SCHEMA_VERSION: &str = "calm-v1alpha1";
