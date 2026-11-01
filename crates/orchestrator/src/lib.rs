//! Orchestrator: sessions, jobs and the scope & safety controller (ADR-005).
//!
//! The scope engine is the one invariant present from day one: enforcement is
//! independent of AI or plugin hints, and anything not explicitly allowed is
//! denied. See [`scope`].

pub mod checks;
pub mod plan;
pub mod probe;
pub mod scope;

pub use plan::{authorize_plan, valid_interface, PlanDenied, PlanGrant, RunPlan};
pub use scope::{
    approve, authorize, binding_from_profile, check_address, in_subnet, same_network, Grant,
    ProbeRequest, ScopeDenied, ScopeDraft,
};
