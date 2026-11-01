//! Nmap adapter (ADR-011, ADR-012).
//!
//! - [`command`] turns a [`calm_orchestrator::PlanGrant`] into Nmap's argument list;
//! - [`runner`] starts Nmap in its own process group and stops the whole group.
//!
//! Parsing Nmap's XML into Calm's model comes in a later step.

pub mod command;
#[cfg(unix)]
pub mod runner;

pub use command::build_args;

#[cfg(all(test, unix))]
mod out_of_scope;
#[cfg(all(test, unix))]
mod test_support;
