//! Scope grant (FR-006, ADR-005): what the user is authorized to test, from
//! where, until when and how fast. Approved once, never edited; a change means
//! revoking it and approving a new one.

use serde::{Deserialize, Serialize};

use crate::entities::{ScopeId, SessionId};
use crate::semantics::TestLevel;

/// What the owner says a target is. Decides which checks may use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetRole {
    Gateway,
    /// Management / web admin interface (S01, N02).
    AdminInterface,
    /// A *test* point-of-sale endpoint — never a production till (N03).
    PosTest,
    /// A second device the user controls, listening on the given ports (N01).
    CooperativeReceiver,
    Other,
}

/// One allowlisted target: a literal IP address and the ports allowed on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeTarget {
    /// Canonical text form of the IP address (no hostnames, no ranges).
    pub address: String,
    pub ports: Vec<u16>,
    pub role: TargetRole,
    #[serde(default)]
    pub label: String,
}

/// The network the grant was given for. Tests refuse to run elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkBinding {
    pub gateway: String,
    /// IPv4 network of this Mac at grant time, e.g. "192.168.68.0/22".
    pub subnet: Option<String>,
    /// Only when macOS let us read it (Location permission).
    pub ssid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateBudget {
    pub max_probes_per_second: u32,
    pub timeout_ms: u32,
    pub max_parallel_targets: u32,
}

/// Where this Mac stands while testing, as the user states it. Findings
/// speak about "this network", so a title like "reachable from guests" is
/// only used when the Mac really is on the guest network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPosition {
    /// The guest / visitor Wi-Fi the assessment is about.
    Guest,
    /// The owner's main or staff network.
    Main,
    /// The user did not say (and scopes stored before this field).
    #[default]
    Unknown,
}

/// An approved, immutable authorization grant. Enforcement: `calm-orchestrator`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    pub id: ScopeId,
    pub session_id: SessionId,
    pub authorization_reference: String,
    /// Who runs the tests.
    pub operator: String,
    /// Who gave permission (owner or their representative).
    pub granted_by: String,
    pub targets: Vec<ScopeTarget>,
    pub max_level: TestLevel,
    pub budget: RateBudget,
    pub network: NetworkBinding,
    /// Where the Mac stands; older stored scopes read as `Unknown`.
    #[serde(default)]
    pub vantage: NetworkPosition,
    pub approved_at_ms: i64,
    pub expires_at_ms: i64,
}
