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

/// One kind of traffic the owner allows (ADR-011). Off unless listed in the
/// scope. Each has a fixed level; what it sends beyond a TCP connect is part
/// of what the owner approves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// One TCP connect per port, closed at once (ADR-010).
    TcpConnect,
    /// ARP or ping inside the scope's ranges.
    HostDiscovery,
    /// PTR lookups, only through the network's own private resolver.
    ReverseDns,
    /// Half-open TCP (`-sS`); raw packets through BPF.
    SynScan,
    /// Probe strings into open ports (`-sV`).
    ServiceDetection,
    /// Extra TCP, ICMP and one UDP probe to a closed port (`-O`).
    OsDetection,
    /// Allowlisted NSE scripts, named one by one in the scope.
    Nse,
}

impl Capability {
    pub const ALL: [Capability; 7] = [
        Capability::TcpConnect,
        Capability::HostDiscovery,
        Capability::ReverseDns,
        Capability::SynScan,
        Capability::ServiceDetection,
        Capability::OsDetection,
        Capability::Nse,
    ];

    pub fn level(self) -> TestLevel {
        match self {
            Capability::TcpConnect | Capability::HostDiscovery | Capability::ReverseDns => {
                TestLevel::L1
            }
            Capability::SynScan
            | Capability::ServiceDetection
            | Capability::OsDetection
            | Capability::Nse => TestLevel::L2,
        }
    }

    /// Needs raw packets (BPF write access through `calm_bpf`, spike nmap-bpf).
    pub fn needs_raw_packets(self) -> bool {
        matches!(
            self,
            Capability::HostDiscovery | Capability::SynScan | Capability::OsDetection
        )
    }
}

/// Capabilities of a scope stored before ADR-011: TCP connect only.
pub fn default_capabilities() -> Vec<Capability> {
    vec![Capability::TcpConnect]
}

/// A private IPv4 block the owner allows, with the ports allowed on every
/// host in it. Hosts listed in the scope's exclusions are never touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRange {
    /// Canonical CIDR text, e.g. "192.168.10.0/24" (network address, prefix ≥ 24).
    pub cidr: String,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub label: String,
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
    /// What kinds of traffic are allowed. Older scopes: TCP connect only.
    #[serde(default = "default_capabilities")]
    pub capabilities: Vec<Capability>,
    /// Private blocks allowed on top of the literal targets (ADR-011).
    #[serde(default)]
    pub ranges: Vec<ScopeRange>,
    /// Addresses never touched, even inside a range. Ranges need these, or
    /// `nothing_to_exclude`.
    #[serde(default)]
    pub exclusions: Vec<String>,
    /// The user confirmed that no device in the ranges needs avoiding.
    /// Recorded instead of a made-up exclusion; only true with ranges.
    #[serde(default)]
    pub nothing_to_exclude: bool,
    /// NSE scripts the owner allowed by name (needs `Capability::Nse`).
    #[serde(default)]
    pub nse_scripts: Vec<String>,
}

impl Scope {
    pub fn allows(&self, c: Capability) -> bool {
        self.capabilities.contains(&c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_capability_has_the_level_adr_011_gives_it() {
        use Capability::*;
        for c in Capability::ALL {
            let expected = match c {
                TcpConnect | HostDiscovery | ReverseDns => TestLevel::L1,
                SynScan | ServiceDetection | OsDetection | Nse => TestLevel::L2,
            };
            assert_eq!(c.level(), expected, "{c:?}");
        }
        assert!(
            SynScan.needs_raw_packets()
                && OsDetection.needs_raw_packets()
                && HostDiscovery.needs_raw_packets()
        );
        assert!(!TcpConnect.needs_raw_packets() && !ServiceDetection.needs_raw_packets());
    }

    #[test]
    fn a_scope_stored_before_capabilities_reads_as_tcp_connect_only() {
        let old = r#"{
          "id":"s1","session_id":"x","authorization_reference":"R","operator":"A","granted_by":"O",
          "targets":[{"address":"192.168.1.1","ports":[443],"role":"admin_interface"}],
          "max_level":"L1",
          "budget":{"max_probes_per_second":5,"timeout_ms":3000,"max_parallel_targets":1},
          "network":{"gateway":"192.168.1.1","subnet":null,"ssid":null},
          "approved_at_ms":1,"expires_at_ms":2
        }"#;
        let s: Scope = serde_json::from_str(old).expect("older scope JSON must still read");
        assert_eq!(s.capabilities, vec![Capability::TcpConnect]);
        assert!(s.ranges.is_empty() && s.exclusions.is_empty() && s.nse_scripts.is_empty());
        assert!(!s.nothing_to_exclude);
        assert!(s.allows(Capability::TcpConnect) && !s.allows(Capability::SynScan));
    }
}
