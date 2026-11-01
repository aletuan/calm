//! Status, confidence and epistemic vocabularies.
//!
//! These enums are deliberately orthogonal: status ≠ severity ≠ confidence ≠
//! epistemic status. Never derive one from another.

use serde::{Deserialize, Serialize};

/// Outcome of a bounded check (data model §Status semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// Bounded test confirms expected control under specified conditions.
    Pass,
    /// Bounded test confirms undesirable condition.
    Fail,
    /// Noteworthy condition without conclusive control failure.
    Warning,
    /// Test attempted but evidence insufficient.
    Inconclusive,
    /// Not attempted or prerequisites missing.
    NotTested,
    /// Observation not assessed as risk.
    Informational,
}

impl FindingStatus {
    /// Only `Pass` may ever be reported as a passed control. Absence of a
    /// response or a missing prerequisite must never become `Pass`.
    pub fn counts_as_pass(self) -> bool {
        matches!(self, FindingStatus::Pass)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Reliability of the evidence — not intrinsic hazard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// How we know a node/edge/claim. Unified vocabulary (ADR-008):
/// `observed | validated | inferred | unverified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    /// Directly measured by this Mac (interface metadata, captured packets).
    Observed,
    /// Confirmed by an authorized, bounded test.
    Validated,
    /// Reasonable interpretation with provenance and confidence.
    Inferred,
    /// Unknown or unsupported; must never be rendered as fact.
    Unverified,
}

impl EpistemicStatus {
    /// UI edge treatment. Distinguishable without relying on hue (NFR-10).
    pub fn edge_style(self) -> EdgeStyle {
        match self {
            EpistemicStatus::Observed | EpistemicStatus::Validated => EdgeStyle::Solid,
            EpistemicStatus::Inferred => EdgeStyle::Dashed,
            EpistemicStatus::Unverified => EdgeStyle::Dotted,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeStyle {
    Solid,
    Dashed,
    Dotted,
}

/// Graph relation types (data model §Graph semantic rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationType {
    /// Wi-Fi association from interface metadata.
    AssociatedWith,
    /// Routing configuration; does not prove same physical AP.
    DefaultRouteVia,
    /// DNS resolver configured/used.
    ResolvesVia,
    /// Successful protocol-specific test; annotate L4 vs L7.
    ConnectivityConfirmed,
    /// Observed packet/flow; record capture origin and time.
    FlowObserved,
    /// Hypothesis; dashed edge, never physical connectivity.
    PossibleMembership,
    /// Asset/service linked to a candidate or confirmed vulnerability.
    AffectedBy,
}

/// Vulnerability evidence ladder. No upgrade without new supporting evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnEvidenceState {
    Candidate,
    LikelyAffected,
    VerifiedVulnerable,
    ExploitValidated,
}

/// Assessment test levels (security methodology).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TestLevel {
    /// Passive — allowed after local collection consent.
    L0,
    /// Safe, target-specific — separate authorization.
    L1,
    /// Active — per-check approval.
    L2,
    /// Exploit validation — separate signed engagement, never auto-run.
    L3,
}

impl TestLevel {
    /// Only L0 may run without an explicit scope grant (ADR-005).
    pub fn requires_scope_grant(self) -> bool {
        !matches!(self, TestLevel::L0)
    }
}

/// Where a record came from. Imported telemetry is never `ObservedByMac`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    ObservedByMac,
    AuthorizedTest,
    ImportedSensor,
    ImportedScan,
    IntelFeed,
    UserAssertion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epistemic_status_never_relies_on_one_style_for_all() {
        assert_eq!(EpistemicStatus::Observed.edge_style(), EdgeStyle::Solid);
        assert_eq!(EpistemicStatus::Inferred.edge_style(), EdgeStyle::Dashed);
        assert_eq!(EpistemicStatus::Unverified.edge_style(), EdgeStyle::Dotted);
    }

    #[test]
    fn only_pass_counts_as_pass() {
        for s in [
            FindingStatus::Fail,
            FindingStatus::Warning,
            FindingStatus::Inconclusive,
            FindingStatus::NotTested,
            FindingStatus::Informational,
        ] {
            assert!(!s.counts_as_pass());
        }
        assert!(FindingStatus::Pass.counts_as_pass());
    }

    #[test]
    fn relation_type_wire_format() {
        let v = serde_json::to_string(&RelationType::DefaultRouteVia).unwrap();
        assert_eq!(v, "\"DEFAULT_ROUTE_VIA\"");
    }

    #[test]
    fn only_l0_runs_without_grant() {
        assert!(!TestLevel::L0.requires_scope_grant());
        assert!(TestLevel::L1.requires_scope_grant());
        assert!(TestLevel::L3.requires_scope_grant());
    }
}
