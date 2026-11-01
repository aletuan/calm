//! Core entities (data model §Core entities). Skeleton: shapes only.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::semantics::*;

pub type SessionId = String;
pub type ScopeId = String;
pub type EvidenceId = String;
pub type AssetId = String;
pub type FindingId = String;

/// Lineage carried by every normalized object (data model §Lineage & integrity).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lineage {
    pub session_id: SessionId,
    pub source_record_id: Option<String>,
    pub parser_version: Option<String>,
    pub scope_id: Option<ScopeId>,
    pub provenance: Provenance,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub ingested_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessmentSession {
    pub id: SessionId,
    pub name: String,
    pub site: Option<String>,
    pub operator: String,
    /// Fixed for MVP: one Mac on an authorized Guest Wi-Fi (ADR-001).
    pub vantage: Vantage,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub ended_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vantage {
    /// One Mac on the network under test. Which network that is (guest or
    /// main) is stated per scope: see `NetworkPosition`.
    GuestWifiLaptop,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub kind: String,
    pub source_tool: String,
    pub source_tool_version: Option<String>,
    /// Pointer to record or artifact file.
    pub pointer: String,
    /// SHA-256 of raw artifact, hex. Hash ≠ chain of custody.
    pub sha256: Option<String>,
    pub lineage: Lineage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedIdentifier {
    pub kind: String,
    pub value: String,
    pub source: Provenance,
    #[serde(with = "time::serde::rfc3339")]
    pub seen_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Asset {
    pub id: AssetId,
    /// Default: separate nodes until corroborated (no auto-merge).
    pub observed_identifiers: Vec<ObservedIdentifier>,
    pub role_hypothesis: Option<String>,
    pub epistemic_status: EpistemicStatus,
    pub confidence: Confidence,
    pub evidence_refs: Vec<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub source: AssetId,
    pub target: AssetId,
    pub relation_type: RelationType,
    pub epistemic_status: EpistemicStatus,
    pub confidence: Confidence,
    pub evidence_ids: Vec<EvidenceId>,
}

/// Finding as exported (`schemas/finding.v1.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub schema_version: String,
    pub session_id: SessionId,
    pub finding_id: FindingId,
    pub status: FindingStatus,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub vantage: Vantage,
    pub tested_target: Option<String>,
    pub verified_claims: Vec<String>,
    pub unverified_claims: Vec<String>,
    pub evidence_refs: Vec<EvidenceId>,
    pub scope_id: Option<ScopeId>,
    pub recommendation: Option<String>,
    #[serde(default)]
    pub example_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented example must stay parseable by the canonical model.
    #[test]
    fn documented_finding_example_parses() {
        let raw = include_str!("../../../fixtures/findings/finding.example.json");
        let f: Finding = serde_json::from_str(raw).expect("example parses");
        assert_eq!(f.status, FindingStatus::Fail);
        assert!(f.example_only);
        assert!(
            !f.unverified_claims.is_empty(),
            "TCP reach must not imply auth bypass"
        );
    }
}
