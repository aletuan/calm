//! Extension SDK (WP7). JSON-RPC 2.0 over stdio. Plugin output is untrusted.
//! JSON-RPC/subprocess is NOT sandboxing — see docs/architecture/03.
//!
//! Skeleton: manifest identity and protocol constants.

use serde::{Deserialize, Serialize};

/// Manifest `apiVersion` for Calm extensions (ADR-008).
pub const MANIFEST_API_VERSION: &str = "calm.aletuan.com/v1alpha1";
pub const JSONRPC_VERSION: &str = "2.0";

/// Handshake methods every adapter must answer.
pub const HANDSHAKE_METHODS: &[&str] = &[
    "plugin.info",
    "capabilities",
    "input_schema",
    "output_schema",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub supported_contract_versions: Vec<String>,
}
