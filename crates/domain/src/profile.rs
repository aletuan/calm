//! Network profile as seen from this Mac (FR-001, W01/W03).
//!
//! Every field carries where it came from and how much we know. A missing
//! value is never guessed: it stays `None` with a reason.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::semantics::EpistemicStatus;

/// A value plus its provenance. `value: None` means "not known", never "absent".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sourced<T> {
    pub value: Option<T>,
    /// e.g. "corewlan", "route -n get default", "scutil --dns", "ifconfig en0"
    pub source: String,
    pub status: EpistemicStatus,
    /// Why the value is missing or how to read it, e.g. "location_permission_not_granted".
    pub note: Option<String>,
}

impl<T> Sourced<T> {
    pub fn observed(value: T, source: impl Into<String>) -> Self {
        Self {
            value: Some(value),
            source: source.into(),
            status: EpistemicStatus::Observed,
            note: None,
        }
    }

    pub fn unknown(source: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            value: None,
            source: source.into(),
            status: EpistemicStatus::Unverified,
            note: Some(note.into()),
        }
    }

    /// A value derived by convention or reasoning, not measured directly.
    pub fn inferred(value: T, source: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            value: Some(value),
            source: source.into(),
            status: EpistemicStatus::Inferred,
            note: Some(note.into()),
        }
    }

    /// Observed if present, otherwise unverified with `note`.
    pub fn from_option(
        value: Option<T>,
        source: impl Into<String>,
        note: impl Into<String>,
    ) -> Self {
        match value {
            Some(v) => Self::observed(v, source),
            None => Self::unknown(source, note),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationAuthorization {
    NotDetermined,
    Restricted,
    Denied,
    Authorized,
    /// Not macOS, or the API could not be queried.
    Unavailable,
}

impl LocationAuthorization {
    pub fn from_cl_code(code: i32) -> Self {
        match code {
            0 => Self::NotDetermined,
            1 => Self::Restricted,
            2 => Self::Denied,
            3 | 4 => Self::Authorized,
            _ => Self::Unavailable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WifiInfo {
    pub interface: Sourced<String>,
    /// Requires Location permission on macOS 14+.
    pub ssid: Sourced<String>,
    /// Requires Location permission on macOS 14+.
    pub bssid: Sourced<String>,
    pub channel: Sourced<u32>,
    pub band: Sourced<String>,
    pub channel_width: Sourced<String>,
    pub rssi_dbm: Sourced<i64>,
    pub noise_dbm: Sourced<i64>,
    pub security: Sourced<String>,
    pub phy_mode: Sourced<String>,
    pub tx_rate_mbps: Sourced<f64>,
    pub country_code: Sourced<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpAddress {
    pub address: String,
    /// Prefix length, when known.
    pub prefix: Option<u8>,
    /// e.g. "secured", "temporary", "autoconf" (IPv6 flags as printed).
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkProfile {
    pub schema_version: String,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    pub location_authorization: LocationAuthorization,
    /// False when running unbundled (`tauri dev`): macOS never shows the Location prompt then.
    pub bundled_app: bool,
    pub wifi: WifiInfo,
    pub hardware_address: Sourced<String>,
    /// True when the locally-administered bit is set (macOS Private Wi-Fi
    /// Address). Inferred from the IEEE 802 U/L convention, not measured.
    pub hardware_address_private: Sourced<bool>,
    pub ipv4: Sourced<Vec<IpAddress>>,
    pub ipv6: Sourced<Vec<IpAddress>>,
    /// "global", "unique_local" or "link_local_only", derived from `ipv6`.
    pub ipv6_scope: Sourced<String>,
    pub default_gateway: Sourced<String>,
    pub default_route_interface: Sourced<String>,
    pub dns_servers: Sourced<Vec<String>>,
}
