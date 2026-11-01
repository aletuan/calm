//! Reporting & export (WP8). Formats that cannot represent a field get a
//! companion JSON — never silently invented data.
//!
//! Skeleton: supported format list.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Markdown,
    Html,
    Pdf,
    CanonicalJson,
    Sarif,
    GraphMl,
    Pcapng,
}
