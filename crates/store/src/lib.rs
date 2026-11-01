//! Local session storage (M1.5, ADR-007, ADR-009, NFR-07, NFR-08).
//!
//! - One SQLite file. Only ids, timestamps, sizes, kinds and retention are in
//!   clear; everything that describes a network (session name, site, labels,
//!   profiles, flows, graphs, file names and hashes) is sealed with AES-256-GCM.
//! - Each session has its own data key, wrapped by a master key that lives in
//!   the macOS Keychain, never in the database. Deleting a session deletes its
//!   wrapped key: the ciphertext becomes unreadable even in old backups
//!   (crypto-shredding). `secure_delete` also zeroes freed pages.
//! - A canary sealed with the master key detects a wrong or replaced key, so
//!   the store refuses to open instead of returning garbage.

pub mod crypto;
pub mod keys;

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use crypto::Key;
pub use keys::{KeyProvider, StaticKey};

pub const SCHEMA_VERSION: i64 = 1;
const DAY_MS: i64 = 86_400_000;

#[derive(Debug, Clone, thiserror::Error, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum StoreError {
    /// The Keychain could not provide the master key.
    #[error("master key unavailable: {0}")]
    KeyUnavailable(String),
    /// The database was sealed with another master key.
    #[error("the database was encrypted with a different key")]
    KeyMismatch,
    #[error("not found")]
    NotFound,
    /// Ciphertext failed authentication or the payload does not parse.
    #[error("stored data is corrupt or was tampered with: {0}")]
    Corrupt(String),
    /// Written by a newer Calm.
    #[error("unsupported schema version {0}")]
    UnsupportedSchema(i64),
    #[error("database error: {0}")]
    Db(String),
    #[error("io error: {0}")]
    Io(String),
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
            other => StoreError::Db(other.to_string()),
        }
    }
}

/// What the user typed when creating a session. Sealed at rest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMeta {
    pub name: String,
    pub site: String,
    pub operator: String,
    pub authorization_ref: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub meta: SessionMeta,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// `None` keeps the session until the user deletes it.
    pub retention_days: Option<u32>,
    pub snapshot_count: u64,
    /// Sum of sealed snapshot sizes.
    pub stored_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    /// This Mac: network profile, graph and optionally a live capture.
    Live,
    /// An imported capture file (summaries only, never the raw file).
    Import,
    /// An approved scope grant (M2). Immutable once written.
    Scope,
    /// Results of one run of authorized checks (M2).
    Findings,
}

/// Audit actions beyond storage housekeeping. Subjects are ids only — never
/// addresses, names or other network data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    ScopeApproved,
    ScopeRevoked,
    ChecksStarted,
    ChecksFinished,
    ProbeAllowed,
    ProbeDenied,
    EmergencyStop,
}

impl AuditAction {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditAction::ScopeApproved => "scope_approved",
            AuditAction::ScopeRevoked => "scope_revoked",
            AuditAction::ChecksStarted => "checks_started",
            AuditAction::ChecksFinished => "checks_finished",
            AuditAction::ProbeAllowed => "probe_allowed",
            AuditAction::ProbeDenied => "probe_denied",
            AuditAction::EmergencyStop => "emergency_stop",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSummary {
    pub id: String,
    pub session_id: String,
    pub kind: SnapshotKind,
    pub label: String,
    pub created_at_ms: i64,
    pub size_bytes: u64,
}

/// Audit trail entry. Contains no network data by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub at_ms: i64,
    pub action: String,
    pub subject_id: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct OpenReport {
    /// Sessions deleted because their retention period ended.
    pub purged: usize,
}

pub struct Store {
    conn: rusqlite::Connection,
    master: Key,
}

const SCHEMA: &str = "
CREATE TABLE meta (
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  retention_days INTEGER,
  wrapped_key BLOB NOT NULL,
  meta BLOB NOT NULL
);
CREATE TABLE snapshots (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  size INTEGER NOT NULL,
  label BLOB NOT NULL,
  payload BLOB NOT NULL
);
CREATE INDEX snapshots_by_session ON snapshots(session_id, created_at);
CREATE TABLE events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  action TEXT NOT NULL,
  subject_id TEXT NOT NULL
);
";

const CANARY_AAD: &[u8] = b"calm/v1/canary";
const CANARY: &[u8] = b"calm-canary-v1";

fn aad_dek(session: &str) -> Vec<u8> {
    format!("calm/v1/dek/{session}").into_bytes()
}
fn aad_session(session: &str) -> Vec<u8> {
    format!("calm/v1/session/{session}").into_bytes()
}
fn aad_label(session: &str, snap: &str, kind: SnapshotKind) -> Vec<u8> {
    format!("calm/v1/label/{session}/{snap}/{}", kind.as_str()).into_bytes()
}
fn aad_payload(session: &str, snap: &str, kind: SnapshotKind) -> Vec<u8> {
    format!("calm/v1/payload/{session}/{snap}/{}", kind.as_str()).into_bytes()
}

impl SnapshotKind {
    fn as_str(self) -> &'static str {
        match self {
            SnapshotKind::Live => "live",
            SnapshotKind::Import => "import",
            SnapshotKind::Scope => "scope",
            SnapshotKind::Findings => "findings",
        }
    }
    fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "live" => Ok(SnapshotKind::Live),
            "import" => Ok(SnapshotKind::Import),
            "scope" => Ok(SnapshotKind::Scope),
            "findings" => Ok(SnapshotKind::Findings),
            other => Err(StoreError::Corrupt(format!(
                "unknown snapshot kind {other}"
            ))),
        }
    }
}

/// A random 128-bit id, hex. Unguessable; used for sessions, snapshots and scopes.
pub fn new_id() -> Result<String, StoreError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| StoreError::Io(e.to_string()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn io(e: std::io::Error) -> StoreError {
    StoreError::Io(e.to_string())
}

#[cfg(unix)]
fn make_private(path: &Path, dir: bool) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if dir { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io)
}
#[cfg(not(unix))]
fn make_private(_path: &Path, _dir: bool) -> Result<(), StoreError> {
    Ok(())
}

struct SessionRow {
    id: String,
    created_at: i64,
    updated_at: i64,
    retention_days: Option<u32>,
    wrapped_key: Vec<u8>,
    meta: Vec<u8>,
    count: u64,
    bytes: u64,
}

const SESSION_SELECT: &str =
    "SELECT s.id, s.created_at, s.updated_at, s.retention_days, s.wrapped_key, s.meta,
  (SELECT count(*) FROM snapshots WHERE session_id = s.id),
  (SELECT coalesce(sum(size), 0) FROM snapshots WHERE session_id = s.id)
  FROM sessions s";

fn session_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        id: r.get(0)?,
        created_at: r.get(1)?,
        updated_at: r.get(2)?,
        retention_days: r
            .get::<_, Option<i64>>(3)?
            .map(|d| d.clamp(0, u32::MAX as i64) as u32),
        wrapped_key: r.get(4)?,
        meta: r.get(5)?,
        count: r.get::<_, i64>(6)?.max(0) as u64,
        bytes: r.get::<_, i64>(7)?.max(0) as u64,
    })
}

struct SnapRow {
    id: String,
    session_id: String,
    kind: String,
    created_at: i64,
    size: i64,
    label: Vec<u8>,
}

const SNAP_SELECT: &str = "SELECT id, session_id, kind, created_at, size, label FROM snapshots";

fn snap_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SnapRow> {
    Ok(SnapRow {
        id: r.get(0)?,
        session_id: r.get(1)?,
        kind: r.get(2)?,
        created_at: r.get(3)?,
        size: r.get(4)?,
        label: r.get(5)?,
    })
}

impl Store {
    /// Opens or creates the database at `path` (file mode 0600, parent 0700),
    /// verifies the master key and purges expired sessions.
    pub fn open(
        path: &Path,
        keys: &dyn KeyProvider,
        now_ms: i64,
    ) -> Result<(Store, OpenReport), StoreError> {
        let master = keys.master_key()?;
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(io)?;
                make_private(dir, true)?;
            }
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(io)?;
        make_private(path, false)?;
        let conn = rusqlite::Connection::open(path)?;
        let store = Store::init(conn, master)?;
        let purged = store.purge_expired(now_ms)?;
        Ok((store, OpenReport { purged }))
    }

    pub fn open_in_memory(master: Key) -> Result<Store, StoreError> {
        Store::init(rusqlite::Connection::open_in_memory()?, master)
    }

    fn init(conn: rusqlite::Connection, master: Key) -> Result<Store, StoreError> {
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        match version {
            0 => {
                let canary = crypto::seal(&master, CANARY_AAD, CANARY)?;
                let tx = conn.unchecked_transaction()?;
                tx.execute_batch(SCHEMA)?;
                tx.execute("INSERT INTO meta (k, v) VALUES ('canary', ?1)", [canary])?;
                tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
                tx.commit()?;
            }
            SCHEMA_VERSION => {
                let canary: Vec<u8> =
                    conn.query_row("SELECT v FROM meta WHERE k = 'canary'", [], |r| r.get(0))?;
                match crypto::open(&master, CANARY_AAD, &canary) {
                    Ok(p) if &p[..] == CANARY => {}
                    _ => return Err(StoreError::KeyMismatch),
                }
            }
            other => return Err(StoreError::UnsupportedSchema(other)),
        }
        Ok(Store { conn, master })
    }

    fn event(
        &self,
        at_ms: i64,
        session_id: &str,
        action: &str,
        subject_id: &str,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO events (at, session_id, action, subject_id) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![at_ms, session_id, action, subject_id],
        )?;
        Ok(())
    }

    fn dek(&self, session_id: &str, wrapped: &[u8]) -> Result<Key, StoreError> {
        let raw = crypto::open(&self.master, &aad_dek(session_id), wrapped)?;
        let arr: [u8; crypto::KEY_LEN] = raw[..]
            .try_into()
            .map_err(|_| StoreError::Corrupt("data key length".into()))?;
        Ok(Key::from_bytes(arr))
    }

    fn summary(&self, row: SessionRow) -> Result<SessionSummary, StoreError> {
        let dek = self.dek(&row.id, &row.wrapped_key)?;
        let plain = crypto::open(&dek, &aad_session(&row.id), &row.meta)?;
        let meta: SessionMeta =
            serde_json::from_slice(&plain).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Ok(SessionSummary {
            id: row.id,
            meta,
            created_at_ms: row.created_at,
            updated_at_ms: row.updated_at,
            retention_days: row.retention_days,
            snapshot_count: row.count,
            stored_bytes: row.bytes,
        })
    }

    fn session_row(&self, id: &str) -> Result<SessionRow, StoreError> {
        Ok(self.conn.query_row(
            &format!("{SESSION_SELECT} WHERE s.id = ?1"),
            [id],
            session_row,
        )?)
    }

    fn seal_meta(&self, id: &str, dek: &Key, meta: &SessionMeta) -> Result<Vec<u8>, StoreError> {
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(meta).map_err(|e| StoreError::Corrupt(e.to_string()))?,
        );
        crypto::seal(dek, &aad_session(id), &json)
    }

    pub fn create_session(
        &self,
        meta: &SessionMeta,
        retention_days: Option<u32>,
        now_ms: i64,
    ) -> Result<SessionSummary, StoreError> {
        let id = new_id()?;
        let dek = Key::random()?;
        let wrapped = crypto::seal(&self.master, &aad_dek(&id), dek.as_bytes())?;
        let sealed = self.seal_meta(&id, &dek, meta)?;
        self.conn.execute(
            "INSERT INTO sessions (id, created_at, updated_at, retention_days, wrapped_key, meta) VALUES (?1, ?2, ?2, ?3, ?4, ?5)",
            rusqlite::params![id, now_ms, retention_days.map(i64::from), wrapped, sealed],
        )?;
        self.event(now_ms, &id, "session_created", &id)?;
        self.get_session(&id)
    }

    pub fn update_session(
        &self,
        id: &str,
        meta: &SessionMeta,
        retention_days: Option<u32>,
        now_ms: i64,
    ) -> Result<SessionSummary, StoreError> {
        let row = self.session_row(id)?;
        let dek = self.dek(id, &row.wrapped_key)?;
        let sealed = self.seal_meta(id, &dek, meta)?;
        self.conn.execute(
            "UPDATE sessions SET meta = ?1, retention_days = ?2, updated_at = ?3 WHERE id = ?4",
            rusqlite::params![sealed, retention_days.map(i64::from), now_ms, id],
        )?;
        self.event(now_ms, id, "session_updated", id)?;
        self.get_session(id)
    }

    /// Newest first.
    pub fn list_sessions(&self) -> Result<Vec<SessionSummary>, StoreError> {
        let mut st = self.conn.prepare(&format!(
            "{SESSION_SELECT} ORDER BY s.created_at DESC, s.rowid DESC"
        ))?;
        let rows = st
            .query_map([], session_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(|r| self.summary(r)).collect()
    }

    pub fn get_session(&self, id: &str) -> Result<SessionSummary, StoreError> {
        let row = self.session_row(id)?;
        self.summary(row)
    }

    /// The session new snapshots go to, remembered across launches. Only its
    /// random id is stored (in clear); the name stays sealed.
    pub fn active_session(&self) -> Result<Option<String>, StoreError> {
        match self
            .conn
            .query_row("SELECT v FROM meta WHERE k = 'active_session'", [], |r| {
                r.get::<_, String>(0)
            }) {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_active_session(&self, id: Option<&str>) -> Result<(), StoreError> {
        match id {
            Some(id) => {
                self.session_row(id)?;
                self.conn.execute(
                    "INSERT INTO meta (k, v) VALUES ('active_session', ?1)
                     ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                    [id],
                )?;
            }
            None => {
                self.conn
                    .execute("DELETE FROM meta WHERE k = 'active_session'", [])?;
            }
        }
        Ok(())
    }

    /// Deletes the session, its snapshots and its data key.
    pub fn delete_session(&self, id: &str, now_ms: i64) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute("DELETE FROM sessions WHERE id = ?1", [id])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        tx.execute(
            "DELETE FROM meta WHERE k = 'active_session' AND v = ?1",
            [id],
        )?;
        tx.execute(
            "INSERT INTO events (at, session_id, action, subject_id) VALUES (?1, ?2, 'session_deleted', ?2)",
            rusqlite::params![now_ms, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn put_snapshot<T: Serialize>(
        &self,
        session_id: &str,
        kind: SnapshotKind,
        label: &str,
        payload: &T,
        now_ms: i64,
    ) -> Result<SnapshotSummary, StoreError> {
        let row = self.session_row(session_id)?;
        let dek = self.dek(session_id, &row.wrapped_key)?;
        let id = new_id()?;
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(payload).map_err(|e| StoreError::Corrupt(e.to_string()))?,
        );
        let sealed_payload = crypto::seal(&dek, &aad_payload(session_id, &id, kind), &json)?;
        let sealed_label = crypto::seal(&dek, &aad_label(session_id, &id, kind), label.as_bytes())?;
        let size = sealed_payload.len() as i64;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO snapshots (id, session_id, kind, created_at, size, label, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![id, session_id, kind.as_str(), now_ms, size, sealed_label, sealed_payload],
        )?;
        tx.execute(
            "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now_ms, session_id],
        )?;
        tx.execute(
            "INSERT INTO events (at, session_id, action, subject_id) VALUES (?1, ?2, 'snapshot_saved', ?3)",
            rusqlite::params![now_ms, session_id, id],
        )?;
        tx.commit()?;
        Ok(SnapshotSummary {
            id,
            session_id: session_id.to_owned(),
            kind,
            label: label.to_owned(),
            created_at_ms: now_ms,
            size_bytes: size as u64,
        })
    }

    fn snap_summary(&self, dek: &Key, r: SnapRow) -> Result<SnapshotSummary, StoreError> {
        let kind = SnapshotKind::parse(&r.kind)?;
        let label = crypto::open(dek, &aad_label(&r.session_id, &r.id, kind), &r.label)?;
        Ok(SnapshotSummary {
            label: String::from_utf8_lossy(&label).into_owned(),
            id: r.id,
            session_id: r.session_id,
            kind,
            created_at_ms: r.created_at,
            size_bytes: r.size.max(0) as u64,
        })
    }

    /// Newest first.
    pub fn list_snapshots(&self, session_id: &str) -> Result<Vec<SnapshotSummary>, StoreError> {
        let row = self.session_row(session_id)?;
        let dek = self.dek(session_id, &row.wrapped_key)?;
        let mut st = self.conn.prepare(&format!(
            "{SNAP_SELECT} WHERE session_id = ?1 ORDER BY created_at DESC, rowid DESC"
        ))?;
        let rows = st
            .query_map([session_id], snap_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|r| self.snap_summary(&dek, r))
            .collect()
    }

    pub fn get_snapshot<T: DeserializeOwned>(
        &self,
        id: &str,
    ) -> Result<(SnapshotSummary, T), StoreError> {
        let (r, payload): (SnapRow, Vec<u8>) = self.conn.query_row(
            "SELECT id, session_id, kind, created_at, size, label, payload FROM snapshots WHERE id = ?1",
            [id],
            |r| Ok((snap_row(r)?, r.get(6)?)),
        )?;
        let session = self.session_row(&r.session_id)?;
        let dek = self.dek(&r.session_id, &session.wrapped_key)?;
        let kind = SnapshotKind::parse(&r.kind)?;
        let plain = crypto::open(&dek, &aad_payload(&r.session_id, &r.id, kind), &payload)?;
        let value: T =
            serde_json::from_slice(&plain).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Ok((self.snap_summary(&dek, r)?, value))
    }

    /// Kind of a snapshot (stored in clear), to choose the payload type.
    pub fn snapshot_kind(&self, id: &str) -> Result<SnapshotKind, StoreError> {
        let k: String =
            self.conn
                .query_row("SELECT kind FROM snapshots WHERE id = ?1", [id], |r| {
                    r.get(0)
                })?;
        SnapshotKind::parse(&k)
    }

    pub fn delete_snapshot(&self, id: &str, now_ms: i64) -> Result<(), StoreError> {
        let session_id: String = self.conn.query_row(
            "SELECT session_id FROM snapshots WHERE id = ?1",
            [id],
            |r| r.get(0),
        )?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM snapshots WHERE id = ?1", [id])?;
        tx.execute(
            "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now_ms, session_id],
        )?;
        tx.execute(
            "INSERT INTO events (at, session_id, action, subject_id) VALUES (?1, ?2, 'snapshot_deleted', ?3)",
            rusqlite::params![now_ms, session_id, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Deletes sessions whose last change is older than their retention.
    pub fn purge_expired(&self, now_ms: i64) -> Result<usize, StoreError> {
        let mut st = self.conn.prepare(
            "SELECT id FROM sessions WHERE retention_days IS NOT NULL AND updated_at + retention_days * ?1 < ?2",
        )?;
        let ids = st
            .query_map(rusqlite::params![DAY_MS, now_ms], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for id in &ids {
            self.delete_session(id, now_ms)?;
            self.conn.execute(
                "UPDATE events SET action = 'session_expired' WHERE seq = (SELECT max(seq) FROM events WHERE session_id = ?1)",
                [id],
            )?;
        }
        Ok(ids.len())
    }

    /// Record an audit event for a session that exists.
    pub fn audit(
        &self,
        session_id: &str,
        action: AuditAction,
        subject_id: &str,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        self.session_row(session_id)?;
        self.event(now_ms, session_id, action.as_str(), subject_id)
    }

    /// Whether `action` was ever recorded for `subject_id` in this session.
    pub fn has_event(
        &self,
        session_id: &str,
        action: AuditAction,
        subject_id: &str,
    ) -> Result<bool, StoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM events WHERE session_id = ?1 AND action = ?2 AND subject_id = ?3",
            rusqlite::params![session_id, action.as_str(), subject_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Audit events for one session, oldest first (kept after deletion).
    pub fn events(&self, session_id: &str) -> Result<Vec<Event>, StoreError> {
        let mut st = self.conn.prepare(
            "SELECT at, action, subject_id FROM events WHERE session_id = ?1 ORDER BY seq",
        )?;
        let ev = st
            .query_map([session_id], |r| {
                Ok(Event {
                    at_ms: r.get(0)?,
                    action: r.get(1)?,
                    subject_id: r.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ev)
    }
}
