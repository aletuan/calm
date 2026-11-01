//! Tauri shell. Exposes read-only IPC commands only. Active operations will be
//! routed through `calm-orchestrator`'s scope guard — never directly from UI.
//!
//! Invariant (NFR-03 / AT-02): nothing active starts on app launch. The network
//! profile is read-only local metadata (L0) and sends no packets.

pub mod assess;
pub mod quit;
pub mod records;
pub mod scopes;
pub mod source;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use calm_capture::{Availability, Capture, CaptureView};
use calm_domain::{LocationAuthorization, NetworkProfile};
use calm_flow_engine::import::ImportSummary;
use calm_flow_engine::{FlowSnapshot, FlowTable};
use calm_graph_engine::GraphSnapshot;
use calm_store::{SessionMeta, SessionSummary, SnapshotKind, SnapshotSummary, Store, StoreError};
use records::{ImportRecord, LiveRecord, RecordedView};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

/// The single local capture session (M1.3). Memory only.
#[derive(Default)]
pub struct CaptureState(Mutex<Option<Capture>>);

/// Max flows returned to the UI per poll; totals always cover everything.
const FLOW_VIEW_LIMIT: usize = 300;

/// One imported capture file (M1.4). Memory only, like live capture; kept
/// apart from this Mac's data and never merged into its graph.
pub struct Imported {
    file_name: String,
    size_bytes: u64,
    sha256: String,
    imported_at_ms: i64,
    summary: ImportSummary,
    table: FlowTable,
    graph: GraphSnapshot,
}

#[derive(Default)]
pub struct ImportState(Mutex<Option<Imported>>);

/// Larger files are refused until the storage and benchmark work (NFR-11).
const MAX_IMPORT_BYTES: u64 = 1 << 30;
const MAX_IMPORT_FLOWS: usize = 50_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportView {
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub imported_at_ms: i64,
    pub summary: ImportSummary,
    pub snapshot: FlowSnapshot,
    pub graph: GraphSnapshot,
}

impl Imported {
    fn record(&self) -> ImportRecord {
        ImportRecord {
            file_name: self.file_name.clone(),
            size_bytes: self.size_bytes,
            sha256: self.sha256.clone(),
            imported_at_ms: self.imported_at_ms,
            summary: self.summary.clone(),
            snapshot: self.table.snapshot(usize::MAX),
            bindings: self.table.bindings(),
            graph: self.graph.clone(),
        }
    }

    fn view(&self) -> ImportView {
        ImportView {
            file_name: self.file_name.clone(),
            size_bytes: self.size_bytes,
            sha256: self.sha256.clone(),
            imported_at_ms: self.imported_at_ms,
            summary: self.summary.clone(),
            snapshot: self.table.snapshot(FLOW_VIEW_LIMIT),
            graph: self.graph.clone(),
        }
    }
}

/// Why an import produced nothing. Damage *after* a readable header is not an
/// error: it is reported in `summary.error` with the partial result.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImportError {
    Cancelled,
    TooLarge { size_bytes: u64, limit_bytes: u64 },
    Unreadable { detail: String },
    NotACapture,
}

fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn load_capture_file(path: &std::path::Path) -> Result<Imported, ImportError> {
    use calm_flow_engine::pcap::ErrorReason;
    let unreadable = |e: std::io::Error| ImportError::Unreadable {
        detail: e.to_string(),
    };
    let size_bytes = std::fs::metadata(path).map_err(unreadable)?.len();
    if size_bytes > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge {
            size_bytes,
            limit_bytes: MAX_IMPORT_BYTES,
        });
    }
    let sha256 = sha256_file(path).map_err(unreadable)?;
    let open = || std::fs::File::open(path).map(std::io::BufReader::new);
    let replay =
        calm_flow_engine::import::replay(open, MAX_IMPORT_FLOWS).map_err(|e| match e.reason {
            ErrorReason::NotACapture => ImportError::NotACapture,
            other => ImportError::Unreadable {
                detail: format!("{other:?} at byte {}", e.offset),
            },
        })?;
    let graph = calm_graph_engine::from_import(
        &replay.summary,
        &replay.table.all_flows(),
        &replay.table.bindings(),
    );
    let imported_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Ok(Imported {
        file_name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        size_bytes,
        sha256,
        imported_at_ms,
        summary: replay.summary,
        table: replay.table,
        graph,
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub identifier: &'static str,
    pub schema_version: &'static str,
    /// Always "passive" at launch.
    pub mode: &'static str,
    pub active_scanning_enabled: bool,
}

pub fn app_info_value() -> AppInfo {
    AppInfo {
        name: "Calm",
        version: env!("CARGO_PKG_VERSION"),
        identifier: "com.aletuan.calm",
        schema_version: calm_domain::CANONICAL_SCHEMA_VERSION,
        mode: "passive",
        active_scanning_enabled: false,
    }
}

/// Runs `f` on the main thread (required by CLLocationManager) and awaits the
/// result without blocking it. Commands using this must be `async` so they are
/// not themselves on the main thread (that would deadlock).
async fn on_main<T, F>(app: &AppHandle, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let _ = tx.send(f());
    })
    .map_err(|e| e.to_string())?;
    tauri::async_runtime::spawn_blocking(move || rx.recv().map_err(|e| e.to_string()))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn app_info() -> AppInfo {
    app_info_value()
}

#[tauri::command]
async fn location_status(app: AppHandle) -> Result<LocationAuthorization, String> {
    on_main(&app, calm_net_profile::location_authorization).await
}

/// Consent-first: only called when the user presses the button in Overview.
#[tauri::command]
async fn request_location(app: AppHandle) -> Result<bool, String> {
    on_main(&app, calm_net_profile::request_location_authorization).await
}

#[tauri::command]
async fn network_profile(app: AppHandle) -> Result<NetworkProfile, String> {
    on_main(&app, calm_net_profile::collect).await
}

/// Profile and the graph derived from it, from one collection so both views
/// always describe the same moment.
#[derive(Debug, Serialize)]
pub struct NetworkOverview {
    pub profile: NetworkProfile,
    pub graph: GraphSnapshot,
}

#[tauri::command]
async fn network_overview(
    app: AppHandle,
    capture: State<'_, CaptureState>,
) -> Result<NetworkOverview, String> {
    let profile = on_main(&app, calm_net_profile::collect).await?;
    let mut graph = calm_graph_engine::from_profile(&profile);
    let flows = capture
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .as_ref()
        .map(|c| c.flows_and_bindings());
    if let Some((flows, bindings)) = flows {
        calm_graph_engine::add_flows(&mut graph, &profile, &flows, &bindings);
    }
    Ok(NetworkOverview { profile, graph })
}

fn capture_interface(p: &NetworkProfile) -> Option<String> {
    p.default_route_interface
        .value
        .clone()
        .or_else(|| p.wifi.interface.value.clone())
}

fn local_addresses(p: &NetworkProfile) -> Vec<IpAddr> {
    p.ipv4
        .value
        .iter()
        .flatten()
        .chain(p.ipv6.value.iter().flatten())
        .filter_map(|a| a.address.parse().ok())
        .collect()
}

#[derive(Debug, Serialize)]
pub struct CaptureProbe {
    pub interface: Option<String>,
    pub availability: Availability,
}

/// Can capture start right now? Opens and closes BPF; captures nothing.
#[tauri::command]
async fn capture_probe(app: AppHandle) -> Result<CaptureProbe, String> {
    let profile = on_main(&app, calm_net_profile::collect).await?;
    let interface = capture_interface(&profile);
    let availability = match &interface {
        Some(i) => calm_capture::probe(i),
        None => Availability::NoInterface {
            detail: "no default route interface".into(),
        },
    };
    Ok(CaptureProbe {
        interface,
        availability,
    })
}

/// Starts local capture (L0 passive; user-initiated after the consent notice).
#[tauri::command]
async fn capture_start(
    app: AppHandle,
    capture: State<'_, CaptureState>,
) -> Result<CaptureView, Availability> {
    let profile = on_main(&app, calm_net_profile::collect)
        .await
        .map_err(|detail| Availability::Error { detail })?;
    let iface = capture_interface(&profile).ok_or_else(|| Availability::NoInterface {
        detail: "no default route interface".into(),
    })?;
    let mut slot = capture.0.lock().map_err(|e| Availability::Error {
        detail: e.to_string(),
    })?;
    if let Some(c) = slot.as_ref() {
        if c.is_running() {
            return Ok(c.view(FLOW_VIEW_LIMIT));
        }
    }
    let c = Capture::start(&iface, local_addresses(&profile))?;
    let view = c.view(FLOW_VIEW_LIMIT);
    *slot = Some(c);
    Ok(view)
}

/// Stops capture; flows stay in memory until the next start or app quit.
#[tauri::command]
fn capture_stop(capture: State<'_, CaptureState>) -> Result<Option<CaptureView>, String> {
    let mut slot = capture.0.lock().map_err(|e| e.to_string())?;
    Ok(slot.as_mut().map(|c| {
        c.stop();
        c.view(FLOW_VIEW_LIMIT)
    }))
}

#[tauri::command]
fn capture_view(capture: State<'_, CaptureState>) -> Result<Option<CaptureView>, String> {
    let slot = capture.0.lock().map_err(|e| e.to_string())?;
    Ok(slot.as_ref().map(|c| c.view(FLOW_VIEW_LIMIT)))
}

/// Opens the native file picker (Rust side: the UI never handles paths or
/// file system access) and replays the chosen PCAP/PCAPNG. Reads the file
/// only; sends nothing on the network.
#[tauri::command]
async fn import_pick(
    app: AppHandle,
    imported: State<'_, ImportState>,
) -> Result<ImportView, ImportError> {
    let dialog = app.dialog().clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        dialog
            .file()
            .set_title("Import packet capture")
            .add_filter("Packet capture", &["pcapng", "pcap", "cap"])
            .blocking_pick_file()
    })
    .await
    .map_err(|e| ImportError::Unreadable {
        detail: e.to_string(),
    })?;
    let path = picked
        .and_then(|p| p.into_path().ok())
        .ok_or(ImportError::Cancelled)?;
    let loaded = tauri::async_runtime::spawn_blocking(move || load_capture_file(&path))
        .await
        .map_err(|e| ImportError::Unreadable {
            detail: e.to_string(),
        })??;
    let view = loaded.view();
    *imported.0.lock().map_err(|e| ImportError::Unreadable {
        detail: e.to_string(),
    })? = Some(loaded);
    Ok(view)
}

#[tauri::command]
fn import_view(imported: State<'_, ImportState>) -> Result<Option<ImportView>, String> {
    let slot = imported.0.lock().map_err(|e| e.to_string())?;
    Ok(slot.as_ref().map(Imported::view))
}

#[tauri::command]
fn import_clear(imported: State<'_, ImportState>) -> Result<(), String> {
    *imported.0.lock().map_err(|e| e.to_string())? = None;
    Ok(())
}

// ---- Session storage (M1.5) ----

/// Encrypted local store, opened on first use (that is when the Keychain is
/// first touched), plus the session new snapshots go to.
#[derive(Default)]
pub struct StoreState {
    slot: Mutex<StoreSlot>,
    active: Mutex<Option<String>>,
}

#[derive(Default)]
enum StoreSlot {
    #[default]
    Closed,
    Ready(Store),
    Failed(StoreError),
}

#[derive(Debug, Serialize)]
pub struct StoreStatus {
    /// "ready" | "closed" | "error"
    pub state: &'static str,
    pub error: Option<StoreError>,
    pub path: Option<String>,
    pub purged_on_open: usize,
    pub active_session: Option<SessionSummary>,
}

const DB_FILE: &str = "calm.sqlite3";

/// Command logic without Tauri types, so it is unit-tested directly.
impl StoreState {
    /// Opens the store if it is not open yet; returns sessions purged by retention.
    fn open_at(
        &self,
        path: &std::path::Path,
        keys: &dyn calm_store::KeyProvider,
        now: i64,
    ) -> usize {
        let Ok(mut slot) = self.slot.lock() else {
            return 0;
        };
        if matches!(*slot, StoreSlot::Ready(_)) {
            return 0;
        }
        match Store::open(path, keys, now) {
            Ok((s, report)) => {
                // The active session is remembered in the store (M1.5 follow-up).
                if let (Ok(id), Ok(mut a)) = (s.active_session(), self.active.lock()) {
                    *a = id;
                }
                *slot = StoreSlot::Ready(s);
                report.purged
            }
            Err(e) => {
                *slot = StoreSlot::Failed(e);
                0
            }
        }
    }

    /// Moves an unreadable database aside (never deletes it).
    fn set_aside(&self, path: &std::path::Path, now: i64) -> Result<PathBuf, String> {
        let mut slot = self.slot.lock().map_err(|e| e.to_string())?;
        if !matches!(*slot, StoreSlot::Failed(StoreError::KeyMismatch)) {
            return Err("only an unreadable database can be set aside".into());
        }
        let aside = path.with_extension(format!("unreadable-{now}.sqlite3"));
        std::fs::rename(path, &aside).map_err(|e| e.to_string())?;
        *slot = StoreSlot::Closed;
        Ok(aside)
    }

    fn active_id(&self) -> Option<String> {
        self.active.lock().ok().and_then(|a| a.clone())
    }

    /// Sets the active session and remembers it in the store.
    fn set_active(&self, id: Option<String>) -> Result<(), StoreError> {
        with_store(self, |s| s.set_active_session(id.as_deref()))?;
        if let Ok(mut a) = self.active.lock() {
            *a = id;
        }
        Ok(())
    }

    fn create_session(&self, input: &SessionInput, now: i64) -> Result<SessionSummary, StoreError> {
        let s = with_store(self, |s| {
            s.create_session(&input.meta, input.retention_days, now)
        })?;
        self.set_active(Some(s.id.clone()))?;
        Ok(s)
    }

    fn delete_session(&self, id: &str, now: i64) -> Result<(), StoreError> {
        with_store(self, |s| s.delete_session(id, now))?;
        // The store already forgot it; keep the in-memory copy in step.
        if self.active_id().as_deref() == Some(id) {
            if let Ok(mut a) = self.active.lock() {
                *a = None;
            }
        }
        Ok(())
    }

    fn activate(&self, id: Option<String>) -> Result<Option<SessionSummary>, StoreError> {
        let summary = match &id {
            Some(id) => Some(with_store(self, |s| s.get_session(id))?),
            None => None,
        };
        self.set_active(id)?;
        Ok(summary)
    }

    fn save<T: Serialize>(
        &self,
        kind: SnapshotKind,
        label: &str,
        rec: &T,
        now: i64,
    ) -> Result<SnapshotSummary, StoreError> {
        let session = self.active_id().ok_or(StoreError::NotFound)?;
        with_store(self, |s| s.put_snapshot(&session, kind, label, rec, now))
    }

    fn open_snapshot(&self, id: &str) -> Result<RecordedView, StoreError> {
        with_store(self, |s| {
            Ok(match s.snapshot_kind(id)? {
                SnapshotKind::Live => {
                    let (snapshot, rec): (_, LiveRecord) = s.get_snapshot(id)?;
                    RecordedView {
                        snapshot,
                        live: Some(rec.view(FLOW_VIEW_LIMIT)),
                        import: None,
                    }
                }
                SnapshotKind::Import => {
                    let (snapshot, rec): (_, ImportRecord) = s.get_snapshot(id)?;
                    RecordedView {
                        snapshot,
                        live: None,
                        import: Some(rec.view(FLOW_VIEW_LIMIT)),
                    }
                }
                // Scopes and findings are not traffic data; they have their own views.
                SnapshotKind::Scope | SnapshotKind::Findings => return Err(StoreError::NotFound),
            })
        })
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn db_path(app: &AppHandle) -> Result<PathBuf, StoreError> {
    app.path()
        .app_data_dir()
        .map(|d| d.join(DB_FILE))
        .map_err(|e| StoreError::Io(e.to_string()))
}

#[cfg(target_os = "macos")]
fn key_provider() -> impl calm_store::KeyProvider {
    calm_store::keys::Keychain::calm()
}
#[cfg(not(target_os = "macos"))]
fn key_provider() -> impl calm_store::KeyProvider {
    calm_store::keys::NoKey("the Keychain is only available on macOS".into())
}

fn with_store<T>(
    state: &StoreState,
    f: impl FnOnce(&Store) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let slot = state
        .slot
        .lock()
        .map_err(|e| StoreError::Io(e.to_string()))?;
    match &*slot {
        StoreSlot::Ready(s) => f(s),
        StoreSlot::Failed(e) => Err(e.clone()),
        StoreSlot::Closed => Err(StoreError::Io("storage is not open".into())),
    }
}

fn status(app: &AppHandle, state: &StoreState, purged: usize) -> StoreStatus {
    let path = db_path(app).ok().map(|p| p.display().to_string());
    state.status(path, purged)
}

impl StoreState {
    fn status(&self, path: Option<String>, purged: usize) -> StoreStatus {
        let state = self;
        let active_id = state.active.lock().ok().and_then(|a| a.clone());
        let slot = state.slot.lock();
        let (st, error, active_session) = match slot.as_deref() {
            Ok(StoreSlot::Ready(s)) => (
                "ready",
                None,
                active_id.and_then(|id| s.get_session(&id).ok()),
            ),
            Ok(StoreSlot::Failed(e)) => ("error", Some(e.clone()), None),
            Ok(StoreSlot::Closed) => ("closed", None, None),
            Err(e) => ("error", Some(StoreError::Io(e.to_string())), None),
        };
        StoreStatus {
            state: st,
            error,
            path,
            purged_on_open: purged,
            active_session,
        }
    }
}

#[tauri::command]
fn store_status(app: AppHandle, state: State<'_, StoreState>) -> StoreStatus {
    status(&app, &state, 0)
}

/// Opens the encrypted store (creating the Keychain master key on first use)
/// and applies retention. Idempotent.
#[tauri::command]
async fn store_open(app: AppHandle, state: State<'_, StoreState>) -> Result<StoreStatus, String> {
    let path = db_path(&app).map_err(|e| e.to_string())?;
    let purged = state.open_at(&path, &key_provider(), now_ms());
    Ok(status(&app, &state, purged))
}

/// When the database was encrypted with a key the Keychain no longer has:
/// move it aside (never delete it) and start an empty store.
#[tauri::command]
async fn store_set_aside_unreadable(
    app: AppHandle,
    state: State<'_, StoreState>,
) -> Result<StoreStatus, String> {
    let path = db_path(&app).map_err(|e| e.to_string())?;
    state.set_aside(&path, now_ms())?;
    store_open(app, state).await
}

#[tauri::command]
fn session_list(state: State<'_, StoreState>) -> Result<Vec<SessionSummary>, StoreError> {
    with_store(&state, |s| s.list_sessions())
}

#[derive(Debug, Deserialize)]
pub struct SessionInput {
    pub meta: SessionMeta,
    pub retention_days: Option<u32>,
}

/// Creates a session and makes it the active one.
#[tauri::command]
fn session_create(
    state: State<'_, StoreState>,
    input: SessionInput,
) -> Result<SessionSummary, StoreError> {
    state.create_session(&input, now_ms())
}

#[tauri::command]
fn session_update(
    state: State<'_, StoreState>,
    id: String,
    input: SessionInput,
) -> Result<SessionSummary, StoreError> {
    with_store(&state, |s| {
        s.update_session(&id, &input.meta, input.retention_days, now_ms())
    })
}

#[tauri::command]
fn session_delete(state: State<'_, StoreState>, id: String) -> Result<(), StoreError> {
    state.delete_session(&id, now_ms())
}

#[tauri::command]
fn session_activate(
    state: State<'_, StoreState>,
    id: Option<String>,
) -> Result<Option<SessionSummary>, StoreError> {
    state.activate(id)
}

#[tauri::command]
fn snapshot_list(
    state: State<'_, StoreState>,
    session_id: String,
) -> Result<Vec<SnapshotSummary>, StoreError> {
    with_store(&state, |s| {
        Ok(s.list_snapshots(&session_id)?
            .into_iter()
            .filter(|x| matches!(x.kind, SnapshotKind::Live | SnapshotKind::Import))
            .collect())
    })
}

/// Saves this Mac now: a fresh profile, the graph and the live capture (all
/// flows, if a capture exists) into the active session. Reads only.
async fn save_live_now(
    app: &AppHandle,
    label: Option<String>,
) -> Result<SnapshotSummary, StoreError> {
    let state = app.state::<StoreState>();
    let capture = app.state::<CaptureState>();
    state.active_id().ok_or(StoreError::NotFound)?;
    let profile = on_main(app, calm_net_profile::collect)
        .await
        .map_err(StoreError::Io)?;
    let mut graph = calm_graph_engine::from_profile(&profile);
    let (capture_view, bindings) = {
        let slot = capture
            .0
            .lock()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        match slot.as_ref() {
            Some(c) => {
                let (flows, bindings) = c.flows_and_bindings();
                calm_graph_engine::add_flows(&mut graph, &profile, &flows, &bindings);
                (Some(c.view(usize::MAX)), bindings)
            }
            None => (None, vec![]),
        }
    };
    let label = label.filter(|l| !l.trim().is_empty()).unwrap_or_else(|| {
        records::live_label(
            capture_view
                .as_ref()
                .map(|c| (c.snapshot.total_flows, c.elapsed_ms)),
        )
    });
    let rec = LiveRecord {
        profile,
        graph,
        capture: capture_view,
        bindings,
    };
    state.save(SnapshotKind::Live, &label, &rec, now_ms())
}

#[tauri::command]
async fn snapshot_save_live(
    app: AppHandle,
    label: Option<String>,
) -> Result<SnapshotSummary, StoreError> {
    save_live_now(&app, label).await
}

/// This Mac's network as a scope would be bound to it (gateway, subnet, SSID).
async fn network_binding(app: &AppHandle) -> Option<calm_domain::NetworkBinding> {
    let profile = on_main(app, calm_net_profile::collect).await.ok()?;
    calm_orchestrator::binding_from_profile(&profile)
}

#[tauri::command]
async fn scope_network(app: AppHandle) -> Option<calm_domain::NetworkBinding> {
    network_binding(&app).await
}

#[tauri::command]
fn scope_list(state: State<'_, StoreState>) -> Result<Vec<scopes::ScopeView>, StoreError> {
    let Some(session) = state.active_id() else {
        return Ok(Vec::new());
    };
    with_store(&state, |s| scopes::list(s, &session, now_ms()))
}

/// Approve a scope for the active session, bound to the network this Mac is on now.
#[tauri::command]
async fn scope_approve(
    app: AppHandle,
    draft: calm_orchestrator::ScopeDraft,
) -> Result<scopes::ScopeView, scopes::ScopeError> {
    let network = network_binding(&app).await;
    let state = app.state::<StoreState>();
    let session = state
        .active_id()
        .ok_or(scopes::ScopeError::NoActiveSession)?;
    let slot = state
        .slot
        .lock()
        .map_err(|e| scopes::ScopeError::Store(StoreError::Io(e.to_string())))?;
    match &*slot {
        StoreSlot::Ready(s) => scopes::approve(s, &session, &draft, network, now_ms()),
        StoreSlot::Failed(e) => Err(scopes::ScopeError::Store(e.clone())),
        StoreSlot::Closed => Err(scopes::ScopeError::Store(StoreError::Io(
            "storage is not open".into(),
        ))),
    }
}

#[tauri::command]
fn scope_revoke(state: State<'_, StoreState>, scope_id: String) -> Result<(), StoreError> {
    let session = state.active_id().ok_or(StoreError::NotFound)?;
    with_store(&state, |s| scopes::revoke(s, &session, &scope_id, now_ms()))
}

/// Profile on the main thread, from a worker thread (bounded wait).
fn binding_blocking(app: &AppHandle) -> Option<calm_domain::NetworkBinding> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let _ = tx.send(calm_net_profile::collect());
    })
    .ok()?;
    let profile = rx.recv_timeout(std::time::Duration::from_secs(10)).ok()?;
    calm_orchestrator::binding_from_profile(&profile)
}

#[tauri::command]
async fn checks_preflight(app: AppHandle) -> Result<assess::Preflight, StoreError> {
    let network = network_binding(&app).await;
    let state = app.state::<StoreState>();
    let scope = match state.active_id() {
        Some(session) => with_store(&state, |s| scopes::current(s, &session, now_ms()))?,
        None => None,
    };
    Ok(assess::preflight(scope, network))
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
enum RunError {
    AlreadyRunning,
    NoActiveSession,
    NoScope,
    NetworkChanged,
    Store(StoreError),
}

/// Start the authorized checks on the active session's scope. Probes run on
/// a worker thread; each one is authorized again just before it is sent.
#[tauri::command]
async fn checks_run(
    app: AppHandle,
    receiver_confirmed: bool,
) -> Result<assess::Progress, RunError> {
    let assess_state = app.state::<assess::AssessState>();
    if assess_state.running() {
        return Err(RunError::AlreadyRunning);
    }
    let state = app.state::<StoreState>();
    let session = state.active_id().ok_or(RunError::NoActiveSession)?;
    let view = with_store(&state, |s| scopes::current(s, &session, now_ms()))
        .map_err(RunError::Store)?
        .ok_or(RunError::NoScope)?;
    let net = network_binding(&app).await;
    if !net
        .as_ref()
        .is_some_and(|n| calm_orchestrator::same_network(&view.scope.network, n))
    {
        return Err(RunError::NetworkChanged);
    }
    let run_id = calm_store::new_id().map_err(RunError::Store)?;
    with_store(&state, |s| {
        s.audit(
            &session,
            calm_store::AuditAction::ChecksStarted,
            &run_id,
            now_ms(),
        )
    })
    .map_err(RunError::Store)?;
    let stop = assess_state.arm();
    let total = calm_orchestrator::checks::plan(&view.scope).len();
    let progress = assess::Progress {
        run_id: run_id.clone(),
        running: true,
        done: 0,
        total,
        last: None,
        stopped: false,
        started_at_ms: now_ms(),
        error: None,
        snapshot_id: None,
    };
    *assess_state
        .progress
        .lock()
        .map_err(|e| RunError::Store(StoreError::Io(e.to_string())))? = Some(progress.clone());
    let worker = app.clone();
    std::thread::spawn(move || {
        run_worker(
            worker,
            session,
            view.scope,
            receiver_confirmed,
            run_id,
            stop,
            net,
        )
    });
    Ok(progress)
}

fn run_worker(
    app: AppHandle,
    session: String,
    scope: calm_domain::Scope,
    receiver_confirmed: bool,
    run_id: String,
    stop: calm_orchestrator::probe::StopFlag,
    first_network: Option<calm_domain::NetworkBinding>,
) {
    use calm_orchestrator::probe::{SystemClock, TcpConnector};
    let assess_state = app.state::<assess::AssessState>();
    let store_state = app.state::<StoreState>();
    // The network is re-read at most every 5 s while probing.
    let mut network = first_network;
    let mut read_at = std::time::Instant::now();
    let run = calm_orchestrator::checks::run_checks(
        run_id,
        &scope,
        receiver_confirmed,
        |req| {
            if read_at.elapsed() >= std::time::Duration::from_secs(5) {
                network = binding_blocking(&app);
                read_at = std::time::Instant::now();
            }
            let revoked = with_store(&store_state, |s| {
                s.has_event(&session, calm_store::AuditAction::ScopeRevoked, &scope.id)
            })
            // If the store cannot answer, treat the scope as revoked.
            .unwrap_or(true);
            calm_orchestrator::authorize(Some(&scope), revoked, req, now_ms(), network.as_ref())
        },
        &TcpConnector,
        &SystemClock,
        &stop,
        |done, total, rec| {
            let rec = rec.clone();
            assess_state.update(|p| {
                p.done = done;
                p.total = total;
                p.last = Some(rec);
            })
        },
    );
    let stored = with_store(&store_state, |s| {
        assess::record_run(s, &session, &run, now_ms())
    });
    assess_state.update(|p| {
        p.running = false;
        p.stopped = run.stopped;
        match stored {
            Ok(id) => p.snapshot_id = Some(id),
            Err(e) => p.error = Some(format!("{e:?}")),
        }
    });
}

#[tauri::command]
fn checks_status(assess_state: State<'_, assess::AssessState>) -> Option<assess::Progress> {
    assess_state.progress.lock().ok().and_then(|p| p.clone())
}

/// Emergency Stop (feature A): cancels pending probes and stops the capture.
#[tauri::command]
fn emergency_stop(
    assess_state: State<'_, assess::AssessState>,
    capture: State<'_, CaptureState>,
    state: State<'_, StoreState>,
) -> Result<(), String> {
    assess_state.emergency_stop();
    if let Ok(mut slot) = capture.0.lock() {
        if let Some(c) = slot.as_mut() {
            c.stop();
        }
    }
    let running = assess_state.running();
    if let (Some(session), false) = (state.active_id(), running) {
        // A run in progress audits the stop itself when it ends.
        let _ = with_store(&state, |s| {
            s.audit(
                &session,
                calm_store::AuditAction::EmergencyStop,
                "manual",
                now_ms(),
            )
        });
    }
    Ok(())
}

#[tauri::command]
fn findings_list(state: State<'_, StoreState>) -> Result<Vec<assess::StoredRun>, StoreError> {
    let Some(session) = state.active_id() else {
        return Ok(Vec::new());
    };
    with_store(&state, |s| assess::list_runs(s, &session))
}

/// The UI tells the shell whether "save on stop or quit" is on.
#[tauri::command]
fn capture_set_autosave(autosave: State<'_, quit::AutoSave>, enabled: bool) {
    autosave
        .0
        .store(enabled, std::sync::atomic::Ordering::SeqCst);
}

/// Called on a quit request: should the running capture be saved first?
fn quit_check(app: &AppHandle) -> quit::QuitCheck {
    let (running, packets) = app
        .state::<CaptureState>()
        .0
        .lock()
        .ok()
        .and_then(|s| {
            s.as_ref()
                .map(|c| (c.is_running(), c.view(0).snapshot.total_packets))
        })
        .unwrap_or((false, 0));
    let store = app.state::<StoreState>();
    quit::QuitCheck {
        autosave: app
            .state::<quit::AutoSave>()
            .0
            .load(std::sync::atomic::Ordering::SeqCst),
        capture_running: running,
        packets,
        store_ready: store.status(None, 0).state == "ready",
        has_active_session: store.active_id().is_some(),
    }
}

/// Stops the capture, saves it, then exits. Quitting never hangs on storage:
/// a watchdog exits after 10 s whatever happens.
async fn save_then_exit(app: AppHandle) {
    let watchdog = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(10));
        watchdog.exit(0);
    });
    let base = {
        let mut label = records::live_label(None);
        if let Ok(mut slot) = app.state::<CaptureState>().0.lock() {
            if let Some(c) = slot.as_mut() {
                c.stop();
                let v = c.view(0);
                label = records::live_label(Some((v.snapshot.total_flows, v.elapsed_ms)));
            }
        }
        label
    };
    let _ = save_live_now(&app, Some(quit::quit_label(&base))).await;
    app.exit(0);
}

/// Saves the imported file's results (not the file) into the active session.
#[tauri::command]
fn snapshot_save_import(
    state: State<'_, StoreState>,
    imported: State<'_, ImportState>,
    label: Option<String>,
) -> Result<SnapshotSummary, StoreError> {
    let rec = imported
        .0
        .lock()
        .map_err(|e| StoreError::Io(e.to_string()))?
        .as_ref()
        .map(Imported::record)
        .ok_or(StoreError::NotFound)?;
    let label = label
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| records::import_label(&rec.file_name));
    state.save(SnapshotKind::Import, &label, &rec, now_ms())
}

#[tauri::command]
fn snapshot_open(state: State<'_, StoreState>, id: String) -> Result<RecordedView, StoreError> {
    state.open_snapshot(&id)
}

#[tauri::command]
fn snapshot_delete(state: State<'_, StoreState>, id: String) -> Result<(), StoreError> {
    with_store(&state, |s| s.delete_snapshot(&id, now_ms()))
}

// ---- Graph and flows for a source + time window (M1: FR-005, timeline) ----

const NODE_FLOW_LIMIT: usize = 200;

impl Imported {
    fn source(&self) -> source::SourceData {
        source::SourceData {
            base: source::Base::Import(Box::new(self.summary.clone())),
            flows: self.table.all_flows(),
            bindings: self.table.bindings(),
        }
    }
}

impl StoreState {
    /// A saved snapshot as a source (decrypted on demand, never cached).
    fn saved_source(&self, snapshot_id: &str) -> Result<source::SourceData, StoreError> {
        with_store(self, |s| {
            Ok(match s.snapshot_kind(snapshot_id)? {
                SnapshotKind::Live => {
                    let (_, r): (_, LiveRecord) = s.get_snapshot(snapshot_id)?;
                    source::SourceData {
                        base: source::Base::Profile(Box::new(r.profile)),
                        flows: r.capture.map(|c| c.snapshot.flows).unwrap_or_default(),
                        bindings: r.bindings,
                    }
                }
                SnapshotKind::Import => {
                    let (_, r): (_, ImportRecord) = s.get_snapshot(snapshot_id)?;
                    source::SourceData {
                        base: source::Base::Import(Box::new(r.summary)),
                        flows: r.snapshot.flows,
                        bindings: r.bindings,
                    }
                }
                SnapshotKind::Scope | SnapshotKind::Findings => return Err(StoreError::NotFound),
            })
        })
    }
}

async fn resolve_source(
    app: &AppHandle,
    src: &source::SourceRef,
    need_graph: bool,
    capture: &CaptureState,
    imported: &ImportState,
    store: &StoreState,
) -> Result<source::SourceData, String> {
    match src {
        source::SourceRef::Live => {
            // The profile is only needed to draw the graph; selecting flows
            // (polled while capturing) must stay cheap.
            let base = if need_graph {
                source::Base::Profile(Box::new(on_main(app, calm_net_profile::collect).await?))
            } else {
                source::Base::FlowsOnly
            };
            let (flows, bindings) = capture
                .0
                .lock()
                .map_err(|e| e.to_string())?
                .as_ref()
                .map(|c| c.flows_and_bindings())
                .unwrap_or_default();
            Ok(source::SourceData {
                base,
                flows,
                bindings,
            })
        }
        source::SourceRef::Imported => imported
            .0
            .lock()
            .map_err(|e| e.to_string())?
            .as_ref()
            .map(Imported::source)
            .ok_or_else(|| "no imported file".to_owned()),
        source::SourceRef::Saved { snapshot_id } => {
            store.saved_source(snapshot_id).map_err(|e| e.to_string())
        }
    }
}

/// The graph of a source, optionally limited to flows active in `window`.
#[tauri::command]
async fn graph_view(
    app: AppHandle,
    capture: State<'_, CaptureState>,
    imported: State<'_, ImportState>,
    store: State<'_, StoreState>,
    source: source::SourceRef,
    window: Option<calm_flow_engine::select::TimeWindow>,
) -> Result<source::GraphView, String> {
    let d = resolve_source(&app, &source, true, &capture, &imported, &store).await?;
    Ok(d.graph(window))
}

/// Flows behind one node (or all, or the external node) of a source.
#[tauri::command]
async fn flows_for(
    app: AppHandle,
    capture: State<'_, CaptureState>,
    imported: State<'_, ImportState>,
    store: State<'_, StoreState>,
    source: source::SourceRef,
    filter: calm_flow_engine::select::FlowFilter,
    window: Option<calm_flow_engine::select::TimeWindow>,
) -> Result<calm_flow_engine::select::FlowSelection, String> {
    let d = resolve_source(&app, &source, false, &capture, &imported, &store).await?;
    Ok(d.select(&filter, window, NODE_FLOW_LIMIT))
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(CaptureState::default())
        .manage(ImportState::default())
        .manage(StoreState::default())
        .manage(quit::AutoSave::default())
        .manage(quit::Quitting::default())
        .manage(assess::AssessState::default())
        .invoke_handler(tauri::generate_handler![
            app_info,
            location_status,
            request_location,
            network_profile,
            network_overview,
            capture_probe,
            capture_start,
            capture_stop,
            capture_view,
            import_pick,
            import_view,
            import_clear,
            store_status,
            store_open,
            store_set_aside_unreadable,
            session_list,
            session_create,
            session_update,
            session_delete,
            session_activate,
            snapshot_list,
            snapshot_save_live,
            snapshot_save_import,
            snapshot_open,
            snapshot_delete,
            graph_view,
            flows_for,
            capture_set_autosave,
            scope_network,
            scope_list,
            scope_approve,
            scope_revoke,
            checks_preflight,
            checks_run,
            checks_status,
            emergency_stop,
            findings_list
        ])
        .build(tauri::generate_context!())
        .expect("error while building Calm");
    app.run(|handle, event| {
        // A user quit (Cmd+Q, last window closed) has no exit code; our own
        // app.exit(0) after saving has one and goes straight through.
        if let tauri::RunEvent::ExitRequested {
            code: None, api, ..
        } = event
        {
            if quit::should_save(quit_check(handle)) && handle.state::<quit::Quitting>().begin() {
                api.prevent_exit();
                tauri::async_runtime::spawn(save_then_exit(handle.clone()));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_fixture_from_disk_is_contained_and_hashed() {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/pcap");
        let ok = load_capture_file(&dir.join("guest-sample.pcapng"))
            .ok()
            .unwrap();
        assert_eq!(ok.sha256.len(), 64);
        assert!(ok.summary.error.is_none());
        assert!(ok
            .graph
            .nodes
            .iter()
            .any(|n| n.id == calm_graph_engine::CAPTURE_HOST));
        let cut = load_capture_file(&dir.join("guest-sample-truncated.pcapng"))
            .ok()
            .unwrap();
        assert!(cut.summary.error.is_some(), "partial result, flagged");
        let not = load_capture_file(&dir.join("guest-sample.golden.json"));
        assert!(matches!(not, Err(ImportError::NotACapture)));
    }

    mod storage {
        use super::super::*;
        use calm_store::{Key, StaticKey};

        fn input(name: &str) -> SessionInput {
            SessionInput {
                meta: SessionMeta {
                    name: name.into(),
                    ..Default::default()
                },
                retention_days: Some(30),
            }
        }

        fn opened(dir: &tempfile::TempDir, k: u8) -> (StoreState, PathBuf) {
            let st = StoreState::default();
            let path = dir.path().join("calm.sqlite3");
            st.open_at(&path, &StaticKey(Key::from_bytes([k; 32])), 0);
            (st, path)
        }

        #[test]
        fn status_reflects_slot_and_active_session() {
            let st = StoreState::default();
            assert_eq!(st.status(None, 0).state, "closed");
            let dir = tempfile::tempdir().unwrap();
            let (st, _) = opened(&dir, 1);
            let s = st.create_session(&input("a"), 0).unwrap();
            let v = st.status(Some("p".into()), 2);
            assert_eq!(v.state, "ready");
            assert_eq!(v.purged_on_open, 2);
            assert_eq!(v.active_session.map(|x| x.id), Some(s.id));
            let failed = StoreState::default();
            failed.open_at(
                &dir.path().join("calm.sqlite3"),
                &calm_store::keys::NoKey("denied".into()),
                0,
            );
            let v = failed.status(None, 0);
            assert_eq!(v.state, "error");
            assert_eq!(v.error, Some(StoreError::KeyUnavailable("denied".into())));
        }

        #[test]
        fn active_session_survives_relaunch() {
            let dir = tempfile::tempdir().unwrap();
            let id = {
                let (st, _) = opened(&dir, 1);
                st.create_session(&input("a"), 0).unwrap().id
            };
            // A new StoreState is a new app launch.
            let (st, _) = opened(&dir, 1);
            assert_eq!(st.active_id(), Some(id.clone()));
            assert!(
                st.save(SnapshotKind::Live, "x", &1, 1).is_ok(),
                "save works right away"
            );
            st.activate(None).unwrap();
            let (st2, _) = opened(&dir, 1);
            assert_eq!(st2.active_id(), None);
        }

        #[test]
        fn saved_snapshots_are_sources_for_graph_and_flows() {
            use calm_flow_engine::select::FlowFilter;
            let dir = tempfile::tempdir().unwrap();
            let (st, _) = opened(&dir, 1);
            st.create_session(&input("a"), 0).unwrap();
            let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../fixtures/pcap/guest-sample.pcapng");
            let imported = load_capture_file(&fx).ok().unwrap();
            let snap = st
                .save(SnapshotKind::Import, "f", &imported.record(), 0)
                .unwrap();
            let saved = st.saved_source(&snap.id).unwrap();
            let live_like = imported.source();
            assert_eq!(
                saved.flows.len(),
                live_like.flows.len(),
                "every flow kept in the snapshot"
            );
            assert_eq!(
                saved.graph(None).graph.nodes.len(),
                imported.graph.nodes.len()
            );
            assert_eq!(
                saved.select(&FlowFilter::All, None, 5).total,
                live_like.select(&FlowFilter::All, None, 5).total
            );
            assert!(st.saved_source("missing").is_err());
        }

        #[test]
        fn closed_store_refuses_work() {
            let st = StoreState::default();
            assert!(matches!(
                st.create_session(&input("x"), 0),
                Err(StoreError::Io(_))
            ));
        }

        #[test]
        fn open_is_idempotent() {
            let dir = tempfile::tempdir().unwrap();
            let (st, path) = opened(&dir, 1);
            st.create_session(&input("a"), 0).unwrap();
            // A second open with another key must not replace the open store.
            st.open_at(&path, &StaticKey(Key::from_bytes([9; 32])), 0);
            assert_eq!(with_store(&st, |s| s.list_sessions()).unwrap().len(), 1);
        }

        #[test]
        fn create_activates_and_delete_deactivates() {
            let dir = tempfile::tempdir().unwrap();
            let (st, _) = opened(&dir, 1);
            let s = st.create_session(&input("a"), 0).unwrap();
            assert_eq!(st.active_id(), Some(s.id.clone()));
            let other = st.create_session(&input("b"), 0).unwrap();
            st.delete_session(&s.id, 1).unwrap();
            assert_eq!(
                st.active_id(),
                Some(other.id.clone()),
                "deleting another session keeps the active one"
            );
            st.delete_session(&other.id, 1).unwrap();
            assert_eq!(st.active_id(), None);
        }

        #[test]
        fn saving_needs_an_active_session() {
            let dir = tempfile::tempdir().unwrap();
            let (st, _) = opened(&dir, 1);
            assert_eq!(
                st.save(SnapshotKind::Live, "x", &1, 0).err(),
                Some(StoreError::NotFound)
            );
            let s = st.create_session(&input("a"), 0).unwrap();
            st.activate(None).unwrap();
            assert!(st.save(SnapshotKind::Live, "x", &1, 0).is_err());
            st.activate(Some(s.id.clone())).unwrap();
            assert!(st.save(SnapshotKind::Live, "x", &1, 0).is_ok());
            assert!(st.activate(Some("missing".into())).is_err());
        }

        #[test]
        fn saved_import_opens_as_import_view() {
            let dir = tempfile::tempdir().unwrap();
            let (st, _) = opened(&dir, 1);
            st.create_session(&input("a"), 0).unwrap();
            let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../fixtures/pcap/guest-sample.pcapng");
            let imported = load_capture_file(&fx).ok().unwrap();
            let snap = st
                .save(SnapshotKind::Import, "file", &imported.record(), 0)
                .unwrap();
            let v = st.open_snapshot(&snap.id).unwrap();
            assert!(v.live.is_none());
            let iv = v.import.unwrap();
            assert_eq!(iv.file_name, "guest-sample.pcapng");
            assert_eq!(iv.sha256, imported.sha256);
            assert!(iv
                .graph
                .nodes
                .iter()
                .any(|n| n.id == calm_graph_engine::CAPTURE_HOST));
        }

        #[test]
        fn wrong_key_fails_then_set_aside_starts_fresh() {
            let dir = tempfile::tempdir().unwrap();
            {
                let (st, _) = opened(&dir, 1);
                st.create_session(&input("old"), 0).unwrap();
            }
            let (st, path) = opened(&dir, 2);
            assert!(matches!(
                st.create_session(&input("x"), 0),
                Err(StoreError::KeyMismatch)
            ));
            let aside = st.set_aside(&path, 5).unwrap();
            assert!(aside.exists(), "old database kept, not deleted");
            assert!(!path.exists());
            st.open_at(&path, &StaticKey(Key::from_bytes([2; 32])), 6);
            assert!(st.create_session(&input("new"), 6).is_ok());
            assert!(
                st.set_aside(&path, 7).is_err(),
                "a readable store is never set aside"
            );
        }
    }

    #[test]
    fn at02_launch_is_passive() {
        let info = app_info_value();
        assert_eq!(info.mode, "passive");
        assert!(!info.active_scanning_enabled);
    }
}
