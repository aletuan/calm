//! M1.5 storage behaviour, written before the implementation (TDD).

use std::path::{Path, PathBuf};

use calm_store::keys::NoKey;
use calm_store::{
    AuditAction, Key, SessionMeta, SnapshotKind, StaticKey, Store, StoreError, SCHEMA_VERSION,
};
use serde_json::{json, Value};

const T0: i64 = 1_793_437_200_000; // 2026-10-31T09:00:00Z
const DAY: i64 = 86_400_000;

fn key(b: u8) -> Key {
    Key::from_bytes([b; 32])
}

fn meta(name: &str) -> SessionMeta {
    SessionMeta {
        name: name.into(),
        site: "Cafe Example, District 1".into(),
        operator: "Andy".into(),
        authorization_ref: "AUTH-2026-031".into(),
        notes: "guest network, lobby".into(),
    }
}

fn db(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("calm").join("calm.sqlite3")
}

fn open(path: &Path, k: u8, now: i64) -> Store {
    Store::open(path, &StaticKey(key(k)), now).expect("open").0
}

/// Every byte Calm left on disk for this database.
fn disk_bytes(path: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{suffix}", path.display()));
        if let Ok(b) = std::fs::read(p) {
            all.extend(b);
        }
    }
    all
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn session_round_trip_and_listing_order() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let a = s.create_session(&meta("first"), Some(30), T0).unwrap();
    let b = s.create_session(&meta("second"), None, T0 + 1000).unwrap();
    assert_ne!(a.id, b.id);
    assert_eq!(s.get_session(&a.id).unwrap().meta, meta("first"));
    assert_eq!(s.get_session(&a.id).unwrap().retention_days, Some(30));
    let names: Vec<_> = s
        .list_sessions()
        .unwrap()
        .into_iter()
        .map(|x| x.meta.name)
        .collect();
    assert_eq!(names, ["second", "first"], "newest first");
}

#[test]
fn update_session_changes_meta_and_retention() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let a = s.create_session(&meta("old"), Some(7), T0).unwrap();
    let u = s.update_session(&a.id, &meta("new"), None, T0 + 5).unwrap();
    assert_eq!(u.meta.name, "new");
    assert_eq!(u.retention_days, None);
    assert_eq!(u.updated_at_ms, T0 + 5);
    assert_eq!(
        s.update_session("nope", &meta("x"), None, T0),
        Err(StoreError::NotFound)
    );
}

#[test]
fn snapshot_round_trip_counts_and_sizes() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let sess = s.create_session(&meta("s"), None, T0).unwrap();
    let payload = json!({"ssid": "GuestNet", "flows": [1, 2, 3]});
    let snap = s
        .put_snapshot(
            &sess.id,
            SnapshotKind::Live,
            "lobby, 10:00",
            &payload,
            T0 + 10,
        )
        .unwrap();
    assert_eq!(snap.kind, SnapshotKind::Live);
    assert!(snap.size_bytes > 0);
    let (sum, back): (_, Value) = s.get_snapshot(&snap.id).unwrap();
    assert_eq!(back, payload);
    assert_eq!(sum.label, "lobby, 10:00");
    let after = s.get_session(&sess.id).unwrap();
    assert_eq!(after.snapshot_count, 1);
    assert_eq!(after.stored_bytes, snap.size_bytes);
    assert_eq!(after.updated_at_ms, T0 + 10, "saving touches the session");
    s.put_snapshot(&sess.id, SnapshotKind::Import, "file", &json!(1), T0 + 20)
        .unwrap();
    let labels: Vec<_> = s
        .list_snapshots(&sess.id)
        .unwrap()
        .into_iter()
        .map(|x| x.label)
        .collect();
    assert_eq!(labels, ["file", "lobby, 10:00"]);
}

#[test]
fn snapshot_into_missing_session_is_not_found() {
    let s = Store::open_in_memory(key(1)).unwrap();
    assert_eq!(
        s.put_snapshot("missing", SnapshotKind::Live, "x", &json!(1), T0)
            .err(),
        Some(StoreError::NotFound)
    );
    assert_eq!(
        s.get_snapshot::<Value>("missing").err(),
        Some(StoreError::NotFound)
    );
}

#[test]
fn wrong_payload_type_is_corrupt_not_panic() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let sess = s.create_session(&meta("s"), None, T0).unwrap();
    let snap = s
        .put_snapshot(&sess.id, SnapshotKind::Live, "x", &json!("a string"), T0)
        .unwrap();
    assert!(matches!(
        s.get_snapshot::<Vec<u32>>(&snap.id),
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn no_network_data_in_clear_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    {
        let s = open(&path, 1, T0);
        let sess = s
            .create_session(&meta("Secret-Session-Name"), Some(30), T0)
            .unwrap();
        s.put_snapshot(
            &sess.id,
            SnapshotKind::Live,
            "Secret-Label",
            &json!({"ssid": "SecretNet-SSID", "peer": "192.0.2.77", "mac": "02:ca:1d:00:01:08"}),
            T0,
        )
        .unwrap();
        s.put_snapshot(
            &sess.id,
            SnapshotKind::Import,
            "secret-capture.pcapng",
            &json!({"sha256": "abc123def456"}),
            T0,
        )
        .unwrap();
    }
    let bytes = disk_bytes(&path);
    assert!(!bytes.is_empty());
    for needle in [
        "Secret-Session-Name",
        "Cafe Example",
        "AUTH-2026-031",
        "Secret-Label",
        "SecretNet-SSID",
        "192.0.2.77",
        "02:ca:1d",
        "secret-capture",
        "abc123def456",
    ] {
        assert!(!contains(&bytes, needle), "{needle} found in clear on disk");
    }
}

#[test]
fn reopen_with_same_key_reads_everything_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let id = {
        let s = open(&path, 1, T0);
        let sess = s.create_session(&meta("persist"), None, T0).unwrap();
        s.put_snapshot(&sess.id, SnapshotKind::Live, "l", &json!({"a": 1}), T0)
            .unwrap();
        sess.id
    };
    let s = open(&path, 1, T0 + 1);
    assert_eq!(s.get_session(&id).unwrap().meta.name, "persist");
    let snaps = s.list_snapshots(&id).unwrap();
    let (_, v): (_, Value) = s.get_snapshot(&snaps[0].id).unwrap();
    assert_eq!(v, json!({"a": 1}));
}

#[test]
fn different_master_key_refuses_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    open(&path, 1, T0)
        .create_session(&meta("x"), None, T0)
        .unwrap();
    let err = Store::open(&path, &StaticKey(key(2)), T0).err();
    assert_eq!(err, Some(StoreError::KeyMismatch));
}

#[test]
fn keychain_failure_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let err = Store::open(&db(&dir), &NoKey("user denied".into()), T0).err();
    assert_eq!(err, Some(StoreError::KeyUnavailable("user denied".into())));
}

#[test]
fn ciphertext_swapped_between_rows_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let (a, b) = {
        let s = open(&path, 1, T0);
        let sess = s.create_session(&meta("x"), None, T0).unwrap();
        let a = s
            .put_snapshot(&sess.id, SnapshotKind::Live, "a", &json!("A"), T0)
            .unwrap();
        let b = s
            .put_snapshot(&sess.id, SnapshotKind::Live, "b", &json!("B"), T0)
            .unwrap();
        (a.id, b.id)
    };
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        let blob_b: Vec<u8> = c
            .query_row("SELECT payload FROM snapshots WHERE id = ?1", [&b], |r| {
                r.get(0)
            })
            .unwrap();
        c.execute(
            "UPDATE snapshots SET payload = ?1 WHERE id = ?2",
            rusqlite::params![blob_b, a],
        )
        .unwrap();
    }
    let s = open(&path, 1, T0);
    assert!(matches!(
        s.get_snapshot::<Value>(&a),
        Err(StoreError::Corrupt(_))
    ));
    assert_eq!(s.get_snapshot::<Value>(&b).unwrap().1, json!("B"));
}

#[test]
fn delete_session_removes_data_and_key_and_zeroes_pages() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let s = open(&path, 1, T0);
    let keep = s.create_session(&meta("keep"), None, T0).unwrap();
    let gone = s.create_session(&meta("gone"), None, T0).unwrap();
    let snap = s
        .put_snapshot(
            &gone.id,
            SnapshotKind::Live,
            "x",
            &json!({"big": "y".repeat(5000)}),
            T0,
        )
        .unwrap();
    let blob: Vec<u8> = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT payload FROM snapshots WHERE id = ?1",
            [&snap.id],
            |r| r.get(0),
        )
        .unwrap();

    s.delete_session(&gone.id, T0 + 1).unwrap();
    assert_eq!(s.get_session(&gone.id), Err(StoreError::NotFound));
    assert_eq!(
        s.get_snapshot::<Value>(&snap.id).err(),
        Some(StoreError::NotFound)
    );
    assert_eq!(s.list_sessions().unwrap().len(), 1);
    assert_eq!(s.get_session(&keep.id).unwrap().meta.name, "keep");
    assert_eq!(s.delete_session(&gone.id, T0), Err(StoreError::NotFound));
    drop(s);

    let c = rusqlite::Connection::open(&path).unwrap();
    let keys: i64 = c
        .query_row(
            "SELECT count(*) FROM sessions WHERE id = ?1",
            [&gone.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(keys, 0, "wrapped data key deleted");
    drop(c);
    assert!(
        !disk_bytes(&path)
            .windows(64)
            .any(|w| w == &blob[blob.len() - 64..]),
        "freed pages no longer hold the old ciphertext"
    );
}

#[test]
fn delete_snapshot_only_removes_that_snapshot() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let sess = s.create_session(&meta("s"), None, T0).unwrap();
    let a = s
        .put_snapshot(&sess.id, SnapshotKind::Live, "a", &json!(1), T0)
        .unwrap();
    let b = s
        .put_snapshot(&sess.id, SnapshotKind::Live, "b", &json!(2), T0)
        .unwrap();
    s.delete_snapshot(&a.id, T0 + 3).unwrap();
    assert_eq!(s.list_snapshots(&sess.id).unwrap().len(), 1);
    assert_eq!(s.get_snapshot::<Value>(&b.id).unwrap().1, json!(2));
    assert_eq!(s.get_session(&sess.id).unwrap().snapshot_count, 1);
    assert_eq!(s.delete_snapshot(&a.id, T0), Err(StoreError::NotFound));
}

#[test]
fn retention_purges_only_expired_sessions() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let short = s.create_session(&meta("short"), Some(1), T0).unwrap();
    let long = s.create_session(&meta("long"), Some(30), T0).unwrap();
    let forever = s.create_session(&meta("forever"), None, T0).unwrap();
    assert_eq!(s.purge_expired(T0 + DAY - 1).unwrap(), 0, "not yet");
    assert_eq!(s.purge_expired(T0 + DAY + 1).unwrap(), 1);
    assert_eq!(s.get_session(&short.id), Err(StoreError::NotFound));
    assert!(s.get_session(&long.id).is_ok());
    assert!(s.get_session(&forever.id).is_ok());
    assert_eq!(
        s.purge_expired(T0 + 10_000 * DAY).unwrap(),
        1,
        "long expires, forever stays"
    );
    assert!(s.get_session(&forever.id).is_ok());
}

#[test]
fn retention_counts_from_last_change() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let a = s.create_session(&meta("a"), Some(1), T0).unwrap();
    s.put_snapshot(&a.id, SnapshotKind::Live, "x", &json!(1), T0 + DAY - 10)
        .unwrap();
    assert_eq!(s.purge_expired(T0 + DAY + 10).unwrap(), 0);
}

#[test]
fn open_purges_expired_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    open(&path, 1, T0)
        .create_session(&meta("x"), Some(1), T0)
        .unwrap();
    let (s, report) = Store::open(&path, &StaticKey(key(1)), T0 + 2 * DAY).unwrap();
    assert_eq!(report.purged, 1);
    assert!(s.list_sessions().unwrap().is_empty());
}

#[test]
fn audit_events_have_no_network_data_and_survive_deletion() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let sess = s.create_session(&meta("Secret-Name"), None, T0).unwrap();
    let snap = s
        .put_snapshot(
            &sess.id,
            SnapshotKind::Live,
            "Secret-Label",
            &json!(1),
            T0 + 1,
        )
        .unwrap();
    s.delete_snapshot(&snap.id, T0 + 2).unwrap();
    s.delete_session(&sess.id, T0 + 3).unwrap();
    let ev = s.events(&sess.id).unwrap();
    let actions: Vec<_> = ev.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "session_created",
            "snapshot_saved",
            "snapshot_deleted",
            "session_deleted"
        ]
    );
    let dump = serde_json::to_string(&ev).unwrap();
    assert!(!dump.contains("Secret"));
}

#[test]
fn schema_version_is_recorded_and_newer_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    drop(open(&path, 1, T0));
    let c = rusqlite::Connection::open(&path).unwrap();
    let v: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, SCHEMA_VERSION);
    c.execute_batch("PRAGMA user_version = 99").unwrap();
    drop(c);
    assert_eq!(
        Store::open(&path, &StaticKey(key(1)), T0).err(),
        Some(StoreError::UnsupportedSchema(99))
    );
}

#[cfg(unix)]
#[test]
fn database_file_and_folder_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    drop(open(&path, 1, T0));
    let f = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    let d = std::fs::metadata(path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(f, 0o600);
    assert_eq!(d, 0o700);
}

#[test]
fn ids_are_unguessable_hex() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let a = s.create_session(&meta("a"), None, T0).unwrap();
    assert_eq!(a.id.len(), 32);
    assert!(a.id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn expiry_is_audited_as_expired() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let a = s.create_session(&meta("a"), Some(1), T0).unwrap();
    s.purge_expired(T0 + 2 * DAY).unwrap();
    let last = s.events(&a.id).unwrap().pop().unwrap();
    assert_eq!(last.action, "session_expired");
    assert_eq!(last.at_ms, T0 + 2 * DAY);
}

#[test]
fn data_key_swapped_between_sessions_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let (a, b) = {
        let s = open(&path, 1, T0);
        (
            s.create_session(&meta("a"), None, T0).unwrap().id,
            s.create_session(&meta("b"), None, T0).unwrap().id,
        )
    };
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        let kb: Vec<u8> = c
            .query_row(
                "SELECT wrapped_key FROM sessions WHERE id = ?1",
                [&b],
                |r| r.get(0),
            )
            .unwrap();
        c.execute(
            "UPDATE sessions SET wrapped_key = ?1 WHERE id = ?2",
            rusqlite::params![kb, a],
        )
        .unwrap();
    }
    let s = open(&path, 1, T0);
    assert!(matches!(s.get_session(&a), Err(StoreError::Corrupt(_))));
    assert!(s.get_session(&b).is_ok());
}

#[test]
fn snapshot_kind_without_decrypting_payload() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let sess = s.create_session(&meta("s"), None, T0).unwrap();
    let a = s
        .put_snapshot(&sess.id, SnapshotKind::Import, "a", &json!(1), T0)
        .unwrap();
    assert_eq!(s.snapshot_kind(&a.id), Ok(SnapshotKind::Import));
    assert_eq!(s.snapshot_kind("missing"), Err(StoreError::NotFound));
}

#[test]
fn active_session_is_remembered_across_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let id = {
        let s = open(&path, 1, T0);
        assert_eq!(s.active_session().unwrap(), None);
        let a = s.create_session(&meta("a"), None, T0).unwrap();
        s.set_active_session(Some(&a.id)).unwrap();
        a.id
    };
    let s = open(&path, 1, T0 + 1);
    assert_eq!(s.active_session().unwrap(), Some(id.clone()));
    s.set_active_session(None).unwrap();
    assert_eq!(s.active_session().unwrap(), None);
    assert_eq!(
        s.set_active_session(Some("missing")),
        Err(StoreError::NotFound)
    );
}

#[test]
fn deleting_or_expiring_the_active_session_clears_it() {
    let s = Store::open_in_memory(key(1)).unwrap();
    let a = s.create_session(&meta("a"), Some(1), T0).unwrap();
    let b = s.create_session(&meta("b"), None, T0).unwrap();
    s.set_active_session(Some(&b.id)).unwrap();
    s.delete_session(&a.id, T0).unwrap();
    assert_eq!(
        s.active_session().unwrap(),
        Some(b.id.clone()),
        "other session kept"
    );
    s.delete_session(&b.id, T0).unwrap();
    assert_eq!(s.active_session().unwrap(), None);
    let c = s.create_session(&meta("c"), Some(1), T0).unwrap();
    s.set_active_session(Some(&c.id)).unwrap();
    s.purge_expired(T0 + 2 * DAY).unwrap();
    assert_eq!(s.active_session().unwrap(), None);
}

#[test]
fn scope_and_findings_are_sealed_like_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let st = open(&path, 7, T0);
    let s = st.create_session(&meta("M2"), None, T0).unwrap();
    let scope = json!({"targets": [{"address": "10.77.66.55", "ports": [443]}], "authorization_reference": "ROE-SECRET-77"});
    let sc = st
        .put_snapshot(&s.id, SnapshotKind::Scope, "scope", &scope, T0 + 1)
        .unwrap();
    let fi = st
        .put_snapshot(
            &s.id,
            SnapshotKind::Findings,
            "run",
            &json!({"tested": "10.77.66.55:443"}),
            T0 + 2,
        )
        .unwrap();
    assert_eq!(st.snapshot_kind(&sc.id).unwrap(), SnapshotKind::Scope);
    assert_eq!(st.snapshot_kind(&fi.id).unwrap(), SnapshotKind::Findings);
    let (_, back): (_, Value) = st.get_snapshot(&sc.id).unwrap();
    assert_eq!(back, scope);
    drop(st);
    let disk = disk_bytes(&path);
    assert!(
        !contains(&disk, "10.77.66.55"),
        "target address on disk in clear"
    );
    assert!(
        !contains(&disk, "ROE-SECRET-77"),
        "authorization reference on disk in clear"
    );
}

#[test]
fn audit_actions_are_recorded_by_id_only() {
    let dir = tempfile::tempdir().unwrap();
    let st = open(&db(&dir), 7, T0);
    let s = st.create_session(&meta("M2"), None, T0).unwrap();
    assert!(!st
        .has_event(&s.id, AuditAction::ScopeRevoked, "scope-1")
        .unwrap());
    st.audit(&s.id, AuditAction::ScopeApproved, "scope-1", T0 + 1)
        .unwrap();
    st.audit(&s.id, AuditAction::ProbeDenied, "job-1", T0 + 2)
        .unwrap();
    st.audit(&s.id, AuditAction::ScopeRevoked, "scope-1", T0 + 3)
        .unwrap();
    assert!(st
        .has_event(&s.id, AuditAction::ScopeRevoked, "scope-1")
        .unwrap());
    assert!(!st
        .has_event(&s.id, AuditAction::ScopeRevoked, "scope-2")
        .unwrap());
    let actions: Vec<String> = st
        .events(&s.id)
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(actions.ends_with(&[
        "scope_approved".into(),
        "probe_denied".into(),
        "scope_revoked".into()
    ]));
    assert!(matches!(
        st.audit("missing", AuditAction::EmergencyStop, "x", T0),
        Err(StoreError::NotFound)
    ));
}
