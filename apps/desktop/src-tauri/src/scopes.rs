//! Scope grants of a session (M2.1): approve, list, revoke.
//!
//! A scope is written once as a sealed `scope` record and never changed.
//! Revoking records an audit event; a session has at most one usable scope
//! at a time, so a new one requires revoking the current one first.

use calm_domain::{NetworkBinding, Scope};
use calm_orchestrator::scope::{approve as approve_draft, DraftError, ScopeDraft};
use calm_store::{AuditAction, SnapshotKind, Store, StoreError};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScopeView {
    pub scope: Scope,
    pub revoked: bool,
    pub expired: bool,
}

impl ScopeView {
    /// Usable for probes, as far as time and revocation go (network is
    /// checked separately, per probe).
    pub fn usable(&self) -> bool {
        !self.revoked && !self.expired
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum ScopeError {
    Invalid(Vec<DraftError>),
    /// Revoke the current scope before approving another one.
    ActiveExists,
    NoActiveSession,
    Store(StoreError),
}

impl From<StoreError> for ScopeError {
    fn from(e: StoreError) -> Self {
        ScopeError::Store(e)
    }
}

/// All scopes of a session, newest first.
pub fn list(store: &Store, session_id: &str, now_ms: i64) -> Result<Vec<ScopeView>, StoreError> {
    let mut out = Vec::new();
    for s in store.list_snapshots(session_id)? {
        if s.kind != SnapshotKind::Scope {
            continue;
        }
        let (_, scope): (_, Scope) = store.get_snapshot(&s.id)?;
        let revoked = store.has_event(session_id, AuditAction::ScopeRevoked, &scope.id)?;
        out.push(ScopeView {
            expired: now_ms >= scope.expires_at_ms,
            revoked,
            scope,
        });
    }
    Ok(out)
}

/// The scope probes may use now, if any.
pub fn current(
    store: &Store,
    session_id: &str,
    now_ms: i64,
) -> Result<Option<ScopeView>, StoreError> {
    Ok(list(store, session_id, now_ms)?
        .into_iter()
        .find(ScopeView::usable))
}

pub fn approve(
    store: &Store,
    session_id: &str,
    draft: &ScopeDraft,
    network: Option<NetworkBinding>,
    now_ms: i64,
) -> Result<ScopeView, ScopeError> {
    if current(store, session_id, now_ms)?.is_some() {
        return Err(ScopeError::ActiveExists);
    }
    let id = calm_store::new_id()?;
    let scope = approve_draft(draft, id, session_id.to_owned(), network, now_ms)
        .map_err(ScopeError::Invalid)?;
    store.put_snapshot(
        session_id,
        SnapshotKind::Scope,
        &scope.authorization_reference,
        &scope,
        now_ms,
    )?;
    store.audit(session_id, AuditAction::ScopeApproved, &scope.id, now_ms)?;
    Ok(ScopeView {
        scope,
        revoked: false,
        expired: false,
    })
}

pub fn revoke(
    store: &Store,
    session_id: &str,
    scope_id: &str,
    now_ms: i64,
) -> Result<(), StoreError> {
    if !list(store, session_id, now_ms)?
        .iter()
        .any(|v| v.scope.id == scope_id)
    {
        return Err(StoreError::NotFound);
    }
    if !store.has_event(session_id, AuditAction::ScopeRevoked, scope_id)? {
        store.audit(session_id, AuditAction::ScopeRevoked, scope_id, now_ms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use calm_domain::TargetRole;
    use calm_orchestrator::scope::TargetDraft;
    use calm_store::{Key, SessionMeta};

    const NOW: i64 = 1_800_000_000_000;
    const HOUR: i64 = 3_600_000;

    fn store_with_session() -> (Store, String) {
        let st = Store::open_in_memory(Key::from_bytes([3; 32])).unwrap();
        let meta = SessionMeta {
            name: "M2".into(),
            site: String::new(),
            operator: "Andy".into(),
            authorization_ref: String::new(),
            notes: String::new(),
        };
        let s = st.create_session(&meta, None, NOW).unwrap();
        (st, s.id)
    }

    fn net() -> NetworkBinding {
        NetworkBinding {
            gateway: "192.168.68.1".into(),
            subnet: Some("192.168.68.0/22".into()),
            ssid: None,
        }
    }

    fn draft() -> ScopeDraft {
        ScopeDraft {
            authorization_reference: "ROE-1".into(),
            operator: "Andy".into(),
            granted_by: "Owner".into(),
            targets: vec![TargetDraft {
                address: "192.168.68.1".into(),
                ports: vec![443],
                role: TargetRole::AdminInterface,
                label: String::new(),
            }],
            expires_at_ms: NOW + 2 * HOUR,
            max_probes_per_second: 5,
            timeout_ms: 3000,
            authorization_confirmed: true,
            vantage: Some(calm_domain::NetworkPosition::Guest),
            ..Default::default()
        }
    }

    #[test]
    fn approve_stores_audits_and_becomes_current() {
        let (st, sid) = store_with_session();
        assert_eq!(current(&st, &sid, NOW).unwrap(), None);
        let v = approve(&st, &sid, &draft(), Some(net()), NOW).unwrap();
        assert_eq!(v.scope.id.len(), 32);
        let cur = current(&st, &sid, NOW + 1).unwrap().expect("current");
        assert_eq!(cur.scope, v.scope);
        assert!(st
            .has_event(&sid, AuditAction::ScopeApproved, &v.scope.id)
            .unwrap());
        // Scopes are not listed as traffic snapshots by the shell; the store has them.
        assert_eq!(
            st.list_snapshots(&sid).unwrap()[0].kind,
            SnapshotKind::Scope
        );
    }

    #[test]
    fn invalid_drafts_store_nothing() {
        let (st, sid) = store_with_session();
        let mut d = draft();
        d.authorization_confirmed = false;
        let e = approve(&st, &sid, &d, Some(net()), NOW).unwrap_err();
        assert_eq!(e, ScopeError::Invalid(vec![DraftError::NotConfirmed]));
        assert!(st.list_snapshots(&sid).unwrap().is_empty());
        let e = approve(&st, &sid, &draft(), None, NOW).unwrap_err();
        assert_eq!(e, ScopeError::Invalid(vec![DraftError::NetworkUnknown]));
    }

    #[test]
    fn one_usable_scope_at_a_time_and_revoke_frees_the_slot() {
        let (st, sid) = store_with_session();
        let a = approve(&st, &sid, &draft(), Some(net()), NOW).unwrap();
        assert_eq!(
            approve(&st, &sid, &draft(), Some(net()), NOW + 1),
            Err(ScopeError::ActiveExists)
        );
        revoke(&st, &sid, &a.scope.id, NOW + 2).unwrap();
        revoke(&st, &sid, &a.scope.id, NOW + 3).unwrap(); // idempotent
        assert_eq!(current(&st, &sid, NOW + 4).unwrap(), None);
        let b = approve(&st, &sid, &draft(), Some(net()), NOW + 5).unwrap();
        let all = list(&st, &sid, NOW + 6).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].scope.id, b.scope.id, "newest first");
        assert!(all[1].revoked && !all[0].revoked);
        let revokes = st
            .events(&sid)
            .unwrap()
            .iter()
            .filter(|e| e.action == "scope_revoked")
            .count();
        assert_eq!(revokes, 1);
    }

    #[test]
    fn expiry_ends_a_scope_without_revoking_it() {
        let (st, sid) = store_with_session();
        let a = approve(&st, &sid, &draft(), Some(net()), NOW).unwrap();
        let later = a.scope.expires_at_ms;
        let v = &list(&st, &sid, later).unwrap()[0];
        assert!(v.expired && !v.revoked && !v.usable());
        assert_eq!(current(&st, &sid, later).unwrap(), None);
        assert!(
            approve(&st, &sid, &draft(), Some(net()), NOW + HOUR).is_err(),
            "still active then"
        );
    }

    #[test]
    fn revoking_an_unknown_scope_is_not_found() {
        let (st, sid) = store_with_session();
        assert_eq!(revoke(&st, &sid, "nope", NOW), Err(StoreError::NotFound));
    }
}
