//! Test helpers: a fake `nmap` and a real grant from the scope engine.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use calm_domain::{Capability, NetworkBinding, NetworkPosition, Scope, TargetRole};
use calm_orchestrator::scope::{approve, RangeDraft, ScopeDraft, TargetDraft};
use calm_orchestrator::{authorize_plan, PlanGrant, RunPlan};
use tempfile::TempDir;

pub const NOW: i64 = 1_800_000_000_000;

pub fn net() -> NetworkBinding {
    NetworkBinding {
        gateway: "192.168.68.1".into(),
        subnet: Some("192.168.68.0/24".into()),
        ssid: None,
    }
}

/// Every capability, a literal admin target, a /24 range excluding .50, two scripts.
pub fn scope() -> Scope {
    let d = ScopeDraft {
        authorization_reference: "ROE".into(),
        operator: "A".into(),
        granted_by: "O".into(),
        targets: vec![TargetDraft {
            address: "10.20.0.5".into(),
            ports: vec![80, 443],
            role: TargetRole::AdminInterface,
            label: String::new(),
        }],
        expires_at_ms: NOW + 3_600_000,
        authorization_confirmed: true,
        vantage: Some(NetworkPosition::Guest),
        capabilities: Capability::ALL.to_vec(),
        ranges: vec![RangeDraft {
            cidr: "192.168.68.0/24".into(),
            ports: vec![22, 80, 443],
            label: String::new(),
        }],
        exclusions: vec!["192.168.68.50".into()],
        nse_scripts: vec!["http-title".into(), "ssl-cert".into()],
        ..Default::default()
    };
    approve(&d, "scope-1".into(), "s".into(), Some(net()), NOW).expect("valid scope")
}

pub fn authorize(p: &RunPlan) -> Option<PlanGrant> {
    authorize_plan(Some(&scope()), false, p, NOW + 1, Some(&net())).ok()
}

/// A TCP-connect grant on the literal target.
pub fn grant() -> PlanGrant {
    authorize(&RunPlan {
        targets: vec!["10.20.0.5".parse().unwrap()],
        ports: vec![443],
        capabilities: vec![Capability::TcpConnect],
        interface: "en0".into(),
        ..Default::default()
    })
    .expect("authorized")
}

/// A stand-in for Nmap. "quick" records its argv and environment and prints
/// XML; "slow" ignores SIGTERM, starts a child that inherits that, writes the
/// child's pid to `child` and waits, so only a group SIGKILL ends them. Commands use absolute paths: the runner clears the env.
pub fn fake_nmap(kind: &str) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let body = match kind {
        "quick" => {
            format!("printf '%s\\n' \"$@\" > {d}/argv\n/usr/bin/env > {d}/env\necho '<nmaprun/>'\n")
        }
        // TERM is ignored before the child starts, so the child ignores it
        // too: only the group SIGKILL ends both. "child" appears atomically
        // once both are set up (macOS may scan a new executable before it runs).
        "slow" => format!(
            "trap '' TERM\n/bin/sleep 30 &\necho $! > {d}/child.tmp\n/bin/mv {d}/child.tmp {d}/child\nwait\n"
        ),
        other => panic!("unknown fake {other}"),
    };
    let path = dir.path().join("nmap");
    fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    (dir, path)
}

/// Alive and not a zombie (a container's init may never reap orphans).
pub fn process_alive(pid: i32) -> bool {
    let out = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    let stat = String::from_utf8_lossy(&out.stdout);
    let stat = stat.trim();
    !stat.is_empty() && !stat.starts_with('Z')
}
