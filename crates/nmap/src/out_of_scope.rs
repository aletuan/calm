//! Out-of-scope suite (ADR-011 validation).
//!
//! Every subset of capabilities × plan shapes that try to leave the scope.
//! Each plan the scope engine grants is run against a fake `nmap`, and the
//! arguments Nmap really received are checked by rules written here, apart
//! from the builder: a bug in `build_args` cannot hide itself.

use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::time::Duration;

use calm_domain::Capability;
use calm_orchestrator::scope::{parse_range, range_contains, NSE_ALLOWLIST};
use calm_orchestrator::RunPlan;

use crate::command::KNOWN_FLAGS;
use crate::runner::run;
use crate::test_support::{authorize, fake_nmap, scope};

/// Options that take a value in the next argument.
const VALUE_FLAGS: [&str; 8] = [
    "--dns-servers",
    "-e",
    "-p",
    "--script",
    "--max-rate",
    "--host-timeout",
    "--exclude",
    "-oX",
];

/// Never, whatever the scope says (ADR-011 §4, spike F2).
const FORBIDDEN: [&str; 11] = [
    "--send-ip",
    "-iL",
    "-iR",
    "--script-args",
    "--script-args-file",
    "--resume",
    "--datadir",
    "-oN",
    "-oG",
    "-oA",
    "--interactive",
];

fn subsets() -> Vec<Vec<Capability>> {
    (0u32..1 << Capability::ALL.len())
        .map(|bits| {
            Capability::ALL
                .iter()
                .enumerate()
                .filter(|(i, _)| bits & (1 << i) != 0)
                .map(|(_, c)| *c)
                .collect()
        })
        .collect()
}

/// Plan shapes, the well-formed ones and the ones that try to escape.
fn shapes(caps: &[Capability]) -> Vec<RunPlan> {
    let base = RunPlan {
        capabilities: caps.to_vec(),
        interface: "en0".into(),
        ..Default::default()
    };
    let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
    vec![
        RunPlan {
            targets: vec![ip("10.20.0.5")],
            ports: vec![443],
            ..base.clone()
        },
        RunPlan {
            ranges: vec!["192.168.68.0/24".into()],
            ports: vec![22],
            ..base.clone()
        },
        RunPlan {
            ranges: vec!["192.168.68.0/24".into()],
            ..base.clone()
        },
        RunPlan {
            targets: vec![ip("10.20.0.5")],
            ports: vec![80],
            scripts: vec!["http-title".into()],
            resolver: Some(ip("192.168.68.1")),
            ..base.clone()
        },
        // Escapes: excluded host, public host, wider range, bad interface,
        // public resolver, a script outside the allowlist.
        RunPlan {
            targets: vec![ip("192.168.68.50")],
            ports: vec![22],
            ..base.clone()
        },
        RunPlan {
            targets: vec![ip("1.1.1.1")],
            ports: vec![443],
            ..base.clone()
        },
        RunPlan {
            ranges: vec!["192.168.0.0/16".into()],
            ports: vec![22],
            ..base.clone()
        },
        RunPlan {
            targets: vec![ip("10.20.0.5")],
            ports: vec![443],
            interface: "-iL/etc/passwd".into(),
            resolver: Some(ip("8.8.8.8")),
            scripts: vec!["smb-brute".into()],
            ..base.clone()
        },
        RunPlan {
            targets: vec![ip("10.20.0.5")],
            ports: vec![22, 443],
            ..base
        },
    ]
}

/// The rules every argument list must satisfy, given what the plan asked for.
fn check(argv: &[String], plan: &RunPlan) {
    let caps: HashSet<Capability> = plan.capabilities.iter().copied().collect();
    let has = |f: &str| argv.iter().any(|a| a == f);
    let value = |f: &str| {
        argv.iter()
            .position(|a| a == f)
            .and_then(|i| argv.get(i + 1))
            .cloned()
    };
    let s = scope();

    for a in argv {
        assert!(
            !FORBIDDEN.contains(&a.as_str()),
            "forbidden {a} in {argv:?}"
        );
    }
    // Every option is one the builder may emit; collect the positional targets.
    let mut positional = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a.starts_with('-') && a != "-" {
            assert!(
                KNOWN_FLAGS.contains(&a.as_str()),
                "unknown option {a} in {argv:?}"
            );
            i += if VALUE_FLAGS.contains(&a.as_str()) {
                2
            } else {
                1
            };
        } else {
            positional.push(a.clone());
            i += 1;
        }
    }
    assert!(!positional.is_empty(), "no target in {argv:?}");

    // Always present.
    assert_eq!(value("-oX").as_deref(), Some("-"), "{argv:?}");
    assert_eq!(value("--max-rate").as_deref(), Some("5"), "{argv:?}");
    assert!(has("--host-timeout"), "{argv:?}");

    // Each traffic kind only with its capability.
    for (flag, cap) in [
        ("-sS", Capability::SynScan),
        ("-sV", Capability::ServiceDetection),
        ("-O", Capability::OsDetection),
        ("--script", Capability::Nse),
        ("--dns-servers", Capability::ReverseDns),
    ] {
        if has(flag) {
            assert!(caps.contains(&cap), "{flag} without {cap:?}: {argv:?}");
        }
    }
    if has("-sT") {
        assert!(caps.contains(&Capability::TcpConnect), "{argv:?}");
    }
    if !has("-n") {
        assert!(
            caps.contains(&Capability::ReverseDns),
            "DNS lookups without the capability: {argv:?}"
        );
    }
    if !has("-Pn") {
        assert!(
            caps.contains(&Capability::HostDiscovery),
            "discovery pings without the capability: {argv:?}"
        );
    }
    if has("--privileged") {
        assert!(caps.iter().any(|c| c.needs_raw_packets()), "{argv:?}");
        assert_eq!(value("-e").as_deref(), Some("en0"), "{argv:?}");
    }
    if let Some(r) = value("--dns-servers") {
        assert_eq!(r, "192.168.68.1", "{argv:?}");
    }
    if let Some(list) = value("--script") {
        for name in list.split(',') {
            assert!(
                NSE_ALLOWLIST.contains(&name) && s.nse_scripts.iter().any(|n| n == name),
                "{name}"
            );
        }
    }

    // Every target is in the scope and not excluded; every range inside one.
    let excluded: Vec<IpAddr> = s.exclusions.iter().map(|e| e.parse().unwrap()).collect();
    let ranges: Vec<_> = s
        .ranges
        .iter()
        .map(|r| parse_range(&r.cidr).unwrap())
        .collect();
    for p in positional {
        if let Some((net, prefix)) = parse_range(&p).filter(|_| p.contains('/')) {
            assert!(
                ranges
                    .iter()
                    .any(|o| prefix >= o.1 && range_contains(*o, IpAddr::V4(net))),
                "range {p} outside the scope"
            );
            // A range scan must skip every excluded host inside it.
            let skipped: Vec<IpAddr> = value("--exclude")
                .map(|l| l.split(',').map(|e| e.parse().unwrap()).collect())
                .unwrap_or_default();
            for e in excluded
                .iter()
                .filter(|e| range_contains((net, prefix), **e))
            {
                assert!(
                    skipped.contains(e),
                    "{p} would reach excluded {e}: {argv:?}"
                );
            }
        } else {
            let ip: IpAddr = p.parse().unwrap_or_else(|_| panic!("not an address: {p}"));
            assert!(!excluded.contains(&ip), "excluded {ip}");
            let literal = s
                .targets
                .iter()
                .any(|t| t.address.parse::<IpAddr>().ok() == Some(ip));
            assert!(
                literal || ranges.iter().any(|r| range_contains(*r, ip)),
                "{ip} outside the scope"
            );
        }
    }
}

#[test]
fn nothing_nmap_receives_leaves_the_scope() {
    let (dir, nmap) = fake_nmap("quick");
    let mut granted = 0;
    let mut denied = 0;
    for caps in subsets() {
        for plan in shapes(&caps) {
            let Some(grant) = authorize(&plan) else {
                denied += 1;
                continue;
            };
            granted += 1;
            run(&nmap, &grant, || None, Duration::from_millis(5)).unwrap();
            let argv: Vec<String> = fs::read_to_string(dir.path().join("argv"))
                .unwrap()
                .lines()
                .map(String::from)
                .collect();
            check(&argv, &plan);
        }
    }
    // The suite must exercise real runs and real refusals, not pass vacuously.
    assert!(granted >= 50, "only {granted} plans granted");
    assert!(denied >= 500, "only {denied} plans denied");
}

#[test]
fn the_escaping_shapes_are_never_granted() {
    for caps in subsets() {
        for plan in shapes(&caps).into_iter().skip(4).take(4) {
            assert!(authorize(&plan).is_none(), "{plan:?}");
        }
    }
}
