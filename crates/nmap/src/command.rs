//! Nmap argument list from a [`PlanGrant`] (ADR-011 §2–4).
//!
//! The grant is the only input: nothing a user typed reaches Nmap. Every value
//! is rendered from a parsed type (IP addresses, numbers, allowlisted script
//! names, a validated interface name), so no argument can start with "-"
//! unless this module put it there. Arguments are passed as argv, never
//! through a shell.

use calm_domain::Capability;
use calm_orchestrator::plan::HOST_TIMEOUT;
use calm_orchestrator::PlanGrant;

/// Options this module may ever emit. Used by tests as the oracle; anything
/// else in an argument list is a bug.
pub const KNOWN_FLAGS: [&str; 17] = [
    "-sT",
    "-sS",
    "-sn",
    "-sV",
    "-O",
    "-Pn",
    "-n",
    "--dns-servers",
    "--privileged",
    "--send-eth",
    "-e",
    "-p",
    "--script",
    "--max-rate",
    "--host-timeout",
    "--exclude",
    "-oX",
];

/// The argument list for one authorized run, without the program name.
pub fn build_args(g: &PlanGrant) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    let mut push = |s: &str| a.push(s.to_owned());

    // Scan type: exactly one when ports are scanned (checked by the grant).
    if g.has(Capability::SynScan) {
        push("-sS");
    } else if g.has(Capability::TcpConnect) {
        push("-sT");
    } else {
        push("-sn"); // host discovery only
    }
    if g.has(Capability::ServiceDetection) {
        push("-sV");
    }
    if g.has(Capability::OsDetection) {
        push("-O");
    }
    // Without discovery Nmap would ping first: TCP to 80/443, outside the plan.
    if !g.has(Capability::HostDiscovery) {
        push("-Pn");
    }
    // Without -n Nmap sends PTR lookups for every address.
    match g.resolver() {
        Some(r) => {
            push("--dns-servers");
            push(&r.to_string());
        }
        None => push("-n"),
    }
    // Raw packets go through BPF (calm_bpf), never raw IP sockets (spike F2).
    if g.needs_raw_packets() {
        push("--privileged");
        push("--send-eth");
        push("-e");
        push(g.interface());
    }
    if !g.ports().is_empty() {
        push("-p");
        push(&join(g.ports().iter().map(u16::to_string)));
    }
    if !g.scripts().is_empty() {
        push("--script");
        push(&g.scripts().join(","));
    }
    push("--max-rate");
    push(&g.max_rate().to_string());
    push("--host-timeout");
    push(&format!("{}s", HOST_TIMEOUT.as_secs()));
    if !g.exclusions().is_empty() {
        push("--exclude");
        push(&join(g.exclusions().iter().map(ToString::to_string)));
    }
    // XML on stdout: no temp files, nothing written next to the user's data.
    push("-oX");
    push("-");
    for t in g.targets() {
        push(&t.to_string());
    }
    for r in g.ranges() {
        push(r);
    }
    a
}

fn join(items: impl Iterator<Item = String>) -> String {
    items.collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use calm_domain::{NetworkBinding, NetworkPosition, Scope, TargetRole};
    use calm_orchestrator::scope::{approve, RangeDraft, ScopeDraft, TargetDraft};
    use calm_orchestrator::{authorize_plan, RunPlan};
    use Capability::*;

    const NOW: i64 = 1_800_000_000_000;

    fn net() -> NetworkBinding {
        NetworkBinding {
            gateway: "192.168.68.1".into(),
            subnet: Some("192.168.68.0/24".into()),
            ssid: None,
        }
    }

    fn scope() -> Scope {
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
        approve(&d, "scope-1".into(), "s".into(), Some(net()), NOW).unwrap()
    }

    fn args(p: RunPlan) -> Vec<String> {
        let g =
            authorize_plan(Some(&scope()), false, &p, NOW + 1, Some(&net())).expect("authorized");
        build_args(&g)
    }

    fn base(caps: Vec<Capability>) -> RunPlan {
        RunPlan {
            targets: vec!["10.20.0.5".parse().unwrap()],
            ports: vec![443, 80],
            capabilities: caps,
            interface: "en0".into(),
            ..Default::default()
        }
    }

    #[test]
    fn tcp_connect_is_the_safest_command() {
        assert_eq!(
            args(base(vec![TcpConnect])).join(" "),
            "-sT -Pn -n -p 80,443 --max-rate 5 --host-timeout 60s -oX - 10.20.0.5"
        );
    }

    #[test]
    fn syn_os_and_service_detection_use_bpf_on_the_named_interface() {
        assert_eq!(
            args(base(vec![SynScan, OsDetection, ServiceDetection])).join(" "),
            "-sS -sV -O -Pn -n --privileged --send-eth -e en0 -p 80,443 --max-rate 5 --host-timeout 60s -oX - 10.20.0.5"
        );
    }

    #[test]
    fn host_discovery_over_a_range_excludes_what_the_owner_named() {
        let p = RunPlan {
            targets: vec![],
            ranges: vec!["192.168.68.0/24".into()],
            ports: vec![],
            ..base(vec![HostDiscovery])
        };
        assert_eq!(
            args(p).join(" "),
            "-sn -n --privileged --send-eth -e en0 --max-rate 5 --host-timeout 60s --exclude 192.168.68.50 -oX - 192.168.68.0/24"
        );
    }

    #[test]
    fn reverse_dns_names_the_resolver_and_scripts_are_listed() {
        let p = RunPlan {
            resolver: Some("192.168.68.1".parse().unwrap()),
            scripts: vec!["http-title".into()],
            ..base(vec![TcpConnect, ReverseDns, Nse])
        };
        assert_eq!(
            args(p).join(" "),
            "-sT -Pn --dns-servers 192.168.68.1 -p 80,443 --script http-title --max-rate 5 --host-timeout 60s -oX - 10.20.0.5"
        );
    }

    #[test]
    fn every_flag_emitted_is_a_known_one() {
        let a = args(base(vec![SynScan, OsDetection, ServiceDetection]));
        for x in a.iter().filter(|x| x.starts_with('-') && x.as_str() != "-") {
            assert!(KNOWN_FLAGS.contains(&x.as_str()), "{x}");
        }
    }
}
