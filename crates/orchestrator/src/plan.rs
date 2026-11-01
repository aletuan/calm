//! Run-plan authorization (ADR-011).
//!
//! Nmap sends its own packets, so Calm cannot check each one. Instead the
//! whole run is decided up front: every target, range, port, capability and
//! script must be inside the scope, now, on the granted network. The only way
//! to get a [`PlanGrant`] is [`authorize_plan`]; the Nmap command builder
//! accepts nothing else, and builds the command from the grant alone.

use std::net::IpAddr;
use std::time::Duration;

use calm_domain::{Capability, NetworkBinding, Scope};
use serde::{Deserialize, Serialize};

use crate::scope::{check_address, parse_range, range_contains, same_network, NSE_ALLOWLIST};

/// Longest a single host may take in one run (`--host-timeout`).
pub const HOST_TIMEOUT: Duration = Duration::from_secs(60);

/// What a run wants to do. Built by Calm from user choices; never trusted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunPlan {
    pub targets: Vec<IpAddr>,
    /// CIDR blocks, each inside one of the scope's ranges.
    pub ranges: Vec<String>,
    /// Ports scanned on every target and range. Empty only for discovery.
    pub ports: Vec<u16>,
    pub capabilities: Vec<Capability>,
    pub scripts: Vec<String>,
    /// Interface for raw packets, e.g. "en0".
    pub interface: String,
    /// The network's resolver, for reverse DNS only.
    pub resolver: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanDenied {
    #[error("no scope grant")]
    NoGrant,
    #[error("scope revoked")]
    Revoked,
    #[error("scope expired")]
    Expired,
    #[error("this Mac's network is unknown")]
    NetworkUnknown,
    #[error("not on the network the scope was granted for")]
    NetworkChanged,
    #[error("the plan has nothing to run")]
    EmptyPlan,
    #[error("a capability in the plan is not in the scope")]
    CapabilityNotGranted,
    #[error("a port scan needs exactly one scan type (TCP connect or SYN)")]
    ScanTypeRequired,
    #[error("this capability needs ports")]
    PortsRequired,
    #[error("an address is not allowed as a target")]
    AddressNotAllowed,
    #[error("a target is not in the scope")]
    TargetNotAllowed,
    #[error("a range is not inside the scope's ranges")]
    RangeNotAllowed,
    #[error("a port is not allowed for a target or range")]
    PortNotAllowed,
    #[error("a target is excluded by the scope")]
    Excluded,
    #[error("a script is not allowed")]
    ScriptNotAllowed,
    #[error("scripts need the NSE capability, and NSE needs scripts")]
    ScriptsMismatch,
    #[error("the interface name is not valid")]
    BadInterface,
    #[error("reverse DNS needs the network's own private resolver")]
    ResolverNotPrivate,
}

/// Permission for exactly one run. Fields are private: only
/// [`authorize_plan`] builds it, and the command builder reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanGrant {
    scope_id: String,
    targets: Vec<IpAddr>,
    ranges: Vec<String>,
    exclusions: Vec<IpAddr>,
    ports: Vec<u16>,
    capabilities: Vec<Capability>,
    scripts: Vec<String>,
    interface: String,
    resolver: Option<IpAddr>,
    max_rate: u32,
}

impl PlanGrant {
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
    pub fn targets(&self) -> &[IpAddr] {
        &self.targets
    }
    pub fn ranges(&self) -> &[String] {
        &self.ranges
    }
    /// Scope exclusions that fall inside the plan's ranges.
    pub fn exclusions(&self) -> &[IpAddr] {
        &self.exclusions
    }
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
    pub fn has(&self, c: Capability) -> bool {
        self.capabilities.contains(&c)
    }
    pub fn scripts(&self) -> &[String] {
        &self.scripts
    }
    pub fn interface(&self) -> &str {
        &self.interface
    }
    pub fn resolver(&self) -> Option<IpAddr> {
        self.resolver
    }
    pub fn max_rate(&self) -> u32 {
        self.max_rate
    }
    pub fn needs_raw_packets(&self) -> bool {
        self.capabilities.iter().any(|c| c.needs_raw_packets())
    }
}

/// A macOS interface name such as "en0" or "bridge100". Anything else could
/// be read by Nmap as an option ("-iL…"), so it is refused.
pub fn valid_interface(name: &str) -> bool {
    let letters = name.chars().take_while(|c| c.is_ascii_lowercase()).count();
    let digits = &name[letters..];
    (1..=8).contains(&letters)
        && (1..=3).contains(&digits.len())
        && digits.chars().all(|c| c.is_ascii_digit())
}

const SCAN_TYPES: [Capability; 2] = [Capability::TcpConnect, Capability::SynScan];
const NEEDS_PORTS: [Capability; 3] = [
    Capability::ServiceDetection,
    Capability::OsDetection,
    Capability::Nse,
];

/// Decide one run, now. Every condition must hold; the first failure wins.
pub fn authorize_plan(
    scope: Option<&Scope>,
    revoked: bool,
    plan: &RunPlan,
    now_ms: i64,
    network_now: Option<&NetworkBinding>,
) -> Result<PlanGrant, PlanDenied> {
    let scope = usable(scope, revoked, now_ms, network_now)?;
    let mut caps = plan.capabilities.clone();
    caps.sort_unstable();
    caps.dedup();
    let mut ports = plan.ports.clone();
    ports.sort_unstable();
    ports.dedup();

    check_shape(plan, &caps, &ports)?;
    if caps.iter().any(|c| !scope.allows(*c)) {
        return Err(PlanDenied::CapabilityNotGranted);
    }
    let excluded: Vec<IpAddr> = scope
        .exclusions
        .iter()
        .filter_map(|e| e.parse().ok())
        .collect();
    for t in &plan.targets {
        check_target(scope, &excluded, *t, &ports)?;
    }
    let mut ranges = Vec::new();
    for r in &plan.ranges {
        ranges.push(check_range(scope, r, &ports)?);
    }
    check_scripts(scope, &caps, &plan.scripts)?;
    if caps.iter().any(|c| c.needs_raw_packets()) && !valid_interface(&plan.interface) {
        return Err(PlanDenied::BadInterface);
    }
    let resolver = if caps.contains(&Capability::ReverseDns) {
        match plan.resolver {
            Some(r) if check_address(&r.to_string()).is_ok() => Some(r),
            _ => return Err(PlanDenied::ResolverNotPrivate),
        }
    } else {
        None
    };
    let exclusions = excluded
        .into_iter()
        .filter(|e| {
            ranges
                .iter()
                .filter_map(|r| parse_range(r))
                .any(|r| range_contains(r, *e))
        })
        .collect();
    Ok(PlanGrant {
        scope_id: scope.id.clone(),
        targets: plan.targets.clone(),
        ranges,
        exclusions,
        ports,
        capabilities: caps,
        scripts: plan.scripts.clone(),
        interface: plan.interface.clone(),
        resolver,
        max_rate: scope.budget.max_probes_per_second,
    })
}

fn usable<'a>(
    scope: Option<&'a Scope>,
    revoked: bool,
    now_ms: i64,
    network_now: Option<&NetworkBinding>,
) -> Result<&'a Scope, PlanDenied> {
    let scope = scope.ok_or(PlanDenied::NoGrant)?;
    if revoked {
        return Err(PlanDenied::Revoked);
    }
    if now_ms >= scope.expires_at_ms || now_ms < scope.approved_at_ms {
        return Err(PlanDenied::Expired);
    }
    let now = network_now.ok_or(PlanDenied::NetworkUnknown)?;
    if !same_network(&scope.network, now) {
        return Err(PlanDenied::NetworkChanged);
    }
    Ok(scope)
}

/// What the plan asks for must make sense on its own, before the scope.
fn check_shape(plan: &RunPlan, caps: &[Capability], ports: &[u16]) -> Result<(), PlanDenied> {
    if caps.is_empty() || (plan.targets.is_empty() && plan.ranges.is_empty()) {
        return Err(PlanDenied::EmptyPlan);
    }
    let scan_types = caps.iter().filter(|c| SCAN_TYPES.contains(c)).count();
    if !ports.is_empty() && scan_types != 1 {
        return Err(PlanDenied::ScanTypeRequired);
    }
    if ports.is_empty() && (scan_types > 0 || caps.iter().any(|c| NEEDS_PORTS.contains(c))) {
        return Err(PlanDenied::PortsRequired);
    }
    if ports.is_empty() && !caps.contains(&Capability::HostDiscovery) {
        return Err(PlanDenied::PortsRequired);
    }
    if ports.contains(&0) {
        return Err(PlanDenied::PortNotAllowed);
    }
    Ok(())
}

fn check_target(
    scope: &Scope,
    excluded: &[IpAddr],
    t: IpAddr,
    ports: &[u16],
) -> Result<(), PlanDenied> {
    // Defence in depth: a stored scope is re-checked against the address policy.
    if check_address(&t.to_string()).is_err() {
        return Err(PlanDenied::AddressNotAllowed);
    }
    if excluded.contains(&t) {
        return Err(PlanDenied::Excluded);
    }
    let literal = scope
        .targets
        .iter()
        .find(|s| s.address.parse::<IpAddr>().ok() == Some(t))
        .map(|s| &s.ports);
    let in_range = scope
        .ranges
        .iter()
        .find(|r| parse_range(&r.cidr).is_some_and(|net| range_contains(net, t)))
        .map(|r| &r.ports);
    let allowed: Vec<&Vec<u16>> = literal.into_iter().chain(in_range).collect();
    if allowed.is_empty() {
        return Err(PlanDenied::TargetNotAllowed);
    }
    if !ports
        .iter()
        .all(|p| allowed.iter().any(|list| list.contains(p)))
    {
        return Err(PlanDenied::PortNotAllowed);
    }
    Ok(())
}

/// A plan range must sit inside one scope range and use only its ports.
/// Returns the canonical CIDR.
fn check_range(scope: &Scope, cidr: &str, ports: &[u16]) -> Result<String, PlanDenied> {
    let (net, prefix) = parse_range(cidr).ok_or(PlanDenied::RangeNotAllowed)?;
    let outer = scope
        .ranges
        .iter()
        .find(|r| {
            parse_range(&r.cidr)
                .is_some_and(|o| prefix >= o.1 && range_contains(o, IpAddr::V4(net)))
        })
        .ok_or(PlanDenied::RangeNotAllowed)?;
    if !ports.iter().all(|p| outer.ports.contains(p)) {
        return Err(PlanDenied::PortNotAllowed);
    }
    Ok(format!("{net}/{prefix}"))
}

fn check_scripts(scope: &Scope, caps: &[Capability], scripts: &[String]) -> Result<(), PlanDenied> {
    if caps.contains(&Capability::Nse) == scripts.is_empty() {
        return Err(PlanDenied::ScriptsMismatch);
    }
    for s in scripts {
        if !NSE_ALLOWLIST.contains(&s.as_str()) || !scope.nse_scripts.contains(s) {
            return Err(PlanDenied::ScriptNotAllowed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{approve, RangeDraft, ScopeDraft, TargetDraft};
    use calm_domain::{NetworkPosition, TargetRole};
    use Capability::*;

    const NOW: i64 = 1_800_000_000_000;
    const HOUR: i64 = 3_600_000;

    fn net() -> NetworkBinding {
        NetworkBinding {
            gateway: "192.168.68.1".into(),
            subnet: Some("192.168.68.0/24".into()),
            ssid: None,
        }
    }

    /// Admin target with 80/443, a /24 range with 22/80/443 excluding .50,
    /// every capability, two scripts.
    fn scope_with(caps: Vec<Capability>) -> Scope {
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
            expires_at_ms: NOW + HOUR,
            authorization_confirmed: true,
            vantage: Some(NetworkPosition::Guest),
            nse_scripts: if caps.contains(&Nse) {
                vec!["http-title".into(), "ssl-cert".into()]
            } else {
                vec![]
            },
            capabilities: caps,
            ranges: vec![RangeDraft {
                cidr: "192.168.68.0/24".into(),
                ports: vec![22, 80, 443],
                label: String::new(),
            }],
            exclusions: vec!["192.168.68.50".into()],
            ..Default::default()
        };
        approve(&d, "scope-1".into(), "s".into(), Some(net()), NOW).expect("valid scope")
    }

    fn all() -> Scope {
        scope_with(Capability::ALL.to_vec())
    }

    fn plan(caps: Vec<Capability>) -> RunPlan {
        RunPlan {
            targets: vec!["10.20.0.5".parse().unwrap()],
            ports: vec![443],
            capabilities: caps,
            interface: "en0".into(),
            ..Default::default()
        }
    }

    fn decide(s: &Scope, p: &RunPlan) -> Result<PlanGrant, PlanDenied> {
        authorize_plan(Some(s), false, p, NOW + 1, Some(&net()))
    }

    #[test]
    fn a_plain_tcp_connect_plan_is_granted_as_asked() {
        let g = decide(&all(), &plan(vec![TcpConnect])).unwrap();
        assert_eq!(g.scope_id(), "scope-1");
        assert_eq!(g.targets(), ["10.20.0.5".parse::<IpAddr>().unwrap()]);
        assert_eq!(g.ports(), [443]);
        assert_eq!(g.capabilities(), [TcpConnect]);
        assert_eq!(g.max_rate(), 5);
        assert!(!g.needs_raw_packets());
    }

    #[test]
    fn the_scope_itself_must_be_usable_now_and_here() {
        let s = all();
        let p = plan(vec![TcpConnect]);
        assert_eq!(
            authorize_plan(None, false, &p, NOW + 1, Some(&net())),
            Err(PlanDenied::NoGrant)
        );
        assert_eq!(
            authorize_plan(Some(&s), true, &p, NOW + 1, Some(&net())),
            Err(PlanDenied::Revoked)
        );
        assert_eq!(
            authorize_plan(Some(&s), false, &p, NOW + HOUR, Some(&net())),
            Err(PlanDenied::Expired)
        );
        assert_eq!(
            authorize_plan(Some(&s), false, &p, NOW - 1, Some(&net())),
            Err(PlanDenied::Expired)
        );
        assert_eq!(
            authorize_plan(Some(&s), false, &p, NOW + 1, None),
            Err(PlanDenied::NetworkUnknown)
        );
        let other = NetworkBinding {
            gateway: "10.0.0.1".into(),
            ..net()
        };
        assert_eq!(
            authorize_plan(Some(&s), false, &p, NOW + 1, Some(&other)),
            Err(PlanDenied::NetworkChanged)
        );
    }

    #[test]
    fn only_capabilities_in_the_scope() {
        let s = scope_with(vec![TcpConnect]);
        for c in [SynScan, ServiceDetection, OsDetection] {
            let caps = if c == SynScan {
                vec![SynScan]
            } else {
                vec![TcpConnect, c]
            };
            assert_eq!(
                decide(&s, &plan(caps)),
                Err(PlanDenied::CapabilityNotGranted),
                "{c:?}"
            );
        }
    }

    #[test]
    fn a_port_scan_has_exactly_one_scan_type_and_identification_needs_ports() {
        let s = all();
        assert_eq!(
            decide(&s, &plan(vec![TcpConnect, SynScan])),
            Err(PlanDenied::ScanTypeRequired)
        );
        assert_eq!(
            decide(&s, &plan(vec![ServiceDetection])),
            Err(PlanDenied::ScanTypeRequired)
        );
        let mut p = plan(vec![TcpConnect]);
        p.ports = vec![];
        assert_eq!(decide(&s, &p), Err(PlanDenied::PortsRequired));
        p.capabilities = vec![OsDetection];
        assert_eq!(decide(&s, &p), Err(PlanDenied::PortsRequired));
        p.capabilities = vec![ReverseDns];
        assert_eq!(
            decide(&s, &p),
            Err(PlanDenied::PortsRequired),
            "nothing to run without discovery"
        );
        let mut empty = plan(vec![TcpConnect]);
        empty.targets = vec![];
        assert_eq!(decide(&s, &empty), Err(PlanDenied::EmptyPlan));
        assert_eq!(decide(&s, &plan(vec![])), Err(PlanDenied::EmptyPlan));
    }

    #[test]
    fn targets_must_be_in_the_scope_with_their_ports_and_not_excluded() {
        let s = all();
        let with = |t: &str, ports: Vec<u16>| RunPlan {
            targets: vec![t.parse().unwrap()],
            ports,
            ..plan(vec![TcpConnect])
        };
        assert!(decide(&s, &with("10.20.0.5", vec![80, 443])).is_ok());
        assert!(
            decide(&s, &with("192.168.68.20", vec![22])).is_ok(),
            "inside the range"
        );
        for (t, ports, want) in [
            ("10.20.0.5", vec![22], PlanDenied::PortNotAllowed),
            ("192.168.68.20", vec![8080], PlanDenied::PortNotAllowed),
            ("10.20.0.6", vec![443], PlanDenied::TargetNotAllowed),
            ("192.168.69.1", vec![443], PlanDenied::TargetNotAllowed),
            ("192.168.68.50", vec![443], PlanDenied::Excluded),
            ("8.8.8.8", vec![443], PlanDenied::AddressNotAllowed),
            ("127.0.0.1", vec![443], PlanDenied::AddressNotAllowed),
        ] {
            assert_eq!(
                decide(&s, &with(t, ports.clone())),
                Err(want),
                "{t} {ports:?}"
            );
        }
    }

    #[test]
    fn ranges_must_sit_inside_a_scope_range_and_carry_its_exclusions() {
        let s = all();
        let with = |r: &str| RunPlan {
            targets: vec![],
            ranges: vec![r.into()],
            ports: vec![80],
            ..plan(vec![TcpConnect])
        };
        let g = decide(&s, &with("192.168.68.0/24")).unwrap();
        assert_eq!(g.exclusions(), ["192.168.68.50".parse::<IpAddr>().unwrap()]);
        let g = decide(&s, &with("192.168.68.0/28")).unwrap();
        assert!(g.exclusions().is_empty(), ".50 is outside .0/28");
        for r in [
            "192.168.68.0/23",
            "192.168.69.0/24",
            "10.20.0.0/24",
            "192.168.68.5/24",
            "nope",
        ] {
            assert_eq!(
                decide(&s, &with(r)),
                Err(PlanDenied::RangeNotAllowed),
                "{r}"
            );
        }
        let mut p = with("192.168.68.0/24");
        p.ports = vec![8080];
        assert_eq!(decide(&s, &p), Err(PlanDenied::PortNotAllowed));
    }

    #[test]
    fn host_discovery_alone_runs_without_ports() {
        let p = RunPlan {
            targets: vec![],
            ranges: vec!["192.168.68.0/24".into()],
            ports: vec![],
            ..plan(vec![HostDiscovery])
        };
        let g = decide(&all(), &p).unwrap();
        assert!(g.needs_raw_packets());
    }

    #[test]
    fn scripts_must_be_allowlisted_named_in_the_scope_and_need_nse() {
        let s = all();
        let with = |scripts: Vec<&str>, caps: Vec<Capability>| RunPlan {
            scripts: scripts.into_iter().map(String::from).collect(),
            ..plan(caps)
        };
        assert!(decide(&s, &with(vec!["http-title"], vec![TcpConnect, Nse])).is_ok());
        assert_eq!(
            decide(&s, &with(vec!["ssh-hostkey"], vec![TcpConnect, Nse])),
            Err(PlanDenied::ScriptNotAllowed),
            "allowlisted but not in this scope"
        );
        assert_eq!(
            decide(&s, &with(vec!["smb-brute"], vec![TcpConnect, Nse])),
            Err(PlanDenied::ScriptNotAllowed)
        );
        assert_eq!(
            decide(&s, &with(vec!["http-title"], vec![TcpConnect])),
            Err(PlanDenied::ScriptsMismatch)
        );
        assert_eq!(
            decide(&s, &with(vec![], vec![TcpConnect, Nse])),
            Err(PlanDenied::ScriptsMismatch)
        );
    }

    #[test]
    fn raw_packet_plans_need_a_real_interface_name() {
        let s = all();
        for bad in [
            "",
            "-iL",
            "-iL/etc/hosts",
            "en0 -O",
            "EN0",
            "en",
            "en0000",
            "verylongname1",
        ] {
            let p = RunPlan {
                interface: bad.into(),
                ..plan(vec![SynScan])
            };
            assert_eq!(decide(&s, &p), Err(PlanDenied::BadInterface), "{bad:?}");
        }
        for ok in ["en0", "en1", "bridge100"] {
            assert!(valid_interface(ok), "{ok}");
        }
        let p = RunPlan {
            interface: "-iL".into(),
            ..plan(vec![TcpConnect])
        };
        assert!(
            decide(&s, &p).is_ok(),
            "TCP connect sends no raw packets and passes no -e"
        );
    }

    #[test]
    fn reverse_dns_only_through_a_private_resolver() {
        let s = all();
        let with = |r: Option<&str>| RunPlan {
            resolver: r.map(|x| x.parse().unwrap()),
            ..plan(vec![TcpConnect, ReverseDns])
        };
        assert_eq!(
            decide(&s, &with(Some("192.168.68.1"))).unwrap().resolver(),
            Some("192.168.68.1".parse().unwrap())
        );
        assert_eq!(
            decide(&s, &with(Some("8.8.8.8"))),
            Err(PlanDenied::ResolverNotPrivate)
        );
        assert_eq!(decide(&s, &with(None)), Err(PlanDenied::ResolverNotPrivate));
        assert_eq!(
            decide(&s, &plan(vec![TcpConnect])).unwrap().resolver(),
            None,
            "no resolver kept without the capability"
        );
    }

    #[test]
    fn plan_denials_wire_format() {
        assert_eq!(
            serde_json::to_value(PlanDenied::ResolverNotPrivate).unwrap(),
            serde_json::json!({"kind": "resolver_not_private"})
        );
    }
}
