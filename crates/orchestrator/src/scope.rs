//! Scope engine (FR-006, NFR-05, ADR-005).
//!
//! Two jobs, both deny-by-default:
//! - `approve` turns what the user typed into an immutable [`Scope`], or a
//!   list of every reason it cannot be one;
//! - `authorize` decides, right before each probe, whether that exact
//!   address:port may be touched now, from this network. The only way to get
//!   a [`Grant`] — which the probe runner requires — is through it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use calm_domain::{
    default_capabilities, Capability, NetworkBinding, NetworkPosition, NetworkProfile, RateBudget,
    Scope, ScopeRange, ScopeTarget, TargetRole, TestLevel,
};
use serde::{Deserialize, Serialize};

pub const MAX_TARGETS: usize = 16;
pub const MAX_PORTS_PER_TARGET: usize = 16;
pub const MAX_TEXT: usize = 200;
/// Longest validity the app accepts for one grant.
pub const MAX_VALIDITY_MS: i64 = 7 * 24 * 3600 * 1000;
pub const DEFAULT_PROBES_PER_SECOND: u32 = 5;
pub const MAX_PROBES_PER_SECOND: u32 = 10;
pub const DEFAULT_TIMEOUT_MS: u32 = 3000;
pub const MIN_TIMEOUT_MS: u32 = 500;
pub const MAX_TIMEOUT_MS: u32 = 5000;
/// Largest range a scope may hold: a /24, 256 addresses (ADR-011).
pub const MIN_RANGE_PREFIX: u32 = 24;
/// NSE scripts Calm can run at all (ADR-011). Only from the `safe` and
/// `default`/`discovery` categories; each must also be named in the scope.
/// Never add a script from brute, dos, exploit, intrusive, malware, fuzzer,
/// external or broadcast.
pub const NSE_ALLOWLIST: [&str; 4] = ["http-headers", "http-title", "ssh-hostkey", "ssl-cert"];

/// What the user filled in. Everything is re-validated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeDraft {
    pub authorization_reference: String,
    pub operator: String,
    pub granted_by: String,
    pub targets: Vec<TargetDraft>,
    pub expires_at_ms: i64,
    pub max_probes_per_second: u32,
    pub timeout_ms: u32,
    /// "I hold written permission from the owner for these targets."
    pub authorization_confirmed: bool,
    /// Where the Mac stands. Required: the user must say, even "unknown".
    #[serde(default)]
    pub vantage: Option<NetworkPosition>,
    /// ADR-011. Drafts from before it mean TCP connect only.
    #[serde(default = "default_capabilities")]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub ranges: Vec<RangeDraft>,
    #[serde(default)]
    pub exclusions: Vec<String>,
    /// "No device in these ranges needs avoiding": the alternative to listing exclusions.
    #[serde(default)]
    pub nothing_to_exclude: bool,
    #[serde(default)]
    pub nse_scripts: Vec<String>,
}

impl Default for ScopeDraft {
    /// An empty form. Capabilities start as TCP connect only, never empty.
    fn default() -> Self {
        Self {
            authorization_reference: String::new(),
            operator: String::new(),
            granted_by: String::new(),
            targets: vec![],
            expires_at_ms: 0,
            max_probes_per_second: DEFAULT_PROBES_PER_SECOND,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            authorization_confirmed: false,
            vantage: None,
            capabilities: default_capabilities(),
            ranges: vec![],
            exclusions: vec![],
            nothing_to_exclude: false,
            nse_scripts: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeDraft {
    pub cidr: String,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDraft {
    pub address: String,
    pub ports: Vec<u16>,
    pub role: TargetRole,
    #[serde(default)]
    pub label: String,
}

/// Why an address may not be a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressReason {
    /// Not an IP address (hostnames and ranges are not accepted).
    NotAnAddress,
    Unspecified,
    Loopback,
    Multicast,
    Broadcast,
    /// Needs an interface to be meaningful (169.254/16, fe80::/10).
    LinkLocal,
    /// Outside private/ULA space: could belong to someone else.
    NotPrivate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DraftError {
    AuthorizationRequired,
    OperatorRequired,
    GrantedByRequired,
    TextTooLong,
    NotConfirmed,
    NoTargets,
    TooManyTargets,
    BadAddress {
        index: usize,
        reason: AddressReason,
    },
    DuplicateAddress {
        index: usize,
    },
    NoPorts {
        index: usize,
    },
    TooManyPorts {
        index: usize,
    },
    BadPort {
        index: usize,
    },
    ExpiryInPast,
    ExpiryTooFar,
    RateOutOfRange,
    TimeoutOutOfRange,
    /// The default gateway is unknown, so the grant cannot be tied to a network.
    NetworkUnknown,
    /// The user did not say which network the Mac is on.
    VantageRequired,
    NoCapabilities,
    /// Not a private IPv4 network address in CIDR form.
    BadRange {
        index: usize,
    },
    /// Wider than /24.
    RangeTooLarge {
        index: usize,
    },
    BadRangePorts {
        index: usize,
    },
    /// Ranges with neither an excluded address nor "nothing to exclude".
    ExclusionsRequired,
    /// Addresses listed and "nothing to exclude" ticked: one of them is wrong.
    ExclusionsContradict,
    BadExclusion {
        index: usize,
    },
    HostDiscoveryNeedsRange,
    ScriptsNeedNse,
    NseNeedsScripts,
    ScriptNotAllowed {
        index: usize,
    },
}

/// Address policy for targets. Private IPv4 (RFC 1918), shared address space
/// (RFC 6598) and IPv6 unique-local only.
pub fn check_address(text: &str) -> Result<IpAddr, AddressReason> {
    let ip: IpAddr = text
        .trim()
        .parse()
        .map_err(|_| AddressReason::NotAnAddress)?;
    match ip {
        IpAddr::V4(v4) => check_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => check_v4(v4),
            None => check_v6(v6),
        },
    }
    .map(|_| ip)
}

fn check_v4(ip: Ipv4Addr) -> Result<(), AddressReason> {
    if ip.is_unspecified() {
        return Err(AddressReason::Unspecified);
    }
    if ip.is_loopback() {
        return Err(AddressReason::Loopback);
    }
    if ip.is_multicast() {
        return Err(AddressReason::Multicast);
    }
    if ip.is_broadcast() {
        return Err(AddressReason::Broadcast);
    }
    if ip.is_link_local() {
        return Err(AddressReason::LinkLocal);
    }
    let o = ip.octets();
    let shared = o[0] == 100 && (o[1] & 0xc0) == 64; // 100.64.0.0/10
    if ip.is_private() || shared {
        Ok(())
    } else {
        Err(AddressReason::NotPrivate)
    }
}

fn check_v6(ip: Ipv6Addr) -> Result<(), AddressReason> {
    let s = ip.segments();
    if ip.is_unspecified() {
        return Err(AddressReason::Unspecified);
    }
    if ip.is_loopback() {
        return Err(AddressReason::Loopback);
    }
    if ip.is_multicast() {
        return Err(AddressReason::Multicast);
    }
    if (s[0] & 0xffc0) == 0xfe80 {
        return Err(AddressReason::LinkLocal);
    }
    if (s[0] & 0xfe00) == 0xfc00 {
        Ok(())
    } else {
        Err(AddressReason::NotPrivate)
    }
}

/// This Mac's network now, as far as a grant cares. `None` without a gateway.
pub fn binding_from_profile(p: &NetworkProfile) -> Option<NetworkBinding> {
    let gateway = p.default_gateway.value.clone()?;
    let subnet = p.ipv4.value.as_ref().and_then(|v| {
        v.iter().find_map(|a| {
            let ip: Ipv4Addr = a.address.parse().ok()?;
            let prefix = a.prefix.filter(|n| *n <= 32)?;
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Some(format!("{}/{prefix}", Ipv4Addr::from(u32::from(ip) & mask)))
        })
    });
    Some(NetworkBinding {
        gateway,
        subnet,
        ssid: p.wifi.ssid.value.clone(),
    })
}

/// Same network as the grant? Gateway must match; subnet and SSID must match
/// whenever both sides know them.
pub fn same_network(granted: &NetworkBinding, now: &NetworkBinding) -> bool {
    let both = |a: &Option<String>, b: &Option<String>| match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
    granted.gateway == now.gateway
        && both(&granted.subnet, &now.subnet)
        && both(&granted.ssid, &now.ssid)
}

/// Is an IPv4 target inside this Mac's subnet ("192.168.68.0/24")? `None`
/// when either side cannot be read or the target is IPv6. A target outside
/// is still allowed: the probe is routed through the gateway to another
/// segment, which the user should know before running.
pub fn in_subnet(address: &str, subnet: &str) -> Option<bool> {
    let ip: Ipv4Addr = address.parse().ok()?;
    let (net, prefix) = subnet.split_once('/')?;
    let net: Ipv4Addr = net.parse().ok()?;
    let prefix: u32 = prefix.parse().ok().filter(|p| *p <= 32)?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some(u32::from(ip) & mask == u32::from(net) & mask)
}

fn text_ok(s: &str) -> bool {
    s.chars().count() <= MAX_TEXT
}

/// Validate a draft into an immutable scope. Returns every problem at once.
pub fn approve(
    draft: &ScopeDraft,
    id: String,
    session_id: String,
    network: Option<NetworkBinding>,
    now_ms: i64,
) -> Result<Scope, Vec<DraftError>> {
    let mut errors = Vec::new();
    if draft.authorization_reference.trim().is_empty() {
        errors.push(DraftError::AuthorizationRequired);
    }
    if draft.operator.trim().is_empty() {
        errors.push(DraftError::OperatorRequired);
    }
    if draft.granted_by.trim().is_empty() {
        errors.push(DraftError::GrantedByRequired);
    }
    let texts = [
        &draft.authorization_reference,
        &draft.operator,
        &draft.granted_by,
    ];
    if texts.iter().any(|t| !text_ok(t)) || draft.targets.iter().any(|t| !text_ok(&t.label)) {
        errors.push(DraftError::TextTooLong);
    }
    if !draft.authorization_confirmed {
        errors.push(DraftError::NotConfirmed);
    }
    if draft.vantage.is_none() {
        errors.push(DraftError::VantageRequired);
    }
    if draft.targets.is_empty() && draft.ranges.is_empty() {
        errors.push(DraftError::NoTargets);
    }
    if draft.targets.len() > MAX_TARGETS {
        errors.push(DraftError::TooManyTargets);
    }

    let mut targets = Vec::new();
    let mut seen: Vec<IpAddr> = Vec::new();
    for (index, t) in draft.targets.iter().enumerate() {
        match check_address(&t.address) {
            Err(reason) => errors.push(DraftError::BadAddress { index, reason }),
            Ok(ip) if seen.contains(&ip) => errors.push(DraftError::DuplicateAddress { index }),
            Ok(ip) => {
                seen.push(ip);
                let mut ports = t.ports.clone();
                ports.sort_unstable();
                ports.dedup();
                if ports.is_empty() {
                    errors.push(DraftError::NoPorts { index });
                } else if ports.len() > MAX_PORTS_PER_TARGET {
                    errors.push(DraftError::TooManyPorts { index });
                } else if ports.contains(&0) {
                    errors.push(DraftError::BadPort { index });
                }
                targets.push(ScopeTarget {
                    address: ip.to_string(),
                    ports,
                    role: t.role,
                    label: t.label.trim().to_owned(),
                });
            }
        }
    }

    let capabilities = check_capabilities(draft, &mut errors);
    let ranges = check_ranges(&draft.ranges, &mut errors);
    let exclusions = check_exclusions(draft, &mut errors);

    if draft.expires_at_ms <= now_ms {
        errors.push(DraftError::ExpiryInPast);
    } else if draft.expires_at_ms - now_ms > MAX_VALIDITY_MS {
        errors.push(DraftError::ExpiryTooFar);
    }
    if !(1..=MAX_PROBES_PER_SECOND).contains(&draft.max_probes_per_second) {
        errors.push(DraftError::RateOutOfRange);
    }
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&draft.timeout_ms) {
        errors.push(DraftError::TimeoutOutOfRange);
    }
    let Some(network) = network else {
        errors.push(DraftError::NetworkUnknown);
        return Err(errors);
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Scope {
        id,
        session_id,
        authorization_reference: draft.authorization_reference.trim().to_owned(),
        operator: draft.operator.trim().to_owned(),
        granted_by: draft.granted_by.trim().to_owned(),
        targets,
        max_level: capabilities
            .iter()
            .map(|c| c.level())
            .max()
            .unwrap_or(TestLevel::L1),
        budget: RateBudget {
            max_probes_per_second: draft.max_probes_per_second,
            timeout_ms: draft.timeout_ms,
            max_parallel_targets: 1,
        },
        network,
        vantage: draft.vantage.unwrap_or_default(),
        approved_at_ms: now_ms,
        expires_at_ms: draft.expires_at_ms,
        capabilities,
        ranges,
        exclusions,
        nothing_to_exclude: draft.nothing_to_exclude && !draft.ranges.is_empty(),
        nse_scripts: draft.nse_scripts.clone(),
    })
}

/// Sorted, deduplicated capabilities, plus the rules that tie them to the
/// rest of the draft (ranges for discovery, scripts for NSE).
fn check_capabilities(draft: &ScopeDraft, errors: &mut Vec<DraftError>) -> Vec<Capability> {
    let mut caps = draft.capabilities.clone();
    caps.sort_unstable();
    caps.dedup();
    if caps.is_empty() {
        errors.push(DraftError::NoCapabilities);
    }
    if caps.contains(&Capability::HostDiscovery) && draft.ranges.is_empty() {
        errors.push(DraftError::HostDiscoveryNeedsRange);
    }
    let nse = caps.contains(&Capability::Nse);
    if !nse && !draft.nse_scripts.is_empty() {
        errors.push(DraftError::ScriptsNeedNse);
    }
    if nse && draft.nse_scripts.is_empty() {
        errors.push(DraftError::NseNeedsScripts);
    }
    for (index, name) in draft.nse_scripts.iter().enumerate() {
        if !NSE_ALLOWLIST.contains(&name.as_str()) {
            errors.push(DraftError::ScriptNotAllowed { index });
        }
    }
    caps
}

/// A private IPv4 network address with a prefix of /24 or longer, in
/// canonical form. Returns the network and its prefix.
pub fn parse_range(cidr: &str) -> Option<(Ipv4Addr, u32)> {
    let (net, prefix) = cidr.trim().split_once('/')?;
    let net: Ipv4Addr = net.parse().ok()?;
    let prefix: u32 = prefix.parse().ok().filter(|p| *p <= 32)?;
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    (u32::from(net) & mask == u32::from(net) && check_v4(net).is_ok()).then_some((net, prefix))
}

/// Is this address inside the range (as parsed by [`parse_range`])?
pub fn range_contains(range: (Ipv4Addr, u32), ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else { return false };
    let mask = u32::MAX.checked_shl(32 - range.1).unwrap_or(0);
    u32::from(v4) & mask == u32::from(range.0)
}

fn check_ranges(drafts: &[RangeDraft], errors: &mut Vec<DraftError>) -> Vec<ScopeRange> {
    let mut out = Vec::new();
    for (index, r) in drafts.iter().enumerate() {
        let Some((net, prefix)) = parse_range(&r.cidr) else {
            errors.push(DraftError::BadRange { index });
            continue;
        };
        if prefix < MIN_RANGE_PREFIX {
            errors.push(DraftError::RangeTooLarge { index });
            continue;
        }
        let mut ports = r.ports.clone();
        ports.sort_unstable();
        ports.dedup();
        if ports.is_empty() || ports.len() > MAX_PORTS_PER_TARGET || ports.contains(&0) {
            errors.push(DraftError::BadRangePorts { index });
            continue;
        }
        out.push(ScopeRange {
            cidr: format!("{net}/{prefix}"),
            ports,
            label: r.label.trim().to_owned(),
        });
    }
    out
}

fn check_exclusions(draft: &ScopeDraft, errors: &mut Vec<DraftError>) -> Vec<String> {
    if draft.nothing_to_exclude && !draft.exclusions.is_empty() {
        errors.push(DraftError::ExclusionsContradict);
    } else if !draft.ranges.is_empty() && draft.exclusions.is_empty() && !draft.nothing_to_exclude {
        errors.push(DraftError::ExclusionsRequired);
    }
    let mut out = Vec::new();
    for (index, e) in draft.exclusions.iter().enumerate() {
        match e.trim().parse::<IpAddr>() {
            Ok(ip) => out.push(ip.to_string()),
            Err(_) => errors.push(DraftError::BadExclusion { index }),
        }
    }
    out
}

/// One probe someone wants to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRequest {
    pub address: IpAddr,
    pub port: u16,
    pub level: TestLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeDenied {
    #[error("no scope grant: active tests need explicit authorization")]
    NoGrant,
    #[error("scope revoked")]
    Revoked,
    #[error("scope expired")]
    Expired,
    #[error("level exceeds the grant")]
    LevelExceeded,
    #[error("target not in the allowlist")]
    TargetNotAllowed,
    #[error("port not allowed for this target")]
    PortNotAllowed,
    #[error("this Mac's network is unknown")]
    NetworkUnknown,
    #[error("not on the network the scope was granted for")]
    NetworkChanged,
    #[error("address not allowed as a target")]
    AddressNotAllowed,
    #[error("the scope does not allow this kind of traffic")]
    CapabilityNotGranted,
}

/// Permission for exactly one address:port, from one scope. Cannot be built
/// outside this module; the probe runner only accepts this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    scope_id: String,
    addr: SocketAddr,
    role: TargetRole,
    timeout: Duration,
}

impl Grant {
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    pub fn role(&self) -> TargetRole {
        self.role
    }
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Decide one probe, now. Every condition must hold; the first failure wins.
pub fn authorize(
    scope: Option<&Scope>,
    revoked: bool,
    req: ProbeRequest,
    now_ms: i64,
    network_now: Option<&NetworkBinding>,
) -> Result<Grant, ScopeDenied> {
    if !req.level.requires_scope_grant() {
        // L0 is passive and never probes; nothing here sends packets for it.
        return Err(ScopeDenied::LevelExceeded);
    }
    let scope = scope.ok_or(ScopeDenied::NoGrant)?;
    if revoked {
        return Err(ScopeDenied::Revoked);
    }
    if now_ms >= scope.expires_at_ms || now_ms < scope.approved_at_ms {
        return Err(ScopeDenied::Expired);
    }
    if req.level > scope.max_level {
        return Err(ScopeDenied::LevelExceeded);
    }
    // Calm's own probe runner sends TCP connects only (ADR-011).
    if !scope.allows(Capability::TcpConnect) {
        return Err(ScopeDenied::CapabilityNotGranted);
    }
    // Defence in depth: even a stored scope is re-checked against the policy.
    if check_address(&req.address.to_string()).is_err() {
        return Err(ScopeDenied::AddressNotAllowed);
    }
    let target = scope
        .targets
        .iter()
        .find(|t| t.address.parse::<IpAddr>().ok() == Some(req.address))
        .ok_or(ScopeDenied::TargetNotAllowed)?;
    if !target.ports.contains(&req.port) {
        return Err(ScopeDenied::PortNotAllowed);
    }
    let now = network_now.ok_or(ScopeDenied::NetworkUnknown)?;
    if !same_network(&scope.network, now) {
        return Err(ScopeDenied::NetworkChanged);
    }
    Ok(Grant {
        scope_id: scope.id.clone(),
        addr: SocketAddr::new(req.address, req.port),
        role: target.role,
        timeout: Duration::from_millis(u64::from(scope.budget.timeout_ms)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;
    const HOUR: i64 = 3_600_000;

    fn net() -> NetworkBinding {
        NetworkBinding {
            gateway: "192.168.68.1".into(),
            subnet: Some("192.168.68.0/22".into()),
            ssid: None,
        }
    }

    fn draft() -> ScopeDraft {
        ScopeDraft {
            authorization_reference: "ROE-2026-11".into(),
            operator: "Andy".into(),
            granted_by: "Site owner".into(),
            targets: vec![
                TargetDraft {
                    address: "192.168.68.1".into(),
                    ports: vec![443, 80, 443],
                    role: TargetRole::AdminInterface,
                    label: " router UI ".into(),
                },
                TargetDraft {
                    address: "10.20.0.5".into(),
                    ports: vec![8443],
                    role: TargetRole::PosTest,
                    label: String::new(),
                },
            ],
            expires_at_ms: NOW + 4 * HOUR,
            max_probes_per_second: DEFAULT_PROBES_PER_SECOND,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            authorization_confirmed: true,
            vantage: Some(NetworkPosition::Guest),
            ..Default::default()
        }
    }

    fn scope() -> Scope {
        approve(&draft(), "scope-1".into(), "s1".into(), Some(net()), NOW).expect("valid")
    }

    fn req(addr: &str, port: u16) -> ProbeRequest {
        ProbeRequest {
            address: addr.parse().unwrap(),
            port,
            level: TestLevel::L1,
        }
    }

    #[test]
    fn approve_normalises_and_fixes_policy() {
        let s = scope();
        assert_eq!(s.targets[0].ports, vec![80, 443], "sorted, deduplicated");
        assert_eq!(s.targets[0].label, "router UI");
        assert_eq!(s.max_level, TestLevel::L1, "TCP connect only is L1");
        assert_eq!(s.budget.max_parallel_targets, 1);
        assert_eq!(s.approved_at_ms, NOW);
        assert_eq!(s.network, net());
    }

    #[test]
    fn in_subnet_reads_the_prefix() {
        assert_eq!(in_subnet("192.168.68.20", "192.168.68.0/24"), Some(true));
        assert_eq!(in_subnet("192.168.1.1", "192.168.68.0/24"), Some(false));
        assert_eq!(in_subnet("192.168.69.4", "192.168.68.0/22"), Some(true));
        assert_eq!(in_subnet("192.168.72.4", "192.168.68.0/22"), Some(false));
        assert_eq!(in_subnet("10.1.2.3", "0.0.0.0/0"), Some(true));
        assert_eq!(in_subnet("10.0.0.1", "10.0.0.1/32"), Some(true));
        assert_eq!(in_subnet("10.0.0.2", "10.0.0.1/32"), Some(false));
        assert_eq!(in_subnet("fd00::1", "192.168.68.0/24"), None);
        assert_eq!(in_subnet("192.168.68.2", "192.168.68.0"), None);
        assert_eq!(in_subnet("192.168.68.2", "192.168.68.0/33"), None);
    }

    #[test]
    fn approve_keeps_the_stated_vantage() {
        let mut d = draft();
        d.vantage = Some(NetworkPosition::Main);
        let s = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap();
        assert_eq!(s.vantage, NetworkPosition::Main);
        d.vantage = None;
        let e = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap_err();
        assert_eq!(e, vec![DraftError::VantageRequired]);
    }

    #[test]
    fn approve_reports_every_problem() {
        let d = ScopeDraft {
            authorization_reference: " ".into(),
            operator: String::new(),
            granted_by: String::new(),
            targets: vec![],
            expires_at_ms: NOW,
            max_probes_per_second: 0,
            timeout_ms: 100,
            authorization_confirmed: false,
            vantage: None,
            ..Default::default()
        };
        let e = approve(&d, "x".into(), "s".into(), None, NOW).unwrap_err();
        for want in [
            DraftError::AuthorizationRequired,
            DraftError::OperatorRequired,
            DraftError::GrantedByRequired,
            DraftError::NotConfirmed,
            DraftError::NoTargets,
            DraftError::ExpiryInPast,
            DraftError::RateOutOfRange,
            DraftError::TimeoutOutOfRange,
            DraftError::NetworkUnknown,
            DraftError::VantageRequired,
        ] {
            assert!(e.contains(&want), "missing {want:?} in {e:?}");
        }
    }

    #[test]
    fn approve_target_rules() {
        let mut d = draft();
        d.targets.push(TargetDraft {
            address: "8.8.8.8".into(),
            ports: vec![53],
            role: TargetRole::Other,
            label: String::new(),
        });
        d.targets.push(TargetDraft {
            address: "192.168.68.1".into(),
            ports: vec![22],
            role: TargetRole::Other,
            label: String::new(),
        });
        d.targets.push(TargetDraft {
            address: "192.168.68.9".into(),
            ports: vec![],
            role: TargetRole::Other,
            label: String::new(),
        });
        d.targets.push(TargetDraft {
            address: "192.168.68.10".into(),
            ports: vec![0],
            role: TargetRole::Other,
            label: String::new(),
        });
        d.targets.push(TargetDraft {
            address: "192.168.68.11".into(),
            ports: (1..=17).collect(),
            role: TargetRole::Other,
            label: String::new(),
        });
        let e = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap_err();
        assert_eq!(
            e,
            vec![
                DraftError::BadAddress {
                    index: 2,
                    reason: AddressReason::NotPrivate
                },
                DraftError::DuplicateAddress { index: 3 },
                DraftError::NoPorts { index: 4 },
                DraftError::BadPort { index: 5 },
                DraftError::TooManyPorts { index: 6 },
            ]
        );
    }

    #[test]
    fn approve_limits_count_validity_and_text() {
        let mut d = draft();
        d.targets = (0..17)
            .map(|i| TargetDraft {
                address: format!("10.0.0.{}", i + 1),
                ports: vec![443],
                role: TargetRole::Other,
                label: String::new(),
            })
            .collect();
        d.expires_at_ms = NOW + MAX_VALIDITY_MS + 1;
        d.operator = "x".repeat(MAX_TEXT + 1);
        d.max_probes_per_second = MAX_PROBES_PER_SECOND + 1;
        d.timeout_ms = MAX_TIMEOUT_MS + 1;
        let e = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap_err();
        for want in [
            DraftError::TooManyTargets,
            DraftError::ExpiryTooFar,
            DraftError::TextTooLong,
            DraftError::RateOutOfRange,
            DraftError::TimeoutOutOfRange,
        ] {
            assert!(e.contains(&want), "missing {want:?} in {e:?}");
        }
        // The limits themselves are allowed.
        let mut ok = draft();
        ok.expires_at_ms = NOW + MAX_VALIDITY_MS;
        ok.max_probes_per_second = MAX_PROBES_PER_SECOND;
        ok.timeout_ms = MIN_TIMEOUT_MS;
        assert!(approve(&ok, "x".into(), "s".into(), Some(net()), NOW).is_ok());
    }

    #[test]
    fn address_policy() {
        use AddressReason::*;
        let cases: &[(&str, Result<(), AddressReason>)] = &[
            ("10.1.2.3", Ok(())),
            ("172.16.0.1", Ok(())),
            ("172.31.255.254", Ok(())),
            ("192.168.1.1", Ok(())),
            ("100.64.0.1", Ok(())),
            ("100.127.255.254", Ok(())),
            ("fd12:3456::1", Ok(())),
            ("::ffff:192.168.1.1", Ok(())),
            ("172.32.0.1", Err(NotPrivate)),
            ("100.128.0.1", Err(NotPrivate)),
            ("192.0.2.10", Err(NotPrivate)),
            ("8.8.8.8", Err(NotPrivate)),
            ("2001:db8::1", Err(NotPrivate)),
            ("::ffff:8.8.8.8", Err(NotPrivate)),
            ("0.0.0.0", Err(Unspecified)),
            ("::", Err(Unspecified)),
            ("127.0.0.1", Err(Loopback)),
            ("::1", Err(Loopback)),
            ("224.0.0.251", Err(Multicast)),
            ("ff02::fb", Err(Multicast)),
            ("255.255.255.255", Err(Broadcast)),
            ("169.254.1.1", Err(LinkLocal)),
            ("fe80::1", Err(LinkLocal)),
            ("router.local", Err(NotAnAddress)),
            ("192.168.1.0/24", Err(NotAnAddress)),
            ("192.168.1.1:80", Err(NotAnAddress)),
            ("", Err(NotAnAddress)),
        ];
        for (a, want) in cases {
            assert_eq!(check_address(a).map(|_| ()), *want, "{a}");
        }
        assert_eq!(check_address(" 10.0.0.1 ").unwrap().to_string(), "10.0.0.1");
    }

    #[test]
    fn ipv6_targets_are_stored_canonically() {
        let mut d = draft();
        d.targets[1].address = "FD00:0:0:0:0:0:0:0A".into();
        let s = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap();
        assert_eq!(s.targets[1].address, "fd00::a");
        assert!(authorize(Some(&s), false, req("fd00::a", 8443), NOW + 1, Some(&net())).is_ok());
    }

    #[test]
    fn at02_without_a_grant_nothing_is_probed() {
        assert_eq!(
            authorize(None, false, req("192.168.68.1", 443), NOW, Some(&net())),
            Err(ScopeDenied::NoGrant)
        );
        let l0 = ProbeRequest {
            level: TestLevel::L0,
            ..req("192.168.68.1", 443)
        };
        assert!(authorize(Some(&scope()), false, l0, NOW + 1, Some(&net())).is_err());
    }

    #[test]
    fn at03_only_the_exact_target_and_port() {
        let s = scope();
        let g = authorize(
            Some(&s),
            false,
            req("192.168.68.1", 443),
            NOW + 1,
            Some(&net()),
        )
        .unwrap();
        assert_eq!(g.addr().to_string(), "192.168.68.1:443");
        assert_eq!(g.scope_id(), "scope-1");
        assert_eq!(g.role(), TargetRole::AdminInterface);
        assert_eq!(g.timeout(), Duration::from_millis(3000));
        for (a, p, want) in [
            ("192.168.68.2", 443, ScopeDenied::TargetNotAllowed),
            ("192.168.68.1", 22, ScopeDenied::PortNotAllowed),
            ("10.20.0.5", 443, ScopeDenied::PortNotAllowed),
            ("8.8.8.8", 443, ScopeDenied::AddressNotAllowed),
        ] {
            assert_eq!(
                authorize(Some(&s), false, req(a, p), NOW + 1, Some(&net())),
                Err(want),
                "{a}:{p}"
            );
        }
    }

    #[test]
    fn a_tampered_scope_still_cannot_reach_public_addresses() {
        let mut s = scope();
        s.targets[0].address = "8.8.8.8".into();
        assert_eq!(
            authorize(Some(&s), false, req("8.8.8.8", 443), NOW + 1, Some(&net())),
            Err(ScopeDenied::AddressNotAllowed)
        );
    }

    #[test]
    fn time_revocation_and_level() {
        let s = scope();
        let r = req("192.168.68.1", 443);
        assert_eq!(
            authorize(Some(&s), true, r, NOW + 1, Some(&net())),
            Err(ScopeDenied::Revoked)
        );
        assert_eq!(
            authorize(Some(&s), false, r, s.expires_at_ms, Some(&net())),
            Err(ScopeDenied::Expired)
        );
        assert_eq!(
            authorize(Some(&s), false, r, NOW - 1, Some(&net())),
            Err(ScopeDenied::Expired)
        );
        let l2 = ProbeRequest {
            level: TestLevel::L2,
            ..r
        };
        assert_eq!(
            authorize(Some(&s), false, l2, NOW + 1, Some(&net())),
            Err(ScopeDenied::LevelExceeded)
        );
    }

    #[test]
    fn another_network_is_refused() {
        let s = scope();
        let r = req("192.168.68.1", 443);
        assert_eq!(
            authorize(Some(&s), false, r, NOW + 1, None),
            Err(ScopeDenied::NetworkUnknown)
        );
        let other_gw = NetworkBinding {
            gateway: "192.168.1.1".into(),
            ..net()
        };
        assert_eq!(
            authorize(Some(&s), false, r, NOW + 1, Some(&other_gw)),
            Err(ScopeDenied::NetworkChanged)
        );
        let other_subnet = NetworkBinding {
            subnet: Some("192.168.68.0/24".into()),
            ..net()
        };
        assert_eq!(
            authorize(Some(&s), false, r, NOW + 1, Some(&other_subnet)),
            Err(ScopeDenied::NetworkChanged)
        );
        // SSID only counts when both sides could read it.
        let ssid_now = NetworkBinding {
            ssid: Some("Guest".into()),
            ..net()
        };
        assert!(authorize(Some(&s), false, r, NOW + 1, Some(&ssid_now)).is_ok());
        let mut with_ssid = s.clone();
        with_ssid.network.ssid = Some("Guest".into());
        let other_ssid = NetworkBinding {
            ssid: Some("Staff".into()),
            ..net()
        };
        assert_eq!(
            authorize(Some(&with_ssid), false, r, NOW + 1, Some(&other_ssid)),
            Err(ScopeDenied::NetworkChanged)
        );
    }

    #[test]
    fn binding_comes_from_the_profile() {
        let raw = include_str!("../../../fixtures/profile/network-profile.example.json");
        let p: NetworkProfile = serde_json::from_str(raw).unwrap();
        let b = binding_from_profile(&p).expect("example has a gateway");
        assert_eq!(Some(b.gateway.clone()), p.default_gateway.value);
        let first = &p.ipv4.value.as_ref().unwrap()[0];
        if let Some(prefix) = first.prefix {
            let subnet = b.subnet.expect("subnet from the first IPv4 with a prefix");
            assert!(subnet.ends_with(&format!("/{prefix}")), "{subnet}");
        }
        let mut no_gw = p.clone();
        no_gw.default_gateway.value = None;
        assert_eq!(binding_from_profile(&no_gw), None);
    }

    #[test]
    fn subnet_is_the_network_address() {
        let raw = include_str!("../../../fixtures/profile/network-profile.example.json");
        let mut p: NetworkProfile = serde_json::from_str(raw).unwrap();
        p.ipv4.value = Some(vec![calm_domain::IpAddress {
            address: "192.168.69.23".into(),
            prefix: Some(22),
            flags: vec![],
        }]);
        assert_eq!(
            binding_from_profile(&p).unwrap().subnet.as_deref(),
            Some("192.168.68.0/22")
        );
        p.ipv4.value = Some(vec![calm_domain::IpAddress {
            address: "10.1.2.3".into(),
            prefix: None,
            flags: vec![],
        }]);
        assert_eq!(binding_from_profile(&p).unwrap().subnet, None);
    }

    // ADR-011: capabilities, ranges, exclusions, NSE scripts.

    #[test]
    fn calms_own_tcp_connect_needs_the_tcp_connect_capability() {
        let mut d = draft();
        d.capabilities = vec![Capability::SynScan];
        let s = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap();
        assert_eq!(
            authorize(
                Some(&s),
                false,
                req("192.168.68.1", 443),
                NOW + 1,
                Some(&net())
            ),
            Err(ScopeDenied::CapabilityNotGranted)
        );
    }

    fn range(cidr: &str, ports: Vec<u16>) -> RangeDraft {
        RangeDraft {
            cidr: cidr.into(),
            ports,
            label: String::new(),
        }
    }

    fn approve_errs(d: &ScopeDraft) -> Vec<DraftError> {
        approve(d, "x".into(), "s".into(), Some(net()), NOW).unwrap_err()
    }

    #[test]
    fn a_draft_without_capabilities_is_tcp_connect_only_as_before() {
        let s = scope();
        assert_eq!(s.capabilities, vec![Capability::TcpConnect]);
        assert_eq!(s.max_level, TestLevel::L1);
        let old: ScopeDraft = serde_json::from_value(serde_json::json!({
            "authorization_reference": "R", "operator": "A", "granted_by": "O",
            "targets": [{"address": "192.168.68.1", "ports": [443], "role": "admin_interface"}],
            "expires_at_ms": NOW + HOUR, "max_probes_per_second": 5, "timeout_ms": 3000,
            "authorization_confirmed": true, "vantage": "guest"
        }))
        .unwrap();
        assert_eq!(old.capabilities, vec![Capability::TcpConnect]);
    }

    #[test]
    fn the_level_is_the_highest_capability_granted() {
        let mut d = draft();
        d.capabilities = vec![
            Capability::TcpConnect,
            Capability::SynScan,
            Capability::TcpConnect,
        ];
        let s = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap();
        assert_eq!(
            s.capabilities,
            vec![Capability::TcpConnect, Capability::SynScan],
            "sorted, deduplicated"
        );
        assert_eq!(s.max_level, TestLevel::L2);
    }

    #[test]
    fn a_scope_needs_at_least_one_capability() {
        let mut d = draft();
        d.capabilities = vec![];
        assert_eq!(approve_errs(&d), vec![DraftError::NoCapabilities]);
    }

    #[test]
    fn ranges_are_private_ipv4_blocks_of_at_most_256_hosts_and_need_exclusions() {
        let mut d = draft();
        d.ranges = vec![range("192.168.68.0/24", vec![22, 80])];
        assert_eq!(approve_errs(&d), vec![DraftError::ExclusionsRequired]);
        d.exclusions = vec!["192.168.68.50".into()];
        let s = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap();
        assert_eq!(s.ranges[0].cidr, "192.168.68.0/24");
        assert_eq!(s.exclusions, vec!["192.168.68.50".to_string()]);

        for (cidr, want) in [
            ("192.168.68.0/23", DraftError::RangeTooLarge { index: 0 }),
            ("8.8.8.0/24", DraftError::BadRange { index: 0 }),
            ("192.168.68.7/24", DraftError::BadRange { index: 0 }), // not the network address
            ("fd00::/120", DraftError::BadRange { index: 0 }),
            ("192.168.68.0", DraftError::BadRange { index: 0 }),
            ("192.168.68.0/33", DraftError::BadRange { index: 0 }),
        ] {
            d.ranges = vec![range(cidr, vec![80])];
            assert_eq!(approve_errs(&d), vec![want], "{cidr}");
        }
        d.ranges = vec![range("192.168.68.0/24", vec![])];
        assert_eq!(
            approve_errs(&d),
            vec![DraftError::BadRangePorts { index: 0 }]
        );
        d.ranges = vec![range("192.168.68.0/24", vec![0])];
        assert_eq!(
            approve_errs(&d),
            vec![DraftError::BadRangePorts { index: 0 }]
        );
        d.ranges = vec![range("192.168.68.0/24", vec![80])];
        d.exclusions = vec!["router".into()];
        assert_eq!(
            approve_errs(&d),
            vec![DraftError::BadExclusion { index: 0 }]
        );
    }

    #[test]
    fn ranges_need_exclusions_or_an_explicit_nothing_to_exclude() {
        let mut d = draft();
        d.ranges = vec![range("192.168.68.0/24", vec![80])];
        d.nothing_to_exclude = true;
        let s = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap();
        assert!(s.nothing_to_exclude && s.exclusions.is_empty());
        // Both at once contradict each other.
        d.exclusions = vec!["192.168.68.50".into()];
        assert_eq!(approve_errs(&d), vec![DraftError::ExclusionsContradict]);
    }

    #[test]
    fn nothing_to_exclude_means_nothing_without_a_range() {
        let mut d = draft();
        d.nothing_to_exclude = true;
        let s = approve(&d, "x".into(), "s".into(), Some(net()), NOW).unwrap();
        assert!(!s.nothing_to_exclude, "only recorded for ranges");
    }

    #[test]
    fn ranges_alone_are_enough_targets() {
        let mut d = draft();
        d.targets = vec![];
        d.ranges = vec![range("10.20.0.0/28", vec![443])];
        d.exclusions = vec!["10.20.0.1".into()];
        assert!(approve(&d, "x".into(), "s".into(), Some(net()), NOW).is_ok());
    }

    #[test]
    fn host_discovery_needs_a_range() {
        let mut d = draft();
        d.capabilities = vec![Capability::HostDiscovery];
        assert_eq!(approve_errs(&d), vec![DraftError::HostDiscoveryNeedsRange]);
    }

    #[test]
    fn nse_scripts_are_allowlisted_and_need_the_capability() {
        let mut d = draft();
        d.nse_scripts = vec!["http-title".into()];
        assert_eq!(approve_errs(&d), vec![DraftError::ScriptsNeedNse]);
        d.capabilities = vec![Capability::Nse];
        assert!(approve(&d, "x".into(), "s".into(), Some(net()), NOW).is_ok());
        d.nse_scripts = vec![];
        assert_eq!(approve_errs(&d), vec![DraftError::NseNeedsScripts]);
        for bad in [
            "smb-brute",
            "http-slowloris",
            "vulners",
            "http-title,ssh-brute",
            "../x",
        ] {
            d.nse_scripts = vec![bad.into()];
            assert_eq!(
                approve_errs(&d),
                vec![DraftError::ScriptNotAllowed { index: 0 }],
                "{bad}"
            );
        }
    }

    #[test]
    fn the_nse_allowlist_holds_only_safe_scripts() {
        // Scripts from the categories ADR-011 forbids (brute, dos, exploit,
        // intrusive, malware, fuzzer, external, broadcast) must never be added.
        assert_eq!(
            NSE_ALLOWLIST,
            ["http-headers", "http-title", "ssh-hostkey", "ssl-cert"]
        );
    }

    #[test]
    fn draft_errors_wire_format() {
        let v = serde_json::to_value(DraftError::BadAddress {
            index: 2,
            reason: AddressReason::NotPrivate,
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "bad_address", "index": 2, "reason": "not_private"})
        );
        let d = serde_json::to_value(ScopeDenied::NetworkChanged).unwrap();
        assert_eq!(d, serde_json::json!({"kind": "network_changed"}));
    }
}
