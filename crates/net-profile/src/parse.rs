//! Parsers for macOS command output. Pure functions, tested with fixtures.
//! Unknown or malformed input yields `None`/empty — never a guessed value.

use calm_domain::IpAddress;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub gateway: Option<String>,
    pub interface: Option<String>,
}

/// `route -n get default`
pub fn route_default(out: &str) -> DefaultRoute {
    let mut r = DefaultRoute::default();
    for line in out.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("gateway:") {
            r.gateway = Some(v.trim().to_owned()).filter(|s| !s.is_empty());
        } else if let Some(v) = line.strip_prefix("interface:") {
            r.interface = Some(v.trim().to_owned()).filter(|s| !s.is_empty());
        }
    }
    r
}

/// `scutil --dns`: nameservers of the *default* resolvers, i.e. resolvers in the
/// unscoped section that have no `domain`. Order preserved, duplicates removed.
pub fn scutil_dns_default_servers(out: &str) -> Vec<String> {
    let mut servers: Vec<String> = Vec::new();
    let mut in_unscoped = false;
    let mut current: Vec<String> = Vec::new();
    let mut current_has_domain = false;
    let mut in_resolver = false;

    let flush = |servers: &mut Vec<String>, current: &mut Vec<String>, has_domain: bool| {
        if !has_domain {
            for s in current.drain(..) {
                if !servers.contains(&s) {
                    servers.push(s);
                }
            }
        }
        current.clear();
    };

    for raw in out.lines() {
        let line = raw.trim();
        if line == "DNS configuration" {
            in_unscoped = true;
            continue;
        }
        if line.starts_with("DNS configuration (") {
            if in_resolver {
                flush(&mut servers, &mut current, current_has_domain);
            }
            in_unscoped = false;
            in_resolver = false;
            continue;
        }
        if !in_unscoped {
            continue;
        }
        if line.starts_with("resolver #") {
            if in_resolver {
                flush(&mut servers, &mut current, current_has_domain);
            }
            in_resolver = true;
            current_has_domain = false;
            continue;
        }
        if !in_resolver {
            continue;
        }
        if line.starts_with("domain") && line.contains(':') {
            current_has_domain = true;
        } else if line.starts_with("nameserver[") {
            if let Some((_, v)) = line.split_once(':') {
                let v = v.trim();
                if !v.is_empty() {
                    current.push(v.to_owned());
                }
            }
        }
    }
    if in_unscoped && in_resolver {
        flush(&mut servers, &mut current, current_has_domain);
    }
    servers
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct IfconfigInfo {
    pub ether: Option<String>,
    pub ipv4: Vec<IpAddress>,
    pub ipv6: Vec<IpAddress>,
    pub status_active: Option<bool>,
}

fn netmask_hex_to_prefix(hex: &str) -> Option<u8> {
    let h = hex.strip_prefix("0x")?;
    u32::from_str_radix(h, 16)
        .ok()
        .map(|m| m.count_ones() as u8)
}

/// `ifconfig <iface>`
pub fn ifconfig(out: &str) -> IfconfigInfo {
    let mut info = IfconfigInfo::default();
    for raw in out.lines() {
        let line = raw.trim();
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("ether") => info.ether = parts.next().map(str::to_owned),
            Some("inet") => {
                let Some(addr) = parts.next() else { continue };
                let rest: Vec<&str> = parts.collect();
                let prefix = rest
                    .iter()
                    .position(|t| *t == "netmask")
                    .and_then(|i| rest.get(i + 1))
                    .and_then(|m| netmask_hex_to_prefix(m));
                info.ipv4.push(IpAddress {
                    address: addr.to_owned(),
                    prefix,
                    flags: vec![],
                });
            }
            Some("inet6") => {
                let Some(addr) = parts.next() else { continue };
                let rest: Vec<&str> = parts.collect();
                let prefix = rest
                    .iter()
                    .position(|t| *t == "prefixlen")
                    .and_then(|i| rest.get(i + 1))
                    .and_then(|p| p.parse().ok());
                let flags = rest
                    .iter()
                    .filter(|t| {
                        matches!(
                            **t,
                            "secured" | "temporary" | "autoconf" | "deprecated" | "dynamic"
                        )
                    })
                    .map(|t| (*t).to_owned())
                    .collect();
                let address = addr.split('%').next().unwrap_or(addr).to_owned();
                info.ipv6.push(IpAddress {
                    address,
                    prefix,
                    flags,
                });
            }
            Some("status:") => info.status_active = parts.next().map(|s| s == "active"),
            _ => {}
        }
    }
    info
}

/// IEEE 802 U/L bit: bit 1 of the first octet set means locally administered,
/// which is how macOS Private Wi-Fi Addresses are formed. `None` if unparsable.
pub fn mac_is_locally_administered(mac: &str) -> Option<bool> {
    let first = mac.split(':').next()?;
    if first.is_empty() || first.len() > 2 || mac.split(':').count() != 6 {
        return None;
    }
    u8::from_str_radix(first, 16).ok().map(|b| b & 0x02 != 0)
}

/// Widest IPv6 scope present: "global", "unique_local", "link_local_only".
/// `None` when there is no IPv6 address at all.
pub fn ipv6_scope(addrs: &[IpAddress]) -> Option<&'static str> {
    if addrs.is_empty() {
        return None;
    }
    let first_hextet = |a: &str| -> Option<u16> {
        let h = a.split(':').next()?;
        if h.is_empty() {
            return Some(0);
        }
        u16::from_str_radix(h, 16).ok()
    };
    let mut ula = false;
    for a in addrs {
        let Some(h) = first_hextet(&a.address) else {
            continue;
        };
        if (h & 0xffc0) == 0xfe80 {
            continue; // link-local fe80::/10
        }
        if (h & 0xfe00) == 0xfc00 {
            ula = true; // fc00::/7
            continue;
        }
        if a.address != "::1" && h != 0 {
            return Some("global");
        }
    }
    Some(if ula {
        "unique_local"
    } else {
        "link_local_only"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_default_parses_gateway_and_interface() {
        let r = route_default(include_str!("../fixtures/route-default.txt"));
        assert_eq!(r.gateway.as_deref(), Some("192.0.2.1"));
        assert_eq!(r.interface.as_deref(), Some("en0"));
    }

    #[test]
    fn route_default_missing_route_is_unknown_not_guessed() {
        assert_eq!(
            route_default(include_str!("../fixtures/route-none.txt")),
            DefaultRoute::default()
        );
        assert_eq!(route_default(""), DefaultRoute::default());
    }

    #[test]
    fn scutil_dns_takes_only_default_unscoped_resolvers() {
        let s = scutil_dns_default_servers(include_str!("../fixtures/scutil-dns.txt"));
        assert_eq!(s, vec!["198.51.100.53", "198.51.100.54", "192.0.2.1"]);
        assert!(
            !s.contains(&"203.0.113.99".to_owned()),
            "scoped resolver must be excluded"
        );
    }

    #[test]
    fn ifconfig_parses_addresses() {
        let i = ifconfig(include_str!("../fixtures/ifconfig-en0.txt"));
        assert_eq!(i.ether.as_deref(), Some("9e:65:00:11:22:33"));
        assert_eq!(i.ipv4.len(), 1);
        assert_eq!(i.ipv4[0].address, "192.0.2.108");
        assert_eq!(i.ipv4[0].prefix, Some(24));
        assert_eq!(i.ipv6.len(), 3);
        assert_eq!(i.ipv6[0].address, "fe80::186c:5366:825e:7217");
        assert!(i.ipv6[2].flags.contains(&"temporary".to_owned()));
        assert_eq!(i.status_active, Some(true));
    }

    #[test]
    fn malformed_input_yields_empty() {
        assert_eq!(ifconfig("garbage\ninet\ninet6"), IfconfigInfo::default());
        assert!(scutil_dns_default_servers("nameserver[0] : 1.2.3.4").is_empty());
    }
    #[test]
    fn private_mac_detected_by_ul_bit() {
        assert_eq!(mac_is_locally_administered("9e:65:84:a1:b9:73"), Some(true));
        assert_eq!(
            mac_is_locally_administered("a4:83:e7:00:11:22"),
            Some(false)
        );
        assert_eq!(mac_is_locally_administered("not-a-mac"), None);
        assert_eq!(mac_is_locally_administered("9e:65:84"), None);
    }

    fn v6(a: &str) -> IpAddress {
        IpAddress {
            address: a.into(),
            prefix: Some(64),
            flags: vec![],
        }
    }

    #[test]
    fn ipv6_scope_classifies() {
        assert_eq!(ipv6_scope(&[]), None);
        assert_eq!(
            ipv6_scope(&[v6("fe80::186c:5366:825e:7217")]),
            Some("link_local_only")
        );
        assert_eq!(
            ipv6_scope(&[v6("fe80::1"), v6("fd12:3456::1")]),
            Some("unique_local")
        );
        assert_eq!(
            ipv6_scope(&[v6("fe80::1"), v6("2001:db8::99")]),
            Some("global")
        );
    }
}
