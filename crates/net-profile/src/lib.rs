//! Network profile collection (M1.1). Read-only and local: no packets are sent.
//!
//! - Wi-Fi: CoreWLAN in-process (ADR-008). SSID/BSSID need Location permission.
//! - IP / route / DNS: `ifconfig`, `route -n get default`, `scutil --dns`, parsed
//!   by tested parsers in [`parse`]. Each value records its command as source.

pub mod parse;

#[cfg(target_os = "macos")]
mod macos;

use calm_domain::{
    LocationAuthorization, NetworkProfile, Sourced, WifiInfo, CANONICAL_SCHEMA_VERSION,
};
use time::OffsetDateTime;

/// True when running inside an `.app` bundle. Unbundled binaries (`tauri dev`)
/// never receive the Location prompt (WP1 S1b).
pub fn is_bundled_app() -> bool {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().contains(".app/Contents/MacOS/"))
        .unwrap_or(false)
}

/// Must be called on the main thread on macOS.
pub fn location_authorization() -> LocationAuthorization {
    #[cfg(target_os = "macos")]
    {
        macos::location_authorization()
    }
    #[cfg(not(target_os = "macos"))]
    {
        LocationAuthorization::Unavailable
    }
}

/// Must be called on the main thread on macOS. Returns false if the request
/// could not be issued.
pub fn request_location_authorization() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::request_location_authorization()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    // `route` exits non-zero when there is no default route; output is still parsed.
    Some(String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

fn unsupported_wifi() -> WifiInfo {
    let u = || "unsupported_platform";
    WifiInfo {
        interface: Sourced::unknown("corewlan", u()),
        ssid: Sourced::unknown("corewlan", u()),
        bssid: Sourced::unknown("corewlan", u()),
        channel: Sourced::unknown("corewlan", u()),
        band: Sourced::unknown("corewlan", u()),
        channel_width: Sourced::unknown("corewlan", u()),
        rssi_dbm: Sourced::unknown("corewlan", u()),
        noise_dbm: Sourced::unknown("corewlan", u()),
        security: Sourced::unknown("corewlan", u()),
        phy_mode: Sourced::unknown("corewlan", u()),
        tx_rate_mbps: Sourced::unknown("corewlan", u()),
        country_code: Sourced::unknown("corewlan", u()),
    }
}

/// Collects the full profile. On macOS the Wi-Fi part must run on the main thread
/// (CLLocationManager); the command-based parts are cheap and synchronous.
pub fn collect() -> NetworkProfile {
    let bundled = is_bundled_app();
    let auth = location_authorization();

    #[cfg(target_os = "macos")]
    let wifi = macos::wifi_info(auth, bundled);
    #[cfg(not(target_os = "macos"))]
    let wifi = unsupported_wifi();
    #[cfg(target_os = "macos")]
    let _ = unsupported_wifi; // keep the helper referenced on macOS

    const ROUTE: &str = "route -n get default";
    const DNS: &str = "scutil --dns";

    let route = run("/sbin/route", &["-n", "get", "default"]).map(|o| parse::route_default(&o));
    let route = route.unwrap_or_default();

    // Addresses: the default-route interface, falling back to the Wi-Fi interface.
    let iface = route
        .interface
        .clone()
        .or_else(|| wifi.interface.value.clone());
    let (ifsrc, ifinfo) = match &iface {
        Some(name) => (
            format!("ifconfig {name}"),
            run("/sbin/ifconfig", &[name]).map(|o| parse::ifconfig(&o)),
        ),
        None => ("ifconfig".to_owned(), None),
    };
    let ifinfo = ifinfo.unwrap_or_default();

    let dns = run("/usr/sbin/scutil", &["--dns"])
        .map(|o| parse::scutil_dns_default_servers(&o))
        .unwrap_or_default();

    NetworkProfile {
        schema_version: CANONICAL_SCHEMA_VERSION.to_owned(),
        observed_at: OffsetDateTime::now_utc(),
        location_authorization: auth,
        bundled_app: bundled,
        wifi,
        hardware_address: Sourced::from_option(ifinfo.ether.clone(), ifsrc.clone(), "unknown"),
        hardware_address_private: match ifinfo
            .ether
            .as_deref()
            .and_then(parse::mac_is_locally_administered)
        {
            Some(p) => Sourced::inferred(
                p,
                "IEEE 802 U/L bit",
                if p {
                    "locally_administered"
                } else {
                    "universally_administered"
                },
            ),
            None => Sourced::unknown("IEEE 802 U/L bit", "unknown"),
        },
        ipv4: Sourced::from_option(
            Some(ifinfo.ipv4.clone()).filter(|v| !v.is_empty()),
            ifsrc.clone(),
            "no_ipv4_address",
        ),
        ipv6_scope: Sourced::from_option(
            parse::ipv6_scope(&ifinfo.ipv6).map(str::to_owned),
            ifsrc.clone(),
            "no_ipv6_address",
        ),
        ipv6: Sourced::from_option(
            Some(ifinfo.ipv6.clone()).filter(|v| !v.is_empty()),
            ifsrc,
            "no_ipv6_address",
        ),
        default_gateway: Sourced::from_option(route.gateway, ROUTE, "no_default_route"),
        default_route_interface: Sourced::from_option(route.interface, ROUTE, "no_default_route"),
        dns_servers: Sourced::from_option(
            Some(dns).filter(|v| !v.is_empty()),
            DNS,
            "no_default_resolver",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_never_panics_and_marks_unknowns() {
        let p = collect();
        // Off macOS everything Wi-Fi is unverified with a reason, never invented.
        if cfg!(not(target_os = "macos")) {
            assert!(p.wifi.ssid.value.is_none());
            assert_eq!(p.wifi.ssid.note.as_deref(), Some("unsupported_platform"));
            assert_eq!(p.location_authorization, LocationAuthorization::Unavailable);
        }
        assert!(!p.bundled_app || cfg!(target_os = "macos"));
    }
}
