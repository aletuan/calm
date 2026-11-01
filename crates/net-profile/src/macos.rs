//! macOS collectors. CoreWLAN and CoreLocation are called in-process (ADR-008:
//! Location is granted per signed executable and is not inherited by children).
//! All functions that touch CLLocationManager must run on the main thread.

use std::cell::RefCell;

use calm_domain::{LocationAuthorization, Sourced, WifiInfo};
use objc2::rc::Retained;
use objc2::MainThreadMarker;
use objc2_core_location::CLLocationManager;
use objc2_core_wlan::CWWiFiClient;

const SRC: &str = "corewlan";

thread_local! {
    static MANAGER: RefCell<Option<Retained<CLLocationManager>>> = const { RefCell::new(None) };
}

fn with_manager<R>(f: impl FnOnce(&CLLocationManager) -> R) -> Option<R> {
    MainThreadMarker::new()?;
    MANAGER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(unsafe { CLLocationManager::new() });
        }
        slot.as_deref().map(f)
    })
}

pub fn location_authorization() -> LocationAuthorization {
    with_manager(|m| LocationAuthorization::from_cl_code(unsafe { m.authorizationStatus() }.0))
        .unwrap_or(LocationAuthorization::Unavailable)
}

/// Shows the system prompt if the decision is still open. Returns false when
/// not called on the main thread.
pub fn request_location_authorization() -> bool {
    with_manager(|m| unsafe { m.requestWhenInUseAuthorization() }).is_some()
}

fn band_name(raw: isize) -> Option<String> {
    match raw {
        1 => Some("2.4 GHz".into()),
        2 => Some("5 GHz".into()),
        3 => Some("6 GHz".into()),
        _ => None,
    }
}

fn width_name(raw: isize) -> Option<String> {
    match raw {
        1 => Some("20 MHz".into()),
        2 => Some("40 MHz".into()),
        3 => Some("80 MHz".into()),
        4 => Some("160 MHz".into()),
        _ => None,
    }
}

fn security_name(raw: isize) -> Option<String> {
    let s = match raw {
        0 => "Open",
        1 => "WEP",
        2 => "WPA Personal",
        3 => "WPA/WPA2 Personal",
        4 => "WPA2 Personal",
        5 => "Personal",
        6 => "Dynamic WEP",
        7 => "WPA Enterprise",
        8 => "WPA/WPA2 Enterprise",
        9 => "WPA2 Enterprise",
        10 => "Enterprise",
        11 => "WPA3 Personal",
        12 => "WPA3 Enterprise",
        13 => "WPA2/WPA3 Personal",
        14 => "OWE",
        15 => "OWE Transition",
        _ => return None,
    };
    Some(s.into())
}

fn phy_name(raw: isize) -> Option<String> {
    let s = match raw {
        1 => "802.11a",
        2 => "802.11b",
        3 => "802.11g",
        4 => "802.11n",
        5 => "802.11ac",
        6 => "802.11ax",
        7 => "802.11be",
        _ => return None,
    };
    Some(s.into())
}

fn unknown_all(note: &str) -> WifiInfo {
    WifiInfo {
        interface: Sourced::unknown(SRC, note),
        ssid: Sourced::unknown(SRC, note),
        bssid: Sourced::unknown(SRC, note),
        channel: Sourced::unknown(SRC, note),
        band: Sourced::unknown(SRC, note),
        channel_width: Sourced::unknown(SRC, note),
        rssi_dbm: Sourced::unknown(SRC, note),
        noise_dbm: Sourced::unknown(SRC, note),
        security: Sourced::unknown(SRC, note),
        phy_mode: Sourced::unknown(SRC, note),
        tx_rate_mbps: Sourced::unknown(SRC, note),
        country_code: Sourced::unknown(SRC, note),
    }
}

/// Reads the current Wi-Fi association. SSID/BSSID are `None` unless this
/// process holds Location authorization; the note says which reason applies.
pub fn wifi_info(auth: LocationAuthorization, bundled: bool) -> WifiInfo {
    let client = unsafe { CWWiFiClient::sharedWiFiClient() };
    let Some(iface) = (unsafe { client.interface() }) else {
        return unknown_all("no_wifi_interface");
    };
    let identity_note = match (auth, bundled) {
        (LocationAuthorization::Authorized, _) => "not_associated_or_hidden",
        (_, false) => "unbundled_dev_build_cannot_get_location",
        (LocationAuthorization::Denied | LocationAuthorization::Restricted, _) => {
            "location_permission_denied"
        }
        _ => "location_permission_not_granted",
    };
    unsafe {
        let channel = iface.wlanChannel();
        let rssi = iface.rssiValue();
        let noise = iface.noiseMeasurement();
        let rate = iface.transmitRate();
        WifiInfo {
            interface: Sourced::from_option(
                iface.interfaceName().map(|s| s.to_string()),
                SRC,
                "unknown",
            ),
            ssid: Sourced::from_option(iface.ssid().map(|s| s.to_string()), SRC, identity_note),
            bssid: Sourced::from_option(iface.bssid().map(|s| s.to_string()), SRC, identity_note),
            channel: Sourced::from_option(
                channel
                    .as_ref()
                    .map(|c| c.channelNumber() as u32)
                    .filter(|n| *n > 0),
                SRC,
                "not_associated",
            ),
            band: Sourced::from_option(
                channel.as_ref().and_then(|c| band_name(c.channelBand().0)),
                SRC,
                "unknown",
            ),
            channel_width: Sourced::from_option(
                channel
                    .as_ref()
                    .and_then(|c| width_name(c.channelWidth().0)),
                SRC,
                "unknown",
            ),
            rssi_dbm: Sourced::from_option(
                Some(rssi as i64).filter(|v| *v != 0),
                SRC,
                "not_associated",
            ),
            noise_dbm: Sourced::from_option(
                Some(noise as i64).filter(|v| *v != 0),
                SRC,
                "not_associated",
            ),
            security: Sourced::from_option(security_name(iface.security().0), SRC, "unknown"),
            phy_mode: Sourced::from_option(
                phy_name(iface.activePHYMode().0),
                SRC,
                "not_associated",
            ),
            tx_rate_mbps: Sourced::from_option(
                Some(rate).filter(|v| *v > 0.0),
                SRC,
                "not_associated",
            ),
            country_code: Sourced::from_option(
                iface.countryCode().map(|s| s.to_string()),
                SRC,
                "unknown",
            ),
        }
    }
}
