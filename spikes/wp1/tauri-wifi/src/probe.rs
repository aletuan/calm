//! macOS-only probe. CLLocationManager lives in a main-thread thread_local; a
//! background ticker hops onto the main thread to poll its authorization
//! status, so no Objective-C delegate class is needed.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use objc2::rc::Retained;
use objc2_core_location::CLLocationManager;
use objc2_core_wlan::CWWiFiClient;
use serde_json::{json, Value};
use tauri::AppHandle;

thread_local! {
    static MANAGER: RefCell<Option<Retained<CLLocationManager>>> = const { RefCell::new(None) };
}

fn auth_name(code: i32) -> &'static str {
    match code {
        0 => "notDetermined",
        1 => "restricted",
        2 => "denied",
        3 => "authorizedAlways",
        4 => "authorizedWhenInUse",
        _ => "unknown",
    }
}

fn mask(v: Option<String>, raw: bool, bssid: bool) -> Value {
    match v {
        None => json!({ "present": false }),
        Some(s) if s.is_empty() => json!({ "present": false }),
        Some(s) if raw => json!({ "present": true, "value": s }),
        Some(s) if bssid => {
            let head: Vec<&str> = s.split(':').take(2).collect();
            json!({ "present": true, "value": format!("{}:**:**:**:**", head.join(":")) })
        }
        Some(s) => {
            let p: String = s.chars().take(2).collect();
            json!({ "present": true, "value": format!("{p}***(len {})", s.chars().count()) })
        }
    }
}

/// Must run on the main thread.
fn snapshot(variant: &str, raw: bool) -> Value {
    let auth: Option<i32> =
        MANAGER.with(|m| m.borrow().as_ref().map(|mgr| unsafe { mgr.authorizationStatus() }.0));
    let client = unsafe { CWWiFiClient::sharedWiFiClient() };
    let iface = unsafe { client.interface() };
    let (name, ssid, bssid, rssi) = match &iface {
        Some(i) => unsafe {
            (
                i.interfaceName().map(|s| s.to_string()),
                i.ssid().map(|s| s.to_string()),
                i.bssid().map(|s| s.to_string()),
                Some(i.rssiValue()),
            )
        },
        None => (None, None, None, None),
    };
    json!({
        "variant": variant,
        "pid": std::process::id(),
        "executable": std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default(),
        "authorization": auth.map(auth_name),
        "interfaceFound": iface.is_some(),
        "interfaceName": name,
        "ssid": mask(ssid, raw, false),
        "bssid": mask(bssid, raw, true),
        "rssi": rssi,
    })
}

fn write(out_dir: &Option<String>, file: &str, v: &Value) {
    let text = serde_json::to_string_pretty(v).unwrap_or_default();
    println!("{text}");
    if let Some(d) = out_dir {
        let _ = std::fs::write(format!("{d}/{file}"), text);
    }
}

pub fn start(app: AppHandle, out_dir: Option<String>, variant: String, raw: bool) {
    // setup() runs on the main thread on macOS.
    let mgr = unsafe { CLLocationManager::new() };
    MANAGER.with(|m| *m.borrow_mut() = Some(mgr));
    write(&out_dir, &format!("s1b-{variant}-before-auth.json"), &snapshot(&format!("{variant}-before-auth"), raw));

    let undecided = MANAGER.with(|m| {
        m.borrow().as_ref().map(|mgr| unsafe { mgr.authorizationStatus() }.0 == 0).unwrap_or(true)
    });
    if undecided {
        MANAGER.with(|m| {
            if let Some(mgr) = m.borrow().as_ref() {
                unsafe { mgr.requestWhenInUseAuthorization() };
            }
        });
    }

    std::thread::spawn(move || {
        let started = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let timed_out = started.elapsed() > Duration::from_secs(90);
            let (tx, rx) = std::sync::mpsc::channel::<bool>();
            let (od, var, a2) = (out_dir.clone(), variant.clone(), app.clone());
            let _ = app.run_on_main_thread(move || {
                let code = MANAGER.with(|m| {
                    m.borrow().as_ref().map(|mgr| unsafe { mgr.authorizationStatus() }.0).unwrap_or(0)
                });
                if code != 0 || timed_out {
                    let reason = if code != 0 { "decided" } else { "timeout-90s" };
                    let mut v = snapshot(&format!("{var}-after"), raw);
                    v["finish_reason"] = json!(reason);
                    write(&od, &format!("s1b-{var}-after.json"), &v);
                    let _ = tx.send(true);
                    a2.exit(0);
                } else {
                    let _ = tx.send(false);
                }
            });
            if rx.recv_timeout(Duration::from_secs(5)).unwrap_or(false) {
                break;
            }
        }
    });
}
