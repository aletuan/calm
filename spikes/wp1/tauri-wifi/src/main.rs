//! WP1 S1b — Tauri app reads Wi-Fi identity in its own Rust process.
//!
//! Sequence (no window is opened):
//!   1. snapshot before authorization        -> s1b-<variant>-before-auth.json
//!   2. CLLocationManager.requestWhenInUseAuthorization (system prompt)
//!   3. poll authorizationStatus on the main thread every 500 ms (no delegate needed)
//!   4. snapshot after a decision or 90 s timeout -> s1b-<variant>-after.json
//!   5. exit
//!
//! Args: `--out-dir DIR --variant NAME --raw`

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "macos")]
mod probe;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn main() {
    let out_dir = arg("--out-dir");
    let variant = arg("--variant").unwrap_or_else(|| "tauri".into());
    let raw = std::env::args().any(|a| a == "--raw");

    tauri::Builder::default()
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            probe::start(app.handle().clone(), out_dir.clone(), variant.clone(), raw);
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (&out_dir, &variant, raw);
                app.handle().exit(2);
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running spike");
}
