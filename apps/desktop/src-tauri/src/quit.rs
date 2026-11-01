//! Saving the running capture when the app quits (Cmd+Q or closing the
//! window). Same rule as "save on Stop" in the UI: the user's switch is on,
//! a session is active, and there is something to save.

use std::sync::atomic::{AtomicBool, Ordering};

/// The UI's "on stop or quit, save to…" switch (default on).
pub struct AutoSave(pub AtomicBool);

impl Default for AutoSave {
    fn default() -> Self {
        AutoSave(AtomicBool::new(true))
    }
}

/// Set once the quit-time save has started, so a second quit request exits.
#[derive(Default)]
pub struct Quitting(pub AtomicBool);

impl Quitting {
    /// True the first time only.
    pub fn begin(&self) -> bool {
        !self.0.swap(true, Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QuitCheck {
    pub autosave: bool,
    pub capture_running: bool,
    pub packets: u64,
    pub store_ready: bool,
    pub has_active_session: bool,
}

pub fn should_save(c: QuitCheck) -> bool {
    c.autosave && c.capture_running && c.packets > 0 && c.store_ready && c.has_active_session
}

pub fn quit_label(base: &str) -> String {
    format!("{base} · saved on quit")
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: QuitCheck = QuitCheck {
        autosave: true,
        capture_running: true,
        packets: 10,
        store_ready: true,
        has_active_session: true,
    };

    #[test]
    fn saves_only_when_everything_lines_up() {
        assert!(should_save(OK));
        assert!(
            !should_save(QuitCheck {
                autosave: false,
                ..OK
            }),
            "user turned it off"
        );
        assert!(
            !should_save(QuitCheck {
                capture_running: false,
                ..OK
            }),
            "stopped capture was saved on Stop"
        );
        assert!(
            !should_save(QuitCheck { packets: 0, ..OK }),
            "nothing captured"
        );
        assert!(!should_save(QuitCheck {
            store_ready: false,
            ..OK
        }));
        assert!(!should_save(QuitCheck {
            has_active_session: false,
            ..OK
        }));
    }

    #[test]
    fn second_quit_request_goes_through() {
        let q = Quitting::default();
        assert!(q.begin());
        assert!(!q.begin());
    }

    #[test]
    fn label_says_how_it_was_saved() {
        assert_eq!(
            quit_label("This Mac — 3 flows, 00:10 capture"),
            "This Mac — 3 flows, 00:10 capture · saved on quit"
        );
    }
}
