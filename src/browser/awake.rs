//! Keeps this Mac's display on while the owner drives a page from the phone
//!
//! A headless Chrome on macOS draws a page only while a display is on: with
//! the display asleep, `Page.startScreencast` sends no images and
//! screenshots hang, so a takeover would show the phone a blank page

use tokio::process::{Child, Command};

/// Where macOS keeps `caffeinate`
const CAFFEINATE: &str = "/usr/bin/caffeinate";

/// The display stays on until this is dropped
pub struct DisplayAwake(Option<Child>);

impl DisplayAwake {
    /// Turns the display on, as user activity would, and keeps it from
    /// sleeping; elsewhere than macOS, or when `caffeinate` cannot start,
    /// nothing is held and the takeover goes on without it
    pub fn hold() -> Self {
        if !cfg!(target_os = "macos") {
            return Self(None);
        }

        // `-u` wakes the display and `-d` keeps it on for as long as this
        // runs; killing it on drop lets the display sleep again
        let child = Command::new(CAFFEINATE).args(["-d", "-u"]).spawn();
        match child {
            Ok(child) => Self(Some(child)),
            Err(error) => {
                tracing::warn!(%error, "could not keep the display on for a takeover");

                Self(None)
            }
        }
    }
}

impl Drop for DisplayAwake {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.start_kill();
        }
    }
}
