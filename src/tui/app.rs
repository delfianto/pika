//! TUI application state.
//!
//! [`App`] holds the entire state for the terminal user interface: the selected
//! process, scan candidates, active session, and status messages. The planned
//! event loop will mutate this state in response to keyboard input and the
//! [`super::ui::draw`] function will render it each frame.

use crate::scan::candidate::Candidate;
use crate::process::pid::ProcessInfo;

/// Application state for the TUI.
#[derive(Debug, Default)]
pub struct App {
    /// Whether the app should exit.
    pub should_quit: bool,
    /// Currently selected process.
    pub selected_process: Option<ProcessInfo>,
    /// Discovered processes.
    pub processes: Vec<ProcessInfo>,
    /// Current scan candidates.
    pub candidates: Vec<Candidate>,
    /// Status message shown in the bottom bar.
    pub status: String,
    /// Currently active scan session ID.
    pub session_id: Option<String>,
}

impl App {
    /// Create a new application state with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: "Ready".to_string(),
            ..Default::default()
        }
    }
}
