use crate::process::pid::ProcessInfo;
use crate::scan::candidate::Candidate;

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
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: "Ready".to_string(),
            ..Default::default()
        }
    }
}
