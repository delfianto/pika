pub mod app;
pub mod ui;

use crate::memory::MemoryAccess;
use anyhow::Result;
use std::sync::Arc;

/// Launch the interactive TUI.
pub fn run(_mem: Arc<dyn MemoryAccess>) -> Result<()> {
    // TODO: Implement full TUI with ratatui
    // Planned panels:
    // - Process selector (top)
    // - Scan controls (left)
    // - Address table with live values (center)
    // - Hex viewer (right)
    // - Command/status bar (bottom)

    tracing::info!("TUI mode not yet implemented -- use 'pika serve' for JSON-RPC or CLI commands");
    println!("pika TUI is under construction.");
    println!("Use 'pika serve' to start the JSON-RPC server,");
    println!("or use CLI commands: pika ps, pika scan, pika read, pika write");
    Ok(())
}
