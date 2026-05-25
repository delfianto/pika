use crate::tui::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};

/// Render the TUI frame.
pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title bar
            Constraint::Min(10),  // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(frame.area());

    // Title
    let title = Paragraph::new(" pika - Memory Scanner")
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    // Main content (placeholder)
    let process_info = match &app.selected_process {
        Some(p) => format!("Attached to: {} (PID {})", p.name, p.pid),
        None => "No process selected. Use 'pika ps' to list processes.".to_string(),
    };
    let content = Paragraph::new(process_info)
        .block(Block::default().borders(Borders::ALL).title("Scanner"));
    frame.render_widget(content, chunks[1]);

    // Status bar
    let status = Paragraph::new(format!(" {}", app.status))
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(status, chunks[2]);
}
