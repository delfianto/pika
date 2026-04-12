# tui — Terminal User Interface

The `tui` module will provide a `ratatui`-based interactive terminal interface for
scanning, filtering, freezing, and patching game values without relying on the CLI or
a web frontend.

**Status: Under construction.** The module defines the application state and a
placeholder rendering function, but the event loop, input handling, and live-updating
panels are not yet implemented.

## Submodules

| Submodule | File | Purpose |
|---|---|---|
| `app` | `tui/app.rs` | Application state struct |
| `ui` | `tui/ui.rs` | Rendering with ratatui widgets |

---

## Planned layout

```
+----------------------------------------------+
|  pika - Memory Scanner                       |  <- Title bar
+----------------------------------------------+
|  Process: Game.exe (PID 12345)               |
|                                              |
|  [Scan controls]  |  [Address table]         |  <- Main content
|  Value: ______    |  ADDR        VALUE  FRZ  |     (split layout)
|  Type:  [auto v]  |  0x14001000  847    [ ]  |
|  [Scan] [Filter]  |  0x14001200  847    [x]  |
|                   |  0x15003400  847    [ ]  |
+----------------------------------------------+
|  Ready | 3 candidates | Session: abc123      |  <- Status bar
+----------------------------------------------+
```

## Planned panels

### Process selector

List all Wine/Proton game processes (from `pid::list_wine_processes`). Arrow keys to
navigate, Enter to attach. Shows PID and process name.

### Scan controls

- Text input for the search value
- Dropdown for data type (`auto`, `i32`, `u32`, `f32`, `i64`, `u64`, `f64`)
- Scan button (first scan) and Filter button (narrow existing session)
- Filter mode selector (`exact`, `increased`, `decreased`, `changed`, `unchanged`)

### Address table

Live-updating table of candidate addresses. Columns:

| Column | Content |
|---|---|
| Address | Hex address (e.g., `0x14001000`) |
| Value | Current value, polled periodically |
| Type | Data type badge (e.g., `i32\|u32`) |
| Confidence | Filter pass count |
| Freeze | Toggle checkbox |

For large candidate lists (thousands), the table should use virtual scrolling to avoid
rendering all rows.

### Hex viewer

16 bytes per row, address gutter on the left, ASCII panel on the right. Matched
candidate bytes highlighted. Clicking a 4-byte or 8-byte group shows typed
interpretations in a tooltip.

### Status bar

Current operation status, candidate count, active session ID, keyboard shortcuts.

---

## State management (`app`)

```rust
pub struct App {
    pub should_quit: bool,
    pub selected_process: Option<ProcessInfo>,
    pub processes: Vec<ProcessInfo>,
    pub candidates: Vec<Candidate>,
    pub status: String,
    pub session_id: Option<String>,
}
```

The event loop will mutate `App` in response to keyboard input and RPC responses.
The `ui::draw` function renders the current state to the terminal each frame.

---

## Planned event loop

```
loop {
    terminal.draw(|frame| ui::draw(frame, &app))?;

    if crossterm::event::poll(tick_rate)? {
        match crossterm::event::read()? {
            Event::Key(key) => handle_key(&mut app, key),
            Event::Resize(..) => { /* ratatui handles this */ }
            _ => {}
        }
    }

    // Poll for live value updates, scan progress, etc.
    poll_updates(&mut app);

    if app.should_quit {
        break;
    }
}
```

The TUI will communicate with the scan engine through the same `MemoryAccess` trait
used by the RPC server, running scans synchronously or in background threads with
progress reporting via channels.
