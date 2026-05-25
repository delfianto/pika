use clap::{Parser, Subcommand};

/// Default Unix socket path for the pika daemon.
pub const DEFAULT_SOCKET: &str = "/tmp/pika.sock";

#[derive(Parser, Debug)]
#[command(
    name = "pika",
    about = "Non-stopping memory scanner for Wine/Proton games",
    version,
    long_about = "Pika scans and patches game memory without using ptrace SIGSTOP.\n\
                   Safe for Wine/Proton games with DXVK/VKD3D GPU translation layers.\n\n\
                   Stateful commands (scan, filter, freeze) require a running daemon.\n\
                   Start one with: pika serve &"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Path to the daemon Unix socket
    #[arg(short, long, global = true, default_value = DEFAULT_SOCKET)]
    pub socket: String,

    /// Output as JSON (machine-readable)
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the JSON-RPC server daemon
    Serve {
        /// Use stdin/stdout instead of Unix socket
        #[arg(long)]
        stdio: bool,
    },

    /// Start the interactive TUI (not yet implemented)
    Tui,

    /// List Wine/Proton game processes
    Ps,

    /// Show classified memory map for a process
    Maps {
        /// Process ID
        pid: u32,
    },

    /// Scan process memory for a value (requires daemon)
    Scan {
        /// Process ID
        pid: u32,

        /// Value to search for
        value: f64,

        /// Data type: i32, u32, f32, i64, u64, f64, auto
        #[arg(short, long, default_value = "auto")]
        dtype: String,
    },

    /// Filter candidates from a previous scan (requires daemon)
    Filter {
        /// Session ID from a previous scan
        session_id: String,

        /// New value to filter by
        new_value: f64,

        /// Filter mode: exact, not-equal, increased, decreased, changed, unchanged
        #[arg(short, long, default_value = "exact")]
        mode: String,
    },

    /// List active scan sessions (requires daemon)
    Sessions,

    /// Discard a scan session (requires daemon)
    Discard {
        /// Session ID to discard
        session_id: String,
    },

    /// Read memory at an address
    Read {
        /// Process ID
        pid: u32,

        /// Hex address (e.g., 0x140001000)
        address: String,

        /// Number of bytes to read
        #[arg(short, long, default_value = "128")]
        length: usize,
    },

    /// Write a value to an address (requires daemon)
    Write {
        /// Process ID
        pid: u32,

        /// Hex address
        address: String,

        /// Value to write
        value: f64,

        /// Data type: i32, u32, f32, i64, u64, f64
        #[arg(short, long)]
        dtype: String,
    },

    /// Freeze a value at an address (requires daemon)
    Freeze {
        /// Process ID
        pid: u32,

        /// Hex address
        address: String,

        /// Value to freeze
        value: f64,

        /// Data type: i32, u32, f32, i64, u64, f64
        #[arg(short, long)]
        dtype: String,

        /// Write interval in milliseconds
        #[arg(short, long, default_value = "100")]
        interval: u64,
    },

    /// Write a value to ALL candidates in a session (requires daemon)
    WriteAll {
        /// Session ID
        session_id: String,

        /// Value to write
        value: f64,

        /// Data type: i32, u32, f32, i64, u64, f64
        #[arg(short, long)]
        dtype: String,

        /// Allow writing to more than 16 addresses
        #[arg(long)]
        force: bool,
    },

    /// Freeze ALL candidates in a session (requires daemon)
    FreezeAll {
        /// Session ID
        session_id: String,

        /// Value to freeze at
        value: f64,

        /// Data type: i32, u32, f32, i64, u64, f64
        #[arg(short, long)]
        dtype: String,

        /// Write interval in milliseconds
        #[arg(short, long, default_value = "100")]
        interval: u64,

        /// Allow freezing more than 16 addresses
        #[arg(long)]
        force: bool,
    },

    /// Unfreeze a previously frozen address (requires daemon)
    Unfreeze {
        /// Hex address to unfreeze
        address: String,
    },

    /// List all active freezes (requires daemon)
    FreezeList,

    /// Disassemble instructions at an address (Linux only)
    Disasm {
        /// Process ID
        pid: u32,

        /// Hex address
        address: String,

        /// Number of instructions
        #[arg(short = 'n', long, default_value = "20")]
        count: usize,
    },

    /// Scan for a byte pattern with wildcards (requires daemon)
    Aob {
        /// Process ID
        pid: u32,

        /// Byte pattern (e.g., "48 89 5C 24 ?? 57")
        pattern: String,

        /// Include read-only (code) regions
        #[arg(long)]
        include_readonly: bool,
    },

    /// Scan for pointer chains to an address (requires daemon)
    PointerScan {
        /// Process ID
        pid: u32,

        /// Target hex address
        address: String,

        /// Maximum chain depth
        #[arg(long, default_value = "5")]
        max_depth: usize,

        /// Maximum struct offset
        #[arg(long, default_value = "4096")]
        max_offset: i64,
    },

    /// Set a hardware watchpoint on an address (Linux only, requires daemon)
    Watch {
        /// Process ID
        pid: u32,

        /// Hex address to watch
        address: String,

        /// Watch mode: write (default) or access (read+write)
        #[arg(long, default_value = "write")]
        mode: String,

        /// Watch size in bytes: 1, 2, 4 (default), or 8
        #[arg(long, default_value = "4")]
        size: u8,

        /// Capture full register state on each hit
        #[arg(long)]
        detail: bool,
    },

    /// Show hits from a watchpoint (requires daemon)
    WatchHits {
        /// Watch ID returned by the watch command
        watch_id: String,
    },

    /// Stop a hardware watchpoint (requires daemon)
    WatchStop {
        /// Watch ID to stop
        watch_id: String,
    },

    /// List active watchpoints (requires daemon)
    WatchList,

    /// NOP an instruction at a code address (requires daemon)
    Nop {
        /// Process ID
        pid: u32,

        /// Hex address of instruction to NOP
        address: String,

        /// Number of bytes to NOP (default: auto-detect from instruction size)
        #[arg(short = 'n', long)]
        size: Option<usize>,
    },

    /// Patch bytes at a code address (requires daemon)
    Patch {
        /// Process ID
        pid: u32,

        /// Hex address to patch
        address: String,

        /// Hex bytes to write (e.g., "90 90 90" or "eb 05")
        bytes: String,
    },

    /// Restore a previously patched code address (requires daemon)
    Restore {
        /// Process ID
        pid: u32,

        /// Hex address to restore
        address: String,
    },

    /// List all active code patches (requires daemon)
    PatchList,
}
