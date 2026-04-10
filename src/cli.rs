use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "pika",
    about = "Non-stopping memory scanner for Wine/Proton games",
    version,
    long_about = "Pika scans and patches game memory without using ptrace SIGSTOP.\n\
                   Safe for Wine/Proton games with DXVK/VKD3D GPU translation layers."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the JSON-RPC server (Unix socket or stdio)
    Serve {
        /// Unix socket path (default: /tmp/pika.sock)
        #[arg(short, long, default_value = "/tmp/pika.sock")]
        socket: String,

        /// Use stdin/stdout instead of Unix socket
        #[arg(long)]
        stdio: bool,
    },

    /// Start the interactive TUI
    Tui,

    /// List Wine/Proton game processes
    Ps,

    /// Show classified memory map for a process
    Maps {
        /// Process ID
        pid: u32,
    },

    /// Scan process memory for a value
    Scan {
        /// Process ID
        pid: u32,

        /// Value to search for
        value: f64,

        /// Data type: i32, u32, f32, i64, u64, f64, auto
        #[arg(short, long, default_value = "auto")]
        dtype: String,
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

    /// Write a value to an address
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
}
