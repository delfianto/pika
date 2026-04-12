//! # Pika — Non-stopping memory scanner for Wine/Proton games
//!
//! Pika is a memory scanner and value patcher designed specifically for Wine/Proton
//! games on Linux. Unlike traditional memory editors (scanmem, PINCE, GameConqueror),
//! pika avoids `ptrace PTRACE_ATTACH` which sends `SIGSTOP` to the entire process
//! tree — freezing DXVK/VKD3D mid-GPU-submission and deadlocking the wineserver.
//!
//! Instead, pika uses [`process_vm_readv`] / [`process_vm_writev`] (Linux 3.2+) which
//! read and write another process's memory **without stopping it**, combined with
//! smart `/proc/[pid]/maps` region classification to never touch GPU driver mappings
//! or Wine internal shared memory.
//!
//! # Architecture
//!
//! The crate is organized into five modules:
//!
//! - [`mem`] — Memory access abstraction, value writing with safety checks, freeze
//!   loops, code patching, hardware watchpoints, and disassembly.
//! - [`process`] — Process discovery, `/proc/[pid]/maps` parsing and region safety
//!   classification, and platform capability checks.
//! - [`scan`] — SIMD-accelerated scan engine, candidate management, multi-pass
//!   filtering, AOB pattern scanning, and pointer chain resolution.
//! - [`rpc`] — JSON-RPC 2.0 server/client over Unix domain sockets or stdio,
//!   providing the daemon interface for all stateful operations.
//! - [`tui`] — Terminal user interface (under construction).
//!
//! Additionally, [`cli`] defines the command-line interface via `clap`.
//!
//! # Usage modes
//!
//! Pika can operate in three modes:
//!
//! 1. **Daemon mode** (`pika serve`): Starts a JSON-RPC server on a Unix socket.
//!    Stateful commands (scan, filter, freeze) require a running daemon.
//! 2. **CLI mode** (`pika scan`, `pika read`, etc.): Sends JSON-RPC requests to
//!    a running daemon for stateful operations, or executes locally for read-only
//!    commands like `pika ps`.
//! 3. **TUI mode** (`pika tui`): Interactive terminal interface (planned).
//!
//! # Safety model
//!
//! Every memory write is gated by a pre-flight region safety check. The write engine
//! re-reads `/proc/[pid]/maps` immediately before writing and re-classifies the
//! target address. Writes are rejected unless the region is classified as
//! [`process::maps::RegionSafety::Safe`]. This prevents writing to regions that may
//! have been remapped by DXVK or the Vulkan driver between the scan and the write.
//!
//! [`process_vm_readv`]: https://man7.org/linux/man-pages/man2/process_vm_readv.2.html
//! [`process_vm_writev`]: https://man7.org/linux/man-pages/man2/process_vm_writev.2.html

pub mod cli;
pub mod mem;
pub mod process;
pub mod rpc;
pub mod scan;
pub mod tui;
