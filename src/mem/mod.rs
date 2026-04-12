//! Memory access, mutation, and monitoring for target processes.
//!
//! This module is the core of pika's ability to read, write, freeze, patch, and
//! watch memory in a running Wine/Proton game — all without sending `SIGSTOP`.
//!
//! The central abstraction is the [`access::MemoryAccess`] trait, which decouples
//! all higher-level operations from the underlying OS primitives. On Linux the real
//! implementation uses `process_vm_readv` / `process_vm_writev` (zero-stop, safe for
//! DXVK/VKD3D). On other platforms (or in tests) a [`access::MockMemoryAccess`]
//! provides an in-process memory simulation.
//!
//! # Submodules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`access`] | [`MemoryAccess`](access::MemoryAccess) trait + Linux / mock implementations |
//! | [`mod@write`] | Value encoding and writing with **pre-flight region safety checks** |
//! | [`freeze`] | Background threads that repeatedly write a value at a configurable interval |
//! | [`patch`] | Code patching (NOP, arbitrary bytes) via `/proc/pid/mem` with backup/restore |
//! | [`watch`] | Hardware watchpoints via x86-64 debug registers (`DR0`–`DR7`) |
//! | [`disassemble`] | x86-64 disassembly via capstone for instruction analysis |
//!
//! For the full technical design, see `docs/MEM.md`.

pub mod access;
pub mod disassemble;
pub mod freeze;
pub mod patch;
pub mod watch;
pub mod write;
