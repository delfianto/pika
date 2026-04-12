//! Process discovery, memory map parsing, and platform capability checks.
//!
//! This module handles everything pika needs to know about target processes before
//! any memory is read or written: finding Wine/Proton game processes, parsing and
//! classifying their memory maps, and verifying that the host platform supports
//! the required system calls.
//!
//! # Submodules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`pid`] | Wine/Proton game process discovery via `/proc` walking |
//! | [`maps`] | `/proc/[pid]/maps` parsing and region safety classification |
//! | [`platform`] | Platform capability checks (ptrace_scope, CAP_SYS_PTRACE) |
//!
//! # Region safety levels
//!
//! | Level | Scan? | Write? |
//! |---|---|---|
//! | [`Safe`](maps::RegionSafety::Safe) | Yes | Yes |
//! | [`ReadOnly`](maps::RegionSafety::ReadOnly) | Yes | No |
//! | [`Risky`](maps::RegionSafety::Risky) | Cautious | No |
//! | [`NeverTouch`](maps::RegionSafety::NeverTouch) | No | No |
//!
//! For the full classification rule set and design details, see `docs/PROCESS.md`.

pub mod maps;
pub mod pid;
pub mod platform;
