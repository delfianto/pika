//! Memory scanning engine: value search, candidate filtering, AOB patterns, and
//! pointer chain resolution.
//!
//! This module implements the core scan-filter-narrow loop that locates game values
//! in a target process's memory. It is designed for high throughput (hundreds of MB/s)
//! on the large anonymous `rw-p` regions typical of Wine/Proton game heaps.
//!
//! # Submodules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`candidate`] | Candidate addresses, type flags, value patterns |
//! | [`engine`] | SIMD-parallel scanning, session management, AOB support |
//! | [`filter`] | Multi-pass candidate narrowing (exact, increased, decreased, etc.) |
//! | [`mod@pointer`] | Pointer chain resolution via BFS for stable address paths |
//!
//! # Scan workflow
//!
//! 1. **First scan** ([`engine::first_scan`]): Scan all `Safe` regions in parallel,
//!    trying all numeric types simultaneously.
//! 2. **Filter passes** ([`filter::filter_candidates`]): Re-read candidate addresses,
//!    discard those that don't match the new value or comparison criteria.
//! 3. **Convergence**: After 2-4 passes, candidates narrow to a handful of addresses.
//!
//! For the full technical design (SIMD internals, AOB anchoring, pointer chain BFS,
//! candidate model), see `docs/SCAN.md`.

pub mod candidate;
pub mod engine;
pub mod filter;
pub mod pointer;
