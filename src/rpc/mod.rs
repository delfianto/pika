//! JSON-RPC 2.0 server and client for the pika daemon.
//!
//! All stateful operations (scan sessions, freeze loops, watchpoints, code patches)
//! live in the daemon process. The CLI and future frontend communicate with the
//! daemon exclusively through this RPC layer.
//!
//! # Submodules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`server`] | Unix socket and stdio JSON-RPC server |
//! | [`client`] | Async client for CLI commands |
//! | [`methods`] | Method dispatch and handler implementations |
//! | [`types`] | JSON-RPC 2.0 wire types and error codes |
//!
//! Heavy handlers (`scan.start`, `scan.filter`, `scan.aob`, `pointer.scan`) are
//! offloaded to [`tokio::task::spawn_blocking`] so the async executor is never
//! starved while rayon parallelises across memory regions.
//!
//! For the full protocol design, method catalog, and architecture details, see
//! `docs/RPC.md`.

pub mod client;
pub mod methods;
pub mod server;
pub mod types;
