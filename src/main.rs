use anyhow::Result;
use clap::Parser;
use pika::cli::{Cli, Command};
use pika::rpc::client::RpcClient;
use serde_json::json;

/// Print `$data` as pretty JSON when `$json` is true, otherwise run `$human`.
macro_rules! output {
    ($json:expr, $data:expr, $human:block) => {
        if $json {
            println!("{}", serde_json::to_string_pretty(&$data)?);
        } else $human
    };
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .init();

    let client = RpcClient::new(&cli.socket);
    let output_json = cli.json;

    match cli.command {
        // ── Server / TUI (non-client commands) ──────────────────────────
        Command::Serve { stdio } => {
            run_platform_check();
            let mem = create_memory_access();
            if stdio {
                pika::rpc::server::serve_stdio(mem).await?;
            } else {
                pika::rpc::server::serve_unix_socket(&cli.socket, mem).await?;
            }
        }

        Command::Tui => {
            let mem = create_memory_access();
            pika::tui::run(mem)?;
        }

        // ── Local-only commands (no daemon needed) ──────────────────────
        Command::Ps => {
            let processes = pika::process::pid::list_wine_processes()?;
            output!(output_json, processes, {
                if processes.is_empty() {
                    println!("No Wine/Proton game processes found.");
                } else {
                    println!("{:<8} NAME", "PID");
                    for p in &processes {
                        println!("{:<8} {}", p.pid, p.name);
                    }
                }
            });
        }

        // ── Daemon-routed commands ──────────────────────────────────────
        Command::Maps { pid } => {
            let result = client.call("maps.get", json!({"pid": pid})).await?;
            output!(output_json, result, {
                let regions = result.as_array().unwrap_or(&Vec::new()).clone();
                println!(
                    "{:<20} {:<20} {:<6} {:<12} PATH",
                    "START", "END", "PERMS", "SAFETY"
                );
                for r in &regions {
                    println!(
                        "{:<20} {:<20} {:<6} {:<12} {}",
                        format!("{:#x}", r["start"].as_u64().unwrap_or(0)),
                        format!("{:#x}", r["end"].as_u64().unwrap_or(0)),
                        r["permissions"].as_str().unwrap_or(""),
                        r["safety"].as_str().unwrap_or(""),
                        r["pathname"].as_str().unwrap_or(""),
                    );
                }
            });
        }

        Command::Scan { pid, value, dtype } => {
            let result = client
                .call(
                    "scan.start",
                    json!({"pid": pid, "value": value, "dtype": dtype}),
                )
                .await?;
            output!(output_json, result, {
                println!("Session: {}", result["session_id"].as_str().unwrap_or("?"));
                println!("Candidates: {}", result["candidates"]);
            });
        }

        Command::Filter {
            session_id,
            new_value,
            mode,
        } => {
            let result = client
                .call(
                    "scan.filter",
                    json!({"session_id": session_id, "new_value": new_value, "mode": mode}),
                )
                .await?;
            output!(output_json, result, {
                println!("Candidates remaining: {}", result["candidates"]);
                if let Some(top) = result["top"].as_array() {
                    for (i, c) in top.iter().take(20).enumerate() {
                        let types = format_types(&c["types"]);
                        println!(
                            "  [{i}] {:<18} {:<16} confidence={}",
                            c["address"].as_str().unwrap_or("?"),
                            types,
                            c["confidence"]
                        );
                    }
                    if top.len() > 20 {
                        println!("  ... and {} more", top.len() - 20);
                    }
                }
            });
        }

        Command::Sessions => {
            let result = client.call("scan.list", json!({})).await?;
            output!(output_json, result, {
                let sessions = result.as_array().unwrap_or(&Vec::new()).clone();
                if sessions.is_empty() {
                    println!("No active scan sessions.");
                } else {
                    println!(
                        "{:<38} {:<8} {:<12} {:<8} DTYPE",
                        "SESSION", "PID", "CANDIDATES", "VALUE"
                    );
                    for s in &sessions {
                        println!(
                            "{:<38} {:<8} {:<12} {:<8} {}",
                            s["id"].as_str().unwrap_or("?"),
                            s["pid"],
                            s["candidates"],
                            s["value"],
                            s["dtype"].as_str().unwrap_or("?"),
                        );
                    }
                }
            });
        }

        Command::Discard { session_id } => {
            let result = client
                .call("scan.discard", json!({"session_id": session_id}))
                .await?;
            output!(output_json, result, {
                if result["discarded"].as_bool().unwrap_or(false) {
                    println!("Session {session_id} discarded.");
                } else {
                    println!("Session {session_id} not found.");
                }
            });
        }

        Command::Read {
            pid,
            address,
            length,
        } => {
            let result = client
                .call(
                    "memory.read",
                    json!({"pid": pid, "address": address, "length": length}),
                )
                .await?;
            output!(output_json, result, {
                let hex = result["hex"].as_str().unwrap_or("");
                let addr = u64::from_str_radix(
                    result["address"]
                        .as_str()
                        .unwrap_or("0")
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap_or(0);
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                    .collect();
                print_hex_dump(addr, &bytes);

                if let Some(interp) = result.get("interpretations") {
                    println!();
                    for (k, v) in interp.as_object().unwrap_or(&serde_json::Map::new()) {
                        println!("  {k}: {v}");
                    }
                }
            });
        }

        Command::Write {
            pid,
            address,
            value,
            dtype,
        } => {
            let result = client
                .call(
                    "memory.write",
                    json!({"pid": pid, "address": address, "value": value, "dtype": dtype}),
                )
                .await?;
            output!(output_json, result, {
                println!("Wrote {value} ({dtype}) to {address}");
            });
        }

        Command::WriteAll {
            session_id,
            value,
            dtype,
            force,
        } => {
            let result = client
                .call(
                    "memory.write_all",
                    json!({
                        "session_id": session_id,
                        "value": value,
                        "dtype": dtype,
                        "force": force,
                    }),
                )
                .await?;
            output!(output_json, result, {
                let written = result["written"].as_u64().unwrap_or(0);
                let failed = result["failed"].as_u64().unwrap_or(0);
                if let Some(addrs) = result["addresses"].as_array() {
                    for addr in addrs {
                        println!(
                            "  wrote {value} ({dtype}) -> {}",
                            addr.as_str().unwrap_or("?")
                        );
                    }
                }
                if failed > 0 {
                    eprintln!("  {failed} write(s) failed (safety check or unmapped)");
                }
                println!("{written} addresses written.");
            });
        }

        Command::FreezeAll {
            session_id,
            value,
            dtype,
            interval,
            force,
        } => {
            let result = client
                .call(
                    "freeze.start_all",
                    json!({
                        "session_id": session_id,
                        "value": value,
                        "dtype": dtype,
                        "interval_ms": interval,
                        "force": force,
                    }),
                )
                .await?;
            output!(output_json, result, {
                let frozen = result["frozen"].as_u64().unwrap_or(0);
                let failed = result["failed"].as_u64().unwrap_or(0);
                if let Some(addrs) = result["addresses"].as_array() {
                    for addr in addrs {
                        println!(
                            "  frozen {value} ({dtype}) -> {}",
                            addr.as_str().unwrap_or("?")
                        );
                    }
                }
                if failed > 0 {
                    eprintln!("  {failed} freeze(s) failed");
                }
                println!("{frozen} addresses frozen at {interval}ms interval.");
            });
        }

        Command::Freeze {
            pid,
            address,
            value,
            dtype,
            interval,
        } => {
            let result = client
                .call(
                    "freeze.start",
                    json!({
                        "pid": pid,
                        "address": address,
                        "value": value,
                        "dtype": dtype,
                        "interval_ms": interval,
                    }),
                )
                .await?;
            output!(output_json, result, {
                println!("Frozen: {address} = {value} ({dtype}), interval={interval}ms");
            });
        }

        Command::Unfreeze { address } => {
            let result = client
                .call("freeze.stop", json!({"address": address}))
                .await?;
            output!(output_json, result, {
                println!("Unfrozen: {address}");
            });
        }

        Command::FreezeList => {
            let result = client.call("freeze.list", json!({})).await?;
            output!(output_json, result, {
                let freezes = result.as_array().unwrap_or(&Vec::new()).clone();
                if freezes.is_empty() {
                    println!("No active freezes.");
                } else {
                    println!("{:<20} {:<12} {:<8} INTERVAL", "ADDRESS", "VALUE", "DTYPE");
                    for f in &freezes {
                        println!(
                            "{:<20} {:<12} {:<8} {}ms",
                            f["address"].as_str().unwrap_or("?"),
                            f["value"],
                            f["dtype"].as_str().unwrap_or("?"),
                            f["interval_ms"],
                        );
                    }
                }
            });
        }

        Command::Disasm {
            pid,
            address,
            count,
        } => {
            let result = client
                .call(
                    "memory.disassemble",
                    json!({"pid": pid, "address": address, "num_instructions": count}),
                )
                .await?;
            output!(output_json, result, {
                if let Some(insns) = result.as_array() {
                    for insn in insns {
                        println!(
                            "  {}: {} {}",
                            insn["address"].as_str().unwrap_or("?"),
                            insn["mnemonic"].as_str().unwrap_or("?"),
                            insn["op_str"].as_str().unwrap_or(""),
                        );
                    }
                }
            });
        }

        Command::Aob {
            pid,
            pattern,
            include_readonly,
        } => {
            let result = client
                .call(
                    "scan.aob",
                    json!({"pid": pid, "pattern": pattern, "include_readonly": include_readonly}),
                )
                .await?;
            output!(output_json, result, {
                if let Some(addrs) = result["addresses"].as_array() {
                    println!("Found {} matches:", addrs.len());
                    for addr in addrs {
                        println!("  {}", addr.as_str().unwrap_or("?"));
                    }
                }
            });
        }

        Command::PointerScan {
            pid,
            address,
            max_depth,
            max_offset,
        } => {
            let result = client
                .call(
                    "pointer.scan",
                    json!({
                        "pid": pid,
                        "target": address,
                        "max_depth": max_depth,
                        "max_offset": max_offset,
                    }),
                )
                .await?;
            output!(output_json, result, {
                if let Some(chains) = result.as_array() {
                    if chains.is_empty() {
                        println!("No pointer chains found.");
                    } else {
                        for (i, chain) in chains.iter().enumerate() {
                            let module = chain["base_module"].as_str().unwrap_or("?");
                            let offset = chain["base_offset"].as_u64().unwrap_or(0);
                            let mut chain_str = format!("{module}+{offset:#x}");
                            if let Some(links) = chain["links"].as_array() {
                                for link in links {
                                    let off = link["offset"].as_i64().unwrap_or(0);
                                    use std::fmt::Write;
                                    let _ = write!(chain_str, " -> [+{off:#x}]");
                                }
                            }
                            println!("  [{i}] {chain_str}");
                        }
                    }
                }
            });
        }

        // ── Watch commands ─────────────────────────────────────────────
        Command::Watch {
            pid,
            address,
            mode,
            size,
            detail,
        } => {
            let result = client
                .call(
                    "watch.start",
                    json!({
                        "pid": pid, "address": address, "mode": mode,
                        "size": size, "detail": detail,
                    }),
                )
                .await?;
            output!(output_json, result, {
                let watch_id = result["watch_id"].as_str().unwrap_or("?");
                println!("Watchpoint set: {watch_id}");
                println!("  address: {address}, mode: {mode}, size: {size}");
                println!("  Use:  pika watch-hits {watch_id}");
                println!("  Stop: pika watch-stop {watch_id}");
            });
        }

        Command::WatchHits { watch_id } => {
            let result = client
                .call("watch.hits", json!({"watch_id": watch_id}))
                .await?;
            output!(output_json, result, {
                if let Some(hits) = result.as_array() {
                    if hits.is_empty() {
                        println!("No hits yet. Change the value in-game and check again.");
                    } else {
                        println!("{:<6} {:<20} INSTRUCTION", "HITS", "RIP");
                        for hit in hits {
                            println!(
                                "  {:<6} {:<20} {}",
                                hit["hit_count"],
                                hit["rip"].as_str().unwrap_or("?"),
                                hit["disasm"].as_str().unwrap_or("(unknown)"),
                            );
                        }
                        println!("\nTo NOP a writer: pika nop <pid> <rip>");
                    }
                }
            });
        }

        Command::WatchStop { watch_id } => {
            let result = client
                .call("watch.stop", json!({"watch_id": watch_id}))
                .await?;
            output!(output_json, result, {
                println!("Watchpoint {watch_id} stopped.");
            });
        }

        Command::WatchList => {
            let result = client.call("watch.list", json!({})).await?;
            output!(output_json, result, {
                let watches = result.as_array().unwrap_or(&Vec::new()).clone();
                if watches.is_empty() {
                    println!("No active watchpoints.");
                } else {
                    println!(
                        "{:<14} {:<8} {:<20} {:<8} {:<6} HITS",
                        "WATCH_ID", "PID", "ADDRESS", "MODE", "SIZE"
                    );
                    for w in &watches {
                        println!(
                            "{:<14} {:<8} {:<20} {:<8} {:<6} {}",
                            w["watch_id"].as_str().unwrap_or("?"),
                            w["pid"],
                            w["address"].as_str().unwrap_or("?"),
                            w["mode"].as_str().unwrap_or("?"),
                            w["size"],
                            w["hit_count"],
                        );
                    }
                }
            });
        }

        // ── Code patch commands ────────────────────────────────────────
        Command::Nop { pid, address, size } => {
            let mut params = json!({"pid": pid, "address": address});
            if let Some(s) = size {
                params["size"] = json!(s);
            }
            let result = client.call("code.nop", params).await?;
            output!(output_json, result, {
                println!("NOPed at {address}");
                println!(
                    "  original: {}",
                    result["original_bytes"].as_str().unwrap_or("?")
                );
                println!(
                    "  patched:  {}",
                    result["patched_bytes"].as_str().unwrap_or("?")
                );
                println!("  Restore:  pika restore {pid} {address}");
            });
        }

        Command::Patch {
            pid,
            address,
            bytes,
        } => {
            let result = client
                .call(
                    "code.patch",
                    json!({
                        "pid": pid, "address": address, "bytes": bytes,
                    }),
                )
                .await?;
            output!(output_json, result, {
                println!("Patched at {address}");
                println!(
                    "  original: {}",
                    result["original_bytes"].as_str().unwrap_or("?")
                );
                println!("  Restore:  pika restore {pid} {address}");
            });
        }

        Command::Restore { pid, address } => {
            let result = client
                .call(
                    "code.restore",
                    json!({
                        "pid": pid, "address": address,
                    }),
                )
                .await?;
            output!(output_json, result, {
                println!("Restored original bytes at {address}");
            });
        }

        Command::PatchList => {
            let result = client.call("code.list", json!({})).await?;
            output!(output_json, result, {
                let patches = result.as_array().unwrap_or(&Vec::new()).clone();
                if patches.is_empty() {
                    println!("No active patches.");
                } else {
                    println!("{:<20} {:<30} PATCHED", "ADDRESS", "ORIGINAL");
                    for p in &patches {
                        println!(
                            "{:<20} {:<30} {}",
                            p["address"].as_str().unwrap_or("?"),
                            p["original_bytes"].as_str().unwrap_or("?"),
                            p["patched_bytes"].as_str().unwrap_or("?"),
                        );
                    }
                }
            });
        }
    }

    Ok(())
}

/// Create the appropriate memory access implementation (for serve/tui only).
fn create_memory_access() -> std::sync::Arc<dyn pika::mem::access::MemoryAccess> {
    #[cfg(target_os = "linux")]
    {
        use pika::mem::access::linux::LinuxMemoryAccess;
        std::sync::Arc::new(LinuxMemoryAccess)
    }
    #[cfg(not(target_os = "linux"))]
    {
        use pika::mem::access::MockMemoryAccess;
        tracing::warn!("not running on Linux -- using mock memory access (no real scanning)");
        std::sync::Arc::new(MockMemoryAccess::new(0))
    }
}

/// Run platform capability check and print warnings.
fn run_platform_check() {
    let check = pika::process::platform::check_platform();
    for warning in &check.warnings {
        eprintln!("warning: {warning}");
    }
    if check.can_scan {
        tracing::info!("platform check passed -- memory scanning available");
    }
}

fn print_hex_dump(base_addr: u64, data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_addr + (i * 16) as u64;
        print!("{addr:016x}  ");
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                print!(" ");
            }
            print!("{byte:02x} ");
        }
        for j in chunk.len()..16 {
            if j == 8 {
                print!(" ");
            }
            print!("   ");
        }
        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

/// Format a JSON types array like `["i32", "u32"]` into `i32|u32`.
fn format_types(types: &serde_json::Value) -> String {
    match types.as_array() {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join("|"),
        None => "?".to_string(),
    }
}
