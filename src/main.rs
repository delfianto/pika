use anyhow::Result;
use clap::Parser;
use pika::cli::{Cli, Command};
use pika::rpc::client::RpcClient;
use serde_json::json;

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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&processes)?);
            } else if processes.is_empty() {
                println!("No Wine/Proton game processes found.");
            } else {
                println!("{:<8} NAME", "PID");
                for p in &processes {
                    println!("{:<8} {}", p.pid, p.name);
                }
            }
        }

        // ── Daemon-routed commands ──────────────────────────────────────
        Command::Maps { pid } => {
            let result = client.call("maps.get", json!({"pid": pid})).await?;
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
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
            }
        }

        Command::Scan { pid, value, dtype } => {
            let result = client
                .call("scan.start", json!({"pid": pid, "value": value, "dtype": dtype}))
                .await?;
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Session: {}", result["session_id"].as_str().unwrap_or("?"));
                println!("Candidates: {}", result["candidates"]);
            }
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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
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
            }
        }

        Command::Sessions => {
            let result = client.call("scan.list", json!({})).await?;
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                let sessions = result.as_array().unwrap_or(&Vec::new()).clone();
                if sessions.is_empty() {
                    println!("No active scan sessions.");
                } else {
                    println!("{:<38} {:<8} {:<12} {:<8} DTYPE", "SESSION", "PID", "CANDIDATES", "VALUE");
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
            }
        }

        Command::Discard { session_id } => {
            let result = client
                .call("scan.discard", json!({"session_id": session_id}))
                .await?;
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result["discarded"].as_bool().unwrap_or(false) {
                println!("Session {session_id} discarded.");
            } else {
                println!("Session {session_id} not found.");
            }
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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
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
            }
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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Wrote {value} ({dtype}) to {address}");
            }
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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                let written = result["written"].as_u64().unwrap_or(0);
                let failed = result["failed"].as_u64().unwrap_or(0);
                if let Some(addrs) = result["addresses"].as_array() {
                    for addr in addrs {
                        println!("  wrote {value} ({dtype}) -> {}", addr.as_str().unwrap_or("?"));
                    }
                }
                if failed > 0 {
                    eprintln!("  {failed} write(s) failed (safety check or unmapped)");
                }
                println!("{written} addresses written.");
            }
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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                let frozen = result["frozen"].as_u64().unwrap_or(0);
                let failed = result["failed"].as_u64().unwrap_or(0);
                if let Some(addrs) = result["addresses"].as_array() {
                    for addr in addrs {
                        println!("  frozen {value} ({dtype}) -> {}", addr.as_str().unwrap_or("?"));
                    }
                }
                if failed > 0 {
                    eprintln!("  {failed} freeze(s) failed");
                }
                println!("{frozen} addresses frozen at {interval}ms interval.");
            }
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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Frozen: {address} = {value} ({dtype}), interval={interval}ms");
            }
        }

        Command::Unfreeze { address } => {
            let result = client
                .call("freeze.stop", json!({"address": address}))
                .await?;
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Unfrozen: {address}");
            }
        }

        Command::FreezeList => {
            let result = client.call("freeze.list", json!({})).await?;
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
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
            }
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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if let Some(insns) = result.as_array() {
                for insn in insns {
                    println!(
                        "  {}: {} {}",
                        insn["address"].as_str().unwrap_or("?"),
                        insn["mnemonic"].as_str().unwrap_or("?"),
                        insn["op_str"].as_str().unwrap_or(""),
                    );
                }
            }
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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if let Some(addrs) = result["addresses"].as_array() {
                println!("Found {} matches:", addrs.len());
                for addr in addrs {
                    println!("  {}", addr.as_str().unwrap_or("?"));
                }
            }
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
            if output_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if let Some(chains) = result.as_array() {
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
