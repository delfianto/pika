use anyhow::Result;
use clap::Parser;
use pika::cli::{Cli, Command};
use pika::memory::MockMemoryAccess;
use std::sync::Arc;

#[cfg(target_os = "linux")]
use pika::memory::linux::LinuxMemoryAccess;

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

    match cli.command {
        Command::Serve { socket, stdio } => {
            let mem = create_memory_access();
            if stdio {
                pika::rpc::server::serve_stdio(mem).await?;
            } else {
                pika::rpc::server::serve_unix_socket(&socket, mem).await?;
            }
        }

        Command::Tui => {
            let mem = create_memory_access();
            pika::tui::run(mem)?;
        }

        Command::Ps => {
            let processes = pika::pid::list_wine_processes()?;
            if processes.is_empty() {
                println!("No Wine/Proton game processes found.");
            } else {
                println!("{:<8} NAME", "PID");
                for p in &processes {
                    println!("{:<8} {}", p.pid, p.name);
                }
            }
        }

        Command::Maps { pid } => {
            let mem = create_memory_access();
            let regions = mem.read_maps(pid)?;
            println!(
                "{:<20} {:<20} {:<6} {:<12} PATH",
                "START", "END", "PERMS", "SAFETY"
            );
            for r in &regions {
                println!(
                    "{:<20} {:<20} {:<6} {:<12} {}",
                    format!("{:#x}", r.start),
                    format!("{:#x}", r.end),
                    r.permissions.as_str(),
                    format!("{:?}", r.safety),
                    r.pathname,
                );
            }
        }

        Command::Scan { pid, value, dtype } => {
            let mem = create_memory_access();
            let dtype = parse_dtype(&dtype)?;
            let session = pika::scan::first_scan(mem.as_ref(), pid, value, dtype)?;
            println!("Session: {}", session.id);
            println!("Candidates: {}", session.candidates.len());
            for (i, c) in session.candidates.iter().take(20).enumerate() {
                println!("  [{i}] {:#x}  types={}", c.address, c.types);
            }
            if session.candidates.len() > 20 {
                println!("  ... and {} more", session.candidates.len() - 20);
            }
        }

        Command::Read {
            pid,
            address,
            length,
        } => {
            let mem = create_memory_access();
            let addr = parse_hex(&address)?;
            let length = length.min(4096);
            let mut buf = vec![0u8; length];
            let n = mem.read(pid, addr, &mut buf)?;
            buf.truncate(n);
            print_hex_dump(addr, &buf);
        }

        Command::Write {
            pid,
            address,
            value,
            dtype,
        } => {
            let mem = create_memory_access();
            let addr = parse_hex(&address)?;
            let dtype = parse_dtype(&dtype)?;
            pika::write::write_value(mem.as_ref(), pid, addr, value, dtype)?;
            println!("Wrote {value} ({dtype}) to {address}");
        }
    }

    Ok(())
}

/// Create the appropriate memory access implementation.
fn create_memory_access() -> Arc<dyn pika::memory::MemoryAccess> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(LinuxMemoryAccess)
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("not running on Linux -- using mock memory access (no real scanning)");
        Arc::new(MockMemoryAccess::new(0))
    }
}

fn parse_hex(s: &str) -> Result<u64> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| anyhow::anyhow!("invalid hex address: {e}"))
}

fn parse_dtype(s: &str) -> Result<pika::candidate::ValueType> {
    match s.to_ascii_lowercase().as_str() {
        "i32" => Ok(pika::candidate::ValueType::I32),
        "u32" => Ok(pika::candidate::ValueType::U32),
        "f32" => Ok(pika::candidate::ValueType::F32),
        "i64" => Ok(pika::candidate::ValueType::I64),
        "u64" => Ok(pika::candidate::ValueType::U64),
        "f64" => Ok(pika::candidate::ValueType::F64),
        "auto" => Ok(pika::candidate::ValueType::Auto),
        _ => anyhow::bail!("unknown dtype: {s} (expected: i32, u32, f32, i64, u64, f64, auto)"),
    }
}

fn print_hex_dump(base_addr: u64, data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_addr + (i * 16) as u64;
        // Address
        print!("{addr:016x}  ");
        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                print!(" ");
            }
            print!("{byte:02x} ");
        }
        // Padding for short last line
        for j in chunk.len()..16 {
            if j == 8 {
                print!(" ");
            }
            print!("   ");
        }
        // ASCII
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
