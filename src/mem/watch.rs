//! Hardware watchpoints via x86-64 debug registers.
//!
//! Uses `PTRACE_SEIZE` + `PTRACE_INTERRUPT` to set hardware watchpoints on target
//! process addresses without sending `SIGSTOP`. This is critical for Wine/Proton
//! games where stopping the process can deadlock DXVK/VKD3D GPU submission.
//!
//! # How it works
//!
//! 1. A thread is spawned per watchpoint, which calls `PTRACE_SEIZE` on a target
//!    thread (preferring a non-main thread to minimize disruption).
//! 2. `PTRACE_INTERRUPT` briefly pauses the thread to configure debug registers
//!    (`DR0` = address, `DR7` = mode/size, `DR6` = clear).
//! 3. The thread is resumed with `PTRACE_CONT`. The CPU triggers `SIGTRAP` on
//!    hardware watchpoint hits.
//! 4. The watch loop uses `waitpid(WNOHANG)` to poll for hits without blocking.
//!    Hits are deduplicated by instruction pointer (`RIP`) and optionally include
//!    a full register snapshot.
//! 5. On stop, debug registers are cleared and the tracer detaches cleanly.
//!
//! On non-Linux platforms, all watch operations return an error.

use crate::mem::access::MemoryAccess;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

// Re-export libc from nix for ptrace raw syscalls on Linux.
#[cfg(target_os = "linux")]
use nix::libc;

/// Which operations to watch for.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WatchMode {
    /// Break on writes only (DR7 condition = 01).
    Write,
    /// Break on reads or writes (DR7 condition = 11).
    ReadWrite,
}

/// Size of the watched region in bytes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WatchSize {
    Byte1,
    Byte2,
    Byte4,
    Byte8,
}

impl WatchSize {
    /// Return the size in bytes as a numeric value.
    pub fn as_bytes(self) -> u8 {
        match self {
            Self::Byte1 => 1,
            Self::Byte2 => 2,
            Self::Byte4 => 4,
            Self::Byte8 => 8,
        }
    }
}

/// Configuration for a hardware watchpoint session.
///
/// Specifies the target address, access mode (write-only or read/write),
/// watched region size, and whether to capture a full register snapshot on hit.
#[derive(Clone, Debug)]
pub struct WatchConfig {
    pub pid: u32,
    pub address: u64,
    pub mode: WatchMode,
    pub size: WatchSize,
    pub capture_registers: bool,
}

/// A single hit from the hardware watchpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchHit {
    pub rip: u64,
    pub disasm: Option<String>,
    pub hit_count: u64,
    pub registers: Option<RegisterSnapshot>,
}

/// Subset of general-purpose registers captured on watchpoint hit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterSnapshot {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// JSON-friendly hit for reporting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchHitJson {
    pub rip: String,
    pub disasm: Option<String>,
    pub hit_count: u64,
    pub registers: Option<RegisterSnapshot>,
}

/// JSON-friendly listing entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchEntryJson {
    pub watch_id: String,
    pub pid: u32,
    pub address: String,
    pub mode: String,
    pub size: u8,
    pub hit_count: u64,
    pub active: bool,
}

/// Handle for a running watch.
struct WatchHandle {
    config: WatchConfig,
    stop: Arc<AtomicBool>,
    hits: Arc<Mutex<Vec<WatchHit>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Manages hardware watchpoint sessions.
///
/// On Linux, uses ptrace SEIZE + debug registers to set x86_64 hardware
/// watchpoints. On other platforms, returns errors.
pub struct WatchManager {
    #[allow(dead_code)] // used on Linux for disassembly in watch_loop
    mem: Arc<dyn MemoryAccess>,
    active: DashMap<String, WatchHandle>,
}

impl WatchManager {
    /// Create a new watch manager backed by the given memory access implementation.
    pub fn new(mem: Arc<dyn MemoryAccess>) -> Self {
        Self {
            mem,
            active: DashMap::new(),
        }
    }

    /// Start a hardware watchpoint. Returns a unique watch_id.
    #[allow(clippy::needless_pass_by_value)] // config is moved into the thread on Linux
    pub fn start(&self, config: WatchConfig) -> anyhow::Result<String> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            anyhow::bail!("hardware watchpoints require Linux (ptrace debug registers)");
        }

        #[cfg(target_os = "linux")]
        {
            let watch_id = nid::Nanoid::<12>::new().to_string();
            let stop = Arc::new(AtomicBool::new(false));
            let hits: Arc<Mutex<Vec<WatchHit>>> = Arc::new(Mutex::new(Vec::new()));

            let stop_clone = stop.clone();
            let hits_clone = hits.clone();
            let config_clone = config.clone();
            let mem_clone = self.mem.clone();

            let thread = std::thread::Builder::new()
                .name(format!("watch-{watch_id}"))
                .spawn(move || {
                    if let Err(e) =
                        watch_loop(&config_clone, &stop_clone, &hits_clone, &mem_clone)
                    {
                        tracing::error!(error = %e, "watch loop failed");
                    }
                })?;

            self.active.insert(
                watch_id.clone(),
                WatchHandle {
                    config,
                    stop,
                    hits,
                    thread: Some(thread),
                },
            );

            tracing::info!(watch_id = %watch_id, "watchpoint started");
            Ok(watch_id)
        }
    }

    /// Get collected hits for a watch session.
    pub fn hits(&self, watch_id: &str) -> anyhow::Result<Vec<WatchHitJson>> {
        let entry = self
            .active
            .get(watch_id)
            .ok_or_else(|| anyhow::anyhow!("watch '{watch_id}' not found"))?;

        let hits = entry.hits.lock().unwrap();
        Ok(hits
            .iter()
            .map(|h| WatchHitJson {
                rip: format!("{:#x}", h.rip),
                disasm: h.disasm.clone(),
                hit_count: h.hit_count,
                registers: h.registers.clone(),
            })
            .collect())
    }

    /// Stop a watch session and detach from the target.
    pub fn stop(&self, watch_id: &str) -> anyhow::Result<()> {
        let (_, mut handle) = self
            .active
            .remove(watch_id)
            .ok_or_else(|| anyhow::anyhow!("watch '{watch_id}' not found"))?;

        handle
            .stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = handle.thread.take() {
            let _ = thread.join();
        }

        tracing::info!(watch_id = %watch_id, "watchpoint stopped");
        Ok(())
    }

    /// List all active watches.
    pub fn list(&self) -> Vec<WatchEntryJson> {
        self.active
            .iter()
            .map(|entry| {
                let id = entry.key().clone();
                let h = entry.value();
                let hit_count: u64 = h
                    .hits
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|hit| hit.hit_count)
                    .sum();
                WatchEntryJson {
                    watch_id: id,
                    pid: h.config.pid,
                    address: format!("{:#x}", h.config.address),
                    mode: match h.config.mode {
                        WatchMode::Write => "write".to_string(),
                        WatchMode::ReadWrite => "access".to_string(),
                    },
                    size: h.config.size.as_bytes(),
                    hit_count,
                    active: !h.stop.load(std::sync::atomic::Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Stop all active watches.
    pub fn stop_all(&self) {
        let keys: Vec<String> = self.active.iter().map(|e| e.key().clone()).collect();
        for key in keys {
            let _ = self.stop(&key);
        }
    }
}

impl Drop for WatchManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}

// ─── x86_64 debug register constants ────────────────────────────────────────

/// User struct offsets for x86_64 debug registers.
/// `offsetof(struct user, u_debugreg[N])` where each register is 8 bytes.
#[cfg(target_os = "linux")]
const DR0_OFFSET: u64 = 848;
#[cfg(target_os = "linux")]
const DR6_OFFSET: u64 = 888;
#[cfg(target_os = "linux")]
const DR7_OFFSET: u64 = 896;

/// Build the DR7 control register value for a watchpoint on DR0.
#[cfg(any(target_os = "linux", test))]
fn build_dr7(mode: WatchMode, size: WatchSize) -> u64 {
    let condition: u64 = match mode {
        WatchMode::Write => 0b01,
        WatchMode::ReadWrite => 0b11,
    };
    // x86 quirk: Byte4 = 0b11, Byte8 = 0b10
    let len: u64 = match size {
        WatchSize::Byte1 => 0b00,
        WatchSize::Byte2 => 0b01,
        WatchSize::Byte4 => 0b11,
        WatchSize::Byte8 => 0b10,
    };

    let mut dr7: u64 = 0;
    dr7 |= 1; // L0: local enable for DR0
    dr7 |= condition << 16; // R/W0: condition bits 16-17
    dr7 |= len << 18; // LEN0: size bits 18-19
    dr7
}

// ─── Ptrace watchpoint loop (Linux only) ────────────────────────────────────

#[cfg(target_os = "linux")]
fn watch_loop(
    config: &WatchConfig,
    stop: &AtomicBool,
    hits: &Arc<Mutex<Vec<WatchHit>>>,
    mem: &Arc<dyn MemoryAccess>,
) -> anyhow::Result<()> {
    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;

    let tid = pick_thread(config.pid)?;
    let pid = Pid::from_raw(tid as i32);

    // PTRACE_SEIZE -- does NOT send SIGSTOP (safe for DXVK)
    ptrace::seize(pid, ptrace::Options::empty())
        .map_err(|e| anyhow::anyhow!("PTRACE_SEIZE on tid {tid} failed: {e}"))?;

    // Briefly interrupt to set debug registers
    ptrace::interrupt(pid)
        .map_err(|e| anyhow::anyhow!("PTRACE_INTERRUPT failed: {e}"))?;

    match waitpid(pid, Some(WaitPidFlag::WSTOPPED)) {
        Ok(WaitStatus::PtraceEvent(..)) | Ok(WaitStatus::Stopped(..)) => {}
        other => {
            let _ = ptrace::detach(pid, None);
            anyhow::bail!("unexpected wait result after interrupt: {other:?}");
        }
    }

    // Set DR0 = address, DR7 = mode+size, clear DR6
    set_debug_registers(pid, config)?;

    // Resume -- watchpoint is now armed
    ptrace::cont(pid, None).map_err(|e| anyhow::anyhow!("PTRACE_CONT failed: {e}"))?;

    // Collect hits until stopped
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
                // Read registers
                let regs = ptrace::getregs(pid)
                    .map_err(|e| anyhow::anyhow!("getregs failed: {e}"))?;
                // RIP points to the instruction AFTER the one that triggered,
                // but for hardware watchpoints on x86_64 it points to the
                // instruction that CAUSED the trap (unlike software breakpoints).
                let rip = regs.rip;

                let snapshot = if config.capture_registers {
                    Some(regs_to_snapshot(&regs))
                } else {
                    None
                };

                // Clear DR6 so it doesn't re-trigger
                let _ = write_user(pid, DR6_OFFSET, 0);

                // Disassemble the hitting instruction
                let disasm = disassemble_rip(mem, config.pid, rip);

                record_hit(hits, rip, disasm, snapshot);

                ptrace::cont(pid, None)
                    .map_err(|e| anyhow::anyhow!("PTRACE_CONT after hit failed: {e}"))?;
            }
            Ok(WaitStatus::Stopped(_, sig)) => {
                // Re-deliver other signals
                let _ = ptrace::cont(pid, sig);
            }
            Ok(WaitStatus::StillAlive) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => {
                tracing::info!("traced thread exited");
                break;
            }
            Err(nix::errno::Errno::ECHILD) => {
                tracing::info!("traced thread no longer exists");
                break;
            }
            _ => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }

    // Cleanup: clear debug registers and detach
    cleanup_ptrace(pid);

    Ok(())
}

#[cfg(target_os = "linux")]
fn set_debug_registers(pid: nix::unistd::Pid, config: &WatchConfig) -> anyhow::Result<()> {
    write_user(pid, DR0_OFFSET, config.address)?;
    write_user(pid, DR6_OFFSET, 0)?;
    let dr7 = build_dr7(config.mode, config.size);
    write_user(pid, DR7_OFFSET, dr7)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_ptrace(pid: nix::unistd::Pid) {
    use nix::sys::ptrace;
    use nix::sys::wait::{waitpid, WaitPidFlag};

    if ptrace::interrupt(pid).is_ok() {
        if waitpid(pid, Some(WaitPidFlag::WSTOPPED)).is_ok() {
            let _ = write_user(pid, DR0_OFFSET, 0);
            let _ = write_user(pid, DR7_OFFSET, 0);
            let _ = write_user(pid, DR6_OFFSET, 0);
        }
    }
    let _ = ptrace::detach(pid, None);
}

/// Write to the user area via raw ptrace POKEUSER syscall.
#[cfg(target_os = "linux")]
fn write_user(pid: nix::unistd::Pid, offset: u64, value: u64) -> anyhow::Result<()> {
    // nix doesn't expose PTRACE_POKEUSER directly in all versions,
    // so we use the raw libc call.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            pid.as_raw(),
            offset as *const libc::c_void,
            value as *const libc::c_void,
        )
    };
    if ret == -1 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("PTRACE_POKEUSER offset={offset} failed: {err}");
    }
    Ok(())
}

/// Pick a thread from /proc/pid/task/ for ptrace.
#[cfg(target_os = "linux")]
fn pick_thread(pid: u32) -> anyhow::Result<u32> {
    let task_dir = format!("/proc/{pid}/task");
    let mut tids: Vec<u32> = std::fs::read_dir(&task_dir)?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .collect();
    tids.sort_unstable();
    // Prefer a non-main thread if available (less disruptive for Wine)
    if tids.len() > 1 {
        Ok(tids[1])
    } else if !tids.is_empty() {
        Ok(tids[0])
    } else {
        anyhow::bail!("no threads found in {task_dir}")
    }
}

#[cfg(target_os = "linux")]
fn regs_to_snapshot(regs: &libc::user_regs_struct) -> RegisterSnapshot {
    RegisterSnapshot {
        rax: regs.rax,
        rbx: regs.rbx,
        rcx: regs.rcx,
        rdx: regs.rdx,
        rsi: regs.rsi,
        rdi: regs.rdi,
        rbp: regs.rbp,
        rsp: regs.rsp,
        r8: regs.r8,
        r9: regs.r9,
        r10: regs.r10,
        r11: regs.r11,
        r12: regs.r12,
        r13: regs.r13,
        r14: regs.r14,
        r15: regs.r15,
    }
}

/// Disassemble one instruction at RIP for the hit record.
#[cfg(target_os = "linux")]
fn disassemble_rip(mem: &Arc<dyn MemoryAccess>, pid: u32, rip: u64) -> Option<String> {
    crate::mem::disassemble::disassemble_at(mem.as_ref(), pid, rip, 1)
        .ok()
        .and_then(|insns| {
            insns.first().map(|i| format!("{} {}", i.mnemonic, i.op_str))
        })
}

/// Record a hit, deduplicating by RIP.
#[cfg(any(target_os = "linux", test))]
fn record_hit(
    hits: &Arc<Mutex<Vec<WatchHit>>>,
    rip: u64,
    disasm: Option<String>,
    registers: Option<RegisterSnapshot>,
) {
    let mut hits = hits.lock().unwrap();
    if let Some(existing) = hits.iter_mut().find(|h| h.rip == rip) {
        existing.hit_count += 1;
        if registers.is_some() {
            existing.registers = registers;
        }
    } else {
        hits.push(WatchHit {
            rip,
            disasm,
            hit_count: 1,
            registers,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dr7_write_4byte() {
        let dr7 = build_dr7(WatchMode::Write, WatchSize::Byte4);
        // L0 = bit 0 = 1
        // condition = 01 at bits 16-17
        // len = 11 at bits 18-19
        assert_eq!(dr7 & 1, 1); // L0 enabled
        assert_eq!((dr7 >> 16) & 0b11, 0b01); // write only
        assert_eq!((dr7 >> 18) & 0b11, 0b11); // 4 bytes
    }

    #[test]
    fn build_dr7_readwrite_8byte() {
        let dr7 = build_dr7(WatchMode::ReadWrite, WatchSize::Byte8);
        assert_eq!((dr7 >> 16) & 0b11, 0b11); // read/write
        assert_eq!((dr7 >> 18) & 0b11, 0b10); // 8 bytes
    }

    #[test]
    fn build_dr7_write_1byte() {
        let dr7 = build_dr7(WatchMode::Write, WatchSize::Byte1);
        assert_eq!((dr7 >> 18) & 0b11, 0b00); // 1 byte
    }

    #[test]
    fn record_hit_deduplicates() {
        let hits = Arc::new(Mutex::new(Vec::new()));
        record_hit(&hits, 0x1000, Some("mov rax, rbx".to_string()), None);
        record_hit(&hits, 0x1000, Some("mov rax, rbx".to_string()), None);
        record_hit(&hits, 0x2000, Some("nop".to_string()), None);

        let h = hits.lock().unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].hit_count, 2);
        assert_eq!(h[1].hit_count, 1);
    }

    #[test]
    fn watch_mode_serialization() {
        let json = serde_json::to_string(&WatchMode::Write).unwrap();
        let parsed: WatchMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, WatchMode::Write);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn start_errors_on_non_linux() {
        let mock = Arc::new(crate::mem::access::MockMemoryAccess::new(1));
        let manager = WatchManager::new(mock);
        let result = manager.start(WatchConfig {
            pid: 1,
            address: 0x1000,
            mode: WatchMode::Write,
            size: WatchSize::Byte4,
            capture_registers: false,
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("require Linux"));
    }
}
