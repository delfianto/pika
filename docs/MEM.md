# mem — Memory Access, Mutation, and Monitoring

The `mem` module is pika's interface to target process memory. Every byte read from
or written to a game goes through this module. It is designed around a single
principle: **never stop the target process**.

## Submodules

| Submodule | File | Purpose |
|---|---|---|
| `access` | `mem/access.rs` | `MemoryAccess` trait + Linux / mock implementations |
| `write` | `mem/write.rs` | Value encoding and writing with pre-flight region safety checks |
| `freeze` | `mem/freeze.rs` | Background threads that repeatedly write a value at a configurable interval |
| `patch` | `mem/patch.rs` | Code patching (NOP, arbitrary bytes) via `/proc/pid/mem` with backup/restore |
| `watch` | `mem/watch.rs` | Hardware watchpoints via x86-64 debug registers (DR0-DR7) |
| `disassemble` | `mem/disassemble.rs` | x86-64 disassembly via capstone for instruction analysis |

---

## MemoryAccess trait (`access`)

The `MemoryAccess` trait decouples all higher-level operations from the underlying
OS primitives:

```rust
pub trait MemoryAccess: Send + Sync {
    fn read(&self, pid: u32, address: u64, buffer: &mut [u8]) -> Result<usize>;
    fn write(&self, pid: u32, address: u64, data: &[u8]) -> Result<usize>;
    fn read_maps(&self, pid: u32) -> Result<Vec<MapRegion>>;
}
```

### Linux implementation

`LinuxMemoryAccess` wraps `process_vm_readv` / `process_vm_writev` from the `nix`
crate. These syscalls:

- **Do not send any signal** to the target. The kernel walks the target's page tables
  under `mmap_read_lock`, copies data, and returns. The target continues executing on
  all threads, completely unaware.
- Support **scatter-gather I/O** via iovec arrays (up to 1024 entries per call).
- Return the number of bytes actually transferred (may be less on partial reads near
  unmapped pages).

Maps are read directly from `/proc/[pid]/maps` (the file, never a cached copy).

### Mock implementation

`MockMemoryAccess` stores memory as a `BTreeMap<u64, Vec<u8>>` of address ranges
plus a configurable set of `MapRegion` entries. This allows the entire
scan/filter/write pipeline to be tested without a live target process. The mock is
available on all platforms, so development and CI can run on macOS or in containers.

Convenience methods (`write_value<T>`, `read_value<T>`) use `bytemuck` for safe
zero-copy transmutation.

---

## Safe value writing (`write`)

`write_value` is the **only** path through which game memory values should be
modified. Before every write it performs a mandatory pre-flight safety check:

```
1. Re-read /proc/[pid]/maps           (fresh, not cached)
2. Find the region containing the target address
3. Classify the region using the safety rules from process/maps
4. REJECT if classification is anything other than Safe
5. Encode the value as little-endian bytes for the requested type
6. Call process_vm_writev
7. Verify bytes_written == expected
```

### Why re-check every time

DXVK recycles command buffers and can remap memory regions between a scan and a
subsequent write. A region that was `Safe` (anonymous `rw-p` heap) during the scan
may have been repurposed as a DXVK staging buffer by the time the user asks to write.
The pre-flight check catches this.

### Value encoding

The `encode_value` function converts an `f64` (the universal numeric input from
JSON-RPC) into the correct little-endian byte representation:

| ValueType | Encoding |
|---|---|
| `I32` | `(value as i32).to_le_bytes()` |
| `U32` | `(value as u32).to_le_bytes()` |
| `F32` | `(value as f32).to_le_bytes()` |
| `I64` | `(value as i64).to_le_bytes()` |
| `U64` | `(value as u64).to_le_bytes()` |
| `F64` | `value.to_le_bytes()` |
| `Auto` | Rejected (must specify a concrete type for writes) |

---

## Freeze loops (`freeze`)

A freeze loop holds a value constant by repeatedly writing it to the target address.
This is how "infinite health" or "locked gold" effects work.

### Thread model

Each frozen address gets a **dedicated `std::thread`** (not a tokio task). This is
a deliberate design choice:

- The write path (`process_vm_writev` + `/proc/[pid]/maps` re-read) is synchronous
  and blocking. Running it on a tokio worker thread would starve the async executor.
- `std::thread::sleep` provides the timing interval. No async runtime involvement.
- Thread names are set to `freeze-{address:#x}` for debuggability.

### Safety per iteration

Every write iteration calls `write_value`, which re-runs the full pre-flight safety
check. If the region is remapped mid-freeze, the write fails, the loop logs a
warning, and stops automatically.

### FreezeManager

`FreezeManager` coordinates active loops via a `DashMap<u64, FreezeHandle>` keyed by
address. Starting a freeze on an already-frozen address atomically stops the old loop
(signals via `AtomicBool`, joins the thread) and starts a new one with the updated
value and interval. `FreezeManager` implements `Drop` to stop all loops on shutdown.

---

## Code patching (`patch`)

Code patches modify executable instructions in the target process. Common use cases:

- **NOP**: Replace a "subtract health" instruction with NOPs to make the player invincible.
- **Arbitrary patch**: Replace a conditional jump with an unconditional one.

### Writing to executable pages

Data writes use `process_vm_writev`, which only works on writable pages (`rw-p`).
Code sections are `r-xp` (read + execute, no write). To patch code, pika writes
through `/proc/pid/mem`, which bypasses page protections at the VFS level without
stopping the process. Requires same-UID or `CAP_SYS_PTRACE`.

```rust
let mut file = OpenOptions::new().read(true).write(true).open(format!("/proc/{pid}/mem"))?;
file.seek(SeekFrom::Start(address))?;
file.write(data)?;
```

### Safety checks

Before patching, `validate_code_address` verifies:

1. The target address falls within a mapped region.
2. The region is not `NeverTouch`.
3. The region has execute or write permissions.

### Backup and restore

`PatchManager` stores a `PatchRecord` for every applied patch, keyed by address. Each
record contains the original bytes. `restore_at` writes the originals back.
`PatchManager` implements `Drop` to restore all patches on shutdown, preventing
permanent corruption of the target's code sections.

### Auto-detect instruction size

When NOP-ing without an explicit size, pika disassembles one instruction at the target
address to determine its byte length, then writes exactly that many `0x90` bytes.

---

## Hardware watchpoints (`watch`)

Hardware watchpoints find **which instruction** reads or writes a memory address.
This is essential for identifying the code responsible for decrementing health,
spending gold, etc. Once identified, that instruction can be NOP-ed.

### x86-64 debug registers

The CPU provides four debug address registers (DR0-DR3) and a control register (DR7).
Pika uses DR0 for a single watchpoint per session:

- **DR0** = watched address
- **DR7** = mode (write-only or read+write) + size (1, 2, 4, or 8 bytes)
- **DR6** = status (cleared after each hit to prevent re-triggering)

### Ptrace strategy

Watchpoints require ptrace, but pika minimizes the impact:

1. **`PTRACE_SEIZE`** (not `PTRACE_ATTACH`): Does NOT send `SIGSTOP`. Safe for DXVK.
2. **`PTRACE_INTERRUPT`**: Briefly pauses a single thread to configure debug registers.
3. **`PTRACE_CONT`**: Resumes the thread. The watchpoint is now armed.
4. **`waitpid(WNOHANG)`**: Polls for hits without blocking. The target runs at full
   speed between breaks.
5. **Cleanup**: Clear DR0/DR6/DR7, then `PTRACE_DETACH`.

### Thread selection

Pika prefers to trace a **non-main thread** (the second entry in `/proc/pid/task/`)
to minimize disruption. Wine games typically have many threads; the main thread handles
the Windows message loop while worker threads handle game logic.

### Hit recording

Hits are deduplicated by instruction pointer (RIP). Each unique RIP accumulates a
hit count. Optionally, a full register snapshot (RAX through R15) is captured on each
hit for detailed analysis. The hitting instruction is disassembled for display.

---

## Disassembly (`disassemble`)

Reads machine code bytes from the target process via `MemoryAccess` and disassembles
them using capstone in Intel syntax. Used by:

- The watch module to annotate watchpoint hits with the triggering instruction.
- The patch module to auto-detect instruction sizes for NOP operations.
- The `memory.disassemble` RPC method for user-requested code analysis.

On non-Linux platforms, disassembly returns an error (capstone requires reading target
process memory, which the mock cannot meaningfully provide for code analysis).
