# Deep Technical Analysis: Proton Memory Scout

> Research findings for building a non-stopping memory scanner for Wine/Proton games.
> Covers kernel primitives, GPU safety, Wine internals, scan algorithms, and Rust implementation strategy.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Problem: Why Existing Tools Fail](#2-the-problem-why-existing-tools-fail)
3. [Linux Kernel Memory Access Primitives](#3-linux-kernel-memory-access-primitives)
4. [GPU Memory Safety](#4-gpu-memory-safety)
5. [Wine/Proton Process Model and Memory Layout](#5-wineproton-process-model-and-memory-layout)
6. [Region Classification System](#6-region-classification-system)
7. [Scan Engine Architecture](#7-scan-engine-architecture)
8. [Implementation Decisions](#8-implementation-decisions)
9. [Risk Analysis and Mitigations](#9-risk-analysis-and-mitigations)

---

## 1. Executive Summary

Traditional Linux memory editors (scanmem, PINCE, GameConqueror) use `ptrace(PTRACE_ATTACH)`
which sends `SIGSTOP` to the target process. For Wine/Proton games, this freezes DXVK/VKD3D
mid-GPU-submission, deadlocking the wineserver and hanging the GPU driver. Even a 10ms stop
has a ~60% chance of hitting an active `vkQueueSubmit` window on a 60fps game.

Our approach uses `process_vm_readv` / `process_vm_writev` (Linux 3.2+) which read/write
another process's memory **without sending any signal or stopping any thread**. Combined with
a strict region classification system that prevents any access to GPU driver mappings,
wineserver shared memory, or DXVK internal regions, this architecture makes GPU deadlocks
structurally impossible.

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Memory access | `process_vm_readv`/`writev` | Non-stopping, scatter-gather, ~1000x faster than ptrace |
| Never use | `ptrace PEEK/POKE` for reads/writes | Sends SIGSTOP, kills DXVK, deadlocks wineserver |
| Region safety | Classify before every access | DXVK remaps regions dynamically |
| Shared mappings (`rw-s`) | Never touch, no exceptions | GPU driver and wineserver communicate via shared memory |
| Scan parallelism | rayon across regions | Near-linear scaling, regions are independent |
| SIMD scanning | Manual AVX2 with SSE2 fallback | 8-12 GB/s throughput, 2-3x faster than memchr::memmem |
| IPC protocol | JSON-RPC 2.0 over Unix socket | Simple, debuggable with socat, language-agnostic |
| Candidate storage | Sorted `Vec<Candidate>` (16 bytes each) | Cache-friendly, serializable, 1M candidates = 16MB |

---

## 2. The Problem: Why Existing Tools Fail

### 2.1 The SIGSTOP/DXVK Deadlock Chain

This is the exact failure sequence that makes ptrace-based tools unusable with Proton games:

```
Step 1: ptrace(PTRACE_ATTACH, game_pid)
        Kernel sends SIGSTOP to ALL threads in the thread group.

Step 2: DXVK's Vulkan command submission thread is frozen mid-vkQueueSubmit().
        The GPU is now waiting for CPU-side fence signaling that will never come.

Step 3: Wineserver's select() loop is waiting for a response from the stopped thread.
        All other Wine processes needing the wineserver are now blocked.

Step 4: GPU driver timeout (5-10s). Driver issues GPU reset.
        Result: VK_ERROR_DEVICE_LOST. DXVK cannot recover.

Step 5: Entire Wine prefix is deadlocked. Game crashes or freezes permanently.
        On NVIDIA, may require killing X server or rebooting.
```

The DXVK command submission thread runs a tight loop. At 60fps, submissions happen every
~16ms. A random SIGSTOP has approximately 60% probability of landing during an active
submission window. This is not a rare edge case -- it is the expected outcome.

### 2.2 Existing Tool Architectures

**scanmem / GameConqueror:**
- Uses `process_vm_readv` for bulk reads (good) but still calls `PTRACE_ATTACH`/`PTRACE_DETACH` around scan operations in many code paths (fatal for Wine)
- Single-threaded scanning -- 30+ seconds for a 64-bit Wine game's address space
- Linked-list candidate storage (~48 bytes per candidate, terrible cache locality)
- No region classification -- happily reads GPU driver mappings
- No pointer scanning capability

**PINCE:**
- Built on GDB, which fundamentally requires `PTRACE_ATTACH`
- Uses `/proc/[pid]/mem` for bulk reads (requires ptrace attachment or `ptrace_scope=0`)
- Has pointer scanning and hardware watchpoints (useful features)
- No Wine/Proton-specific handling whatsoever

**CESERVER (Cheat Engine Linux backend):**
- Uses `/proc/[pid]/mem` + `pread()`, NOT `process_vm_readv`
- Requires `ptrace(PTRACE_ATTACH)` for writing
- No region classification for GPU safety

### 2.3 What We Take From Existing Tools

| Feature | Source | Adaptation |
|---|---|---|
| `process_vm_readv` for reads | scanmem | Use exclusively, never fall back to ptrace |
| Bitmask-per-page candidate storage | Cheat Engine | Adopt for dense first-scan results |
| AOB/signature scanning with wildcards | Cheat Engine | Implement in `scan.rs` |
| Pointer chain BFS with offset limits | Cheat Engine, PINCE | Implement in `pointer.rs` |
| Multi-type simultaneous first scan | scanmem | Extend with SIMD parallelism |
| Hardware watchpoints for access tracing | PINCE (via GDB) | Future: ptrace single thread briefly, detach immediately |

---

## 3. Linux Kernel Memory Access Primitives

### 3.1 `process_vm_readv` / `process_vm_writev` -- Core Mechanism

Added in Linux 3.2 (January 2012). Syscall numbers 310/311 on x86_64.

```c
ssize_t process_vm_readv(
    pid_t pid,
    const struct iovec *local_iov,    // buffers in THIS process
    unsigned long liovcnt,
    const struct iovec *remote_iov,   // regions in TARGET process
    unsigned long riovcnt,
    unsigned long flags               // must be 0
);
```

**Kernel code path** (`mm/process_vm_access.c`):
1. Validate flags and iovec counts (`UIO_MAXIOV` = 1024 max)
2. `find_get_task_by_vpid(pid)` -- look up target task_struct
3. `ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS)` -- permission check
4. For each remote iovec: grab target's `mm_struct`, `pin_user_pages_remote()` to walk page tables and pin physical pages, `kmap`/copy to local buffer, `unpin_user_pages()`
5. Return total bytes transferred

**Critical property: NO signal is sent.** The kernel source never calls `send_sig()`,
`ptrace_attach()`, or any signal-related function. The target process continues executing
on all threads, completely unaware its memory is being read.

### 3.2 How It Differs From ptrace

| Aspect | `process_vm_readv` | `ptrace PEEKDATA` |
|---|---|---|
| Target stopped? | **NO** | YES (SIGSTOP required) |
| Transfer size | Arbitrary scatter-gather | 8 bytes per syscall |
| Read 1 MB | ~200 us (1 syscall) | ~330,000 us (131K syscalls) |
| Read 100 MB | ~20 ms | ~33 seconds |
| GPU-safe? | **YES** | NO (SIGSTOP kills DXVK) |
| Concurrent from multiple threads | **YES** (kernel takes read lock) | NO |

### 3.3 Permission Model

Both syscalls call `ptrace_may_access()` -- the **same permission check** as `ptrace(PTRACE_ATTACH)`, but **without actually attaching or sending any signal**.

**Yama ptrace_scope affects `process_vm_readv`:**

| `ptrace_scope` | Effect | Common Distros |
|---|---|---|
| 0 (classic) | Any same-UID process can read/write | Arch, Manjaro, SteamOS |
| 1 (restricted) | Only parent or `PR_SET_PTRACER` designee | **Ubuntu**, Fedora |
| 2 (admin-only) | Requires `CAP_SYS_PTRACE` | Hardened systems |
| 3 (no-attach) | Blocked entirely, even for root | Rare |

**Our approach for `ptrace_scope=1` (Ubuntu default):**
```bash
# Set capability on the scanner binary (one-time setup)
sudo setcap cap_sys_ptrace=eip ./memscout
```

**Runtime check at scanner startup:**
```rust
let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
    .unwrap_or_else(|_| "0".to_string())
    .trim()
    .to_string();
if scope != "0" {
    // Check if we have CAP_SYS_PTRACE
    // If not, warn user with remediation steps
}
```

### 3.4 Non-Stopping Behavior: Safety Guarantees and Caveats

**Structurally safe:** Page table walks are properly locked (`mmap_read_lock`). Cannot crash
the kernel or corrupt kernel data structures.

**NOT atomically consistent:** The target is modifying memory concurrently. Possible outcomes:
- **Torn values** (half-old, half-new) if target writes during our read. For aligned 4-byte
  and 8-byte reads on x86_64, this cannot happen (CPU guarantees atomicity for naturally
  aligned loads/stores up to 8 bytes).
- **Stale data** if target munmaps a region after we pin its pages (we get the old data,
  target no longer sees it). Harmless -- next scan pass catches this.
- **Partial reads** if a region spans mapped and unmapped memory. Return value indicates
  bytes actually transferred. We must handle this.

**What happens with GPU device regions:** `pin_user_pages_remote()` refuses to pin pages
with `VM_IO` or `VM_PFNMAP` flags (set by GPU drivers via `remap_pfn_range()`). Result
is `EFAULT` -- a safe failure. However, some GPU shared memory regions (especially on AMD
via GTT) do not have these flags and CAN be read. They return stale/incoherent data. Our
region classifier catches these before the syscall.

### 3.5 Error Conditions

| errno | Meaning | Our response |
|---|---|---|
| `EFAULT` | Target memory unmapped (or GPU VRAM) | Skip region/chunk, continue scanning |
| `ESRCH` | PID doesn't exist (game exited) | Abort scan, notify frontend |
| `EPERM` | Permission denied (Yama, SELinux) | Error with remediation instructions |
| `EINVAL` | Bad flags or iovec count > 1024 | Programming error -- should not happen |
| Partial read (n < expected) | Unmapped page mid-region | Process bytes we got, skip rest |

### 3.6 Performance Characteristics

Approximate benchmarks (x86_64, kernel 5.x+, same-UID access):

| Operation | Time |
|---|---|
| Single syscall overhead | ~1-2 us |
| Read 4 KB (1 page) | ~3 us |
| Read 4 MB (1024 pages) | ~400-800 us |
| Scan 2 GB (rayon, 4 cores, AVX2) | ~200-400 ms |
| Filter 100K candidates (coalesced iovecs) | ~5-15 ms |
| Filter 1K candidates | ~0.5-1 ms |

**Optimal chunk size: 4 MB.** Large enough to amortize syscall overhead, small enough that
partial-read failures don't waste work. Matches typical L3 cache. For regions < 4 MB,
read the whole region in one call.

### 3.7 Comparison with `/proc/[pid]/mem`

`/proc/pid/mem` goes through VFS and internally calls the same `access_remote_vm()` function.
Viable as a fallback for environments where `process_vm_readv` is blocked by seccomp filters.
Disadvantage: no scatter-gather (must `lseek` + `read` for each disjoint region).

---

## 4. GPU Memory Safety

**This is the single most critical safety concern.** Incorrect access to GPU driver mappings
can crash the GPU, deadlock the display server, or require a full system reboot.

### 4.1 GPU Memory Mappings in `/proc/[pid]/maps`

**NVIDIA proprietary driver:**
```
7f8a00000000-7f8a00010000  rw-s  00000000  00:06  1234  /dev/nvidiactl       # Control channel
7f8a10000000-7f8a20000000  rw-s  00000000  00:06  1235  /dev/nvidia0         # GPU device (BAR)
7f2100000000-7f2200000000  rw-s  00000000  00:06  1236  /dev/nvidia-uvm      # Unified virtual memory
```
- Always `rw-s` (shared). Control, BAR, and UVM mappings.
- UVM pages may be GPU-resident. CPU access triggers page migration, stalling GPU pipeline.
- Writing to `/dev/nvidiactl` can corrupt ioctl channel -- may crash GPU or kernel module.
- Sizes range from 64KB (control) to multiple GB (full VRAM via resizable BAR).

**AMD/AMDGPU (Mesa RADV):**
```
7f6c00000000-7f6c10000000  rw-s  00100000  00:06  2345  /dev/dri/renderD128  # GEM buffer objects
7f6c20000000-7f6c20010000  rw-s  00000000  00:06  2346  /dev/dri/card0       # Card node
```
- GEM buffers via DRM subsystem. Offset field is a fake DRM handle, not a real file offset.
- GTT (Graphics Translation Table) buffers in system RAM may be CPU-readable but data is incoherent.
- AMDGPU "doorbell" pages: small `rw-s` mappings for GPU command submission signaling.

**Intel (i915 / xe):**
```
7f5000000000-7f5010000000  rw-s  00200000  00:06  3456  /dev/dri/renderD128
```
- Same DRM paths as AMD. Cannot distinguish by path alone (doesn't matter -- both `NeverTouch`).
- Shares system RAM (no discrete VRAM). Reads may succeed but return cache-incoherent data.

### 4.2 What Happens When You Touch GPU Memory

| Operation | CPU-resident pages | GPU-only pages |
|---|---|---|
| `process_vm_readv` | **Succeeds**, data may be stale/incoherent | **EFAULT** (safe failure) |
| `process_vm_writev` | **Corrupts GPU state** -- hang, crash, `VK_ERROR_DEVICE_LOST` | **EFAULT** (safe failure) |

**NVIDIA UVM special case:** Reading a GPU-resident UVM page may trigger page migration from
VRAM to RAM. This stalls the GPU pipeline, can cause GPU timeout ("GPU has fallen off the
bus" in dmesg), and performance tanks. Even reads are dangerous.

**Writing to GPU command buffers:** If the buffer is being executed by the GPU, writes cause
torn reads on the GPU side -- undefined behavior, GPU hang, requires GPU reset. If not yet
submitted, corrupts the next batch of GPU commands. If retired, corrupts recycled memory.

**Bottom line:** `process_vm_readv` naturally returns EFAULT on most GPU VRAM regions
(`VM_IO`/`VM_PFNMAP` pages). But some regions (GTT, shared memory, UVM with CPU residency)
won't EFAULT -- they just return useless or dangerous data. Our region classifier is the
primary defense, EFAULT is the backup.

### 4.3 DXVK and VKD3D-Proton Memory Layout

**DXVK (D3D9/D3D11 to Vulkan):**

| Region Type | Maps Appearance | Safety |
|---|---|---|
| Vulkan memory heaps | File-backed `/dev/dri/*` or `/dev/nvidia*`, `rw-s` | NeverTouch |
| Command buffer staging | Anonymous `rw-p`, 2-64MB | Risky (modifying corrupts DXVK state) |
| Shader cache (in-memory) | Anonymous `rw-p`, 64-512MB | Risky (scan OK, never write) |
| Shader cache (on-disk) | File-backed `.dxvk-cache` path, `r--p` or `rw-p` | ReadOnly |
| DXVK DLL data sections | Path contains `dxvk`/`d3d11`/`d3d9`, `rw-p` | Risky |

**VKD3D-Proton (D3D12 to Vulkan):**
- D3D12 heaps map to `vkAllocateMemory` -- appear as DRM device mappings, NeverTouch.
- Descriptor heaps are Vulkan buffers -- modifying causes GPU to reference invalid resources.
- Upload/readback heaps are host-visible Vulkan memory -- DRM mappings, NeverTouch.

**Identifying DXVK/VKD3D in maps paths:**
```
/path/to/proton/lib/wine/dxvk/d3d11.dll      # DXVK DLL
/path/to/proton/lib64/libdxvk_d3d11.so        # Native DXVK library
/path/to/pfx/drive_c/windows/system32/d3d12.dll  # VKD3D-Proton
```
Match case-insensitive substrings: `dxvk`, `vkd3d`, `d3d9`, `d3d10`, `d3d11`, `d3d12`, `dxgi`.

### 4.4 Wineserver Shared Memory

```
7f4000000000-7f4000010000  rw-s  00000000  00:01  3333  /dev/shm/wine-abcdef123456
```

Contains process synchronization data, file descriptor mapping tables, registry cache,
window management state, and signal delivery metadata. Corrupting any of these can:
- Deadlock individual threads (mild) or the entire Wine prefix (severe)
- Cause file handle table corruption -- writes go to wrong files, corrupting save data
- Break all Wine processes in the prefix (wineserver is shared across the prefix)

**The wineserver shares state across ALL processes in a Wine prefix. A single bad write
cascades to every Wine process.**

### 4.5 The `rw-s` Rule

**ANY mapping with `rw-s` (shared) permissions = `NeverTouch`. No exceptions.**

In the context of a Wine/Proton game process, `rw-s` mappings include:

| Source | Risk Level |
|---|---|
| GPU device memory (`/dev/nvidia*`, `/dev/dri/*`) | Critical -- GPU crash/hang |
| Wine shared memory (`/dev/shm/wine*`) | Critical -- prefix-wide corruption |
| PipeWire/PulseAudio (`/dev/shm/pulse-*`) | Moderate -- audio daemon crash |
| Futex-based IPC shared memory | High -- IPC corruption |
| D-Bus shared memory | Low -- service disruption |

---

## 5. Wine/Proton Process Model and Memory Layout

### 5.1 Process Tree

A typical Proton game session spawns:

| Process | Role | Scan? |
|---|---|---|
| `wineserver` | Kernel analog, manages handles/mutexes/registry | NEVER touch |
| `wine64-preloader` | Reserves Windows address space, then execs Wine loader | This IS the game process |
| `Game.exe` (via cmdline) | The actual game | **PRIMARY TARGET** |
| `services.exe` | Wine Service Control Manager | Skip |
| `winedevice.exe` | Kernel-mode driver host | Skip |
| `explorer.exe` | Desktop shell | Skip |
| `plugplay.exe`, `svchost.exe`, `conhost.exe` | Wine infrastructure | Skip |
| Steam overlay processes | Overlay rendering | Skip |

**Finding the game process:**
1. Walk `/proc/[pid]/cmdline` for all same-UID processes
2. Filter for `.exe` in cmdline
3. Exclude known infrastructure: `wineserver`, `services.exe`, `winedevice.exe`,
   `explorer.exe`, `plugplay.exe`, `svchost.exe`, `conhost.exe`, `rpcss.exe`, `tabtip.exe`
4. Validate: check `/proc/[pid]/maps` for PE image near `0x140000000` (64-bit) or `0x400000` (32-bit)
5. Tiebreaker: largest RSS (`/proc/[pid]/statm`) among remaining candidates

Note: `/proc/[pid]/exe` points to the Wine preloader/loader, NOT the game .exe. The game
name only appears in `/proc/[pid]/cmdline` and `/proc/[pid]/maps`.

### 5.2 Windows PE Layout in Memory

**64-bit game (standard Proton):**
```
140000000-140001000  r--p  ...  Game.exe         # PE headers
140001000-1401a0000  r-xp  ...  Game.exe         # .text (code) -- ReadOnly
1401a0000-1401f0000  r--p  ...  Game.exe         # .rdata (read-only data) -- ReadOnly
1401f0000-140210000  rw-p  ...  Game.exe         # .data/.bss (globals) -- SAFE
140210000-140215000  r--p  ...  Game.exe         # .rsrc (resources) -- ReadOnly
```

The `rw-p` section (`.data`/`.bss`) contains global and static variables -- sometimes game
values live here. These are **excellent scan targets** because they are stable within a
session and their offset from module base survives restarts.

**Wine system DLLs (do NOT write):**
```
/path/to/proton/dist/lib64/wine/x86_64-windows/ntdll.dll
/path/to/proton/dist/lib64/wine/x86_64-windows/kernel32.dll
/path/to/proton/dist/lib64/wine/x86_64-windows/user32.dll
```

**Game-specific DLLs (scan their `rw-p` sections):**
```
/path/to/game/UnityPlayer.dll
/path/to/game/GameAssembly.dll        # IL2CPP
/path/to/game/Engine/Binaries/Win64/UnrealEngine.dll
```

### 5.3 Wine Heap Implementation

Wine implements the full Windows heap API in `dlls/ntdll/heap.c`. This is a **custom
allocator** that directly calls `mmap` -- it does NOT use glibc `malloc`.

**Allocation path:**
```
Game calls HeapAlloc() / new / malloc()
  -> MSVCRT malloc() -> HeapAlloc(GetProcessHeap(), ...)
    -> RtlAllocateHeap() in ntdll
      -> Wine's heap manager (heap.c)
        -> NtAllocateVirtualMemory() for large allocs or new subheaps
          -> Linux mmap() syscall
```

**Heap structure:**
- Each heap contains a list of **subheaps** -- contiguous mmap'd `rw-p` regions
- Default initial subheap: 64KB, grows by doubling (64K -> 128K -> 256K -> ...)
- Large allocations (> ~508KB) get their own dedicated mmap, visible as individual
  anonymous `rw-p` entries in `/proc/[pid]/maps`
- Each allocation has an 8-16 byte block header (size, flags)
- Multiple heaps per process: process default heap, MSVCRT heap, application-created heaps

**All heaps produce anonymous `rw-p` regions.** This is where game values live.

### 5.4 HeapAlloc vs VirtualAlloc

| Mechanism | Size Range | Maps Appearance | Typical Use |
|---|---|---|---|
| `HeapAlloc` | Bytes to ~500KB | Part of a larger subheap region | Most game values |
| `VirtualAlloc` | Pages (4KB+) | Individual anonymous `rw-p` entries | Level data, custom allocators, VM memory |

UE4/UE5 games use `VirtualAlloc` extensively for their own memory pools. Both produce
anonymous `rw-p` regions that are safe to scan.

### 5.5 ASLR and Address Stability

**Within a session:** Module bases, heap bases, and individual allocation addresses are
stable. Scan results are valid for the entire session.

**Across restarts:** All addresses change. Module base offsets within a module are stable.
Pointer chains survive: `[module_base + 0x1234] -> [+0x48] -> [+0x10] -> value`.

### 5.6 Address Space Layout (64-bit Proton Game)

```
0x000000000 - 0x140000000   Low addresses, some Wine allocations
0x140000000 - 0x180000000   PE base region (Game.exe, game DLLs)  <- PRIMARY TARGET
0x180000000 - 0x7BC000000   More heap, game DLLs, Wine internal
0x7BC000000 - 0x7C0000000   Wine system DLLs (ntdll, kernel32)
0x7F0000000 - 0x7F8000000   Linux libraries, GPU driver mappings  <- DANGER ZONE
0x7FF000000 - 0x800000000   Stack, VDSO, kernel                   <- OFF LIMITS
```

### 5.7 Common Value Encodings

| Game Concept | Typical Type | Notes |
|---|---|---|
| Health / Mana / Stamina | `int32` | Most common. Some games use `float32` |
| Float stats (multipliers) | `float32` | e.g., `1.0` stamina multiplier |
| Money / Score | `int32` or `int64` | `int64` for large economies |
| Boolean flags | `int32` (0/1) | Windows `BOOL` is 4 bytes |
| Timers / Cooldowns | `float32` | In seconds |
| Position (XYZ) | Three consecutive `float32` | Often followed by rotation quaternion |

### 5.8 Game Engine Object Patterns

**Unreal Engine 4/5 (common in Proton games):**
- Custom allocator (`FMallocBinned2`) via `VirtualAlloc` pools
- UObject at +0x00: vtable, +0x08: ObjectFlags, +0x10: ClassPrivate, +0x18: NamePrivate
- Typical pointer chain depth: 3-6 levels (module -> GEngine -> World -> Actor -> Component -> value)

**Unity IL2CPP:**
- `GameAssembly.dll` contains compiled C# code
- Object at +0x00: vtable/Il2CppClass*, +0x08: MonitorData, +0x10: first field
- Boehm GC heap in anonymous `rw-p` regions
- Typical pointer chain depth: 2-4 levels

**Source 2:**
- Entity lists at known offsets from client.dll base
- Typical pointer chain depth: 2-4 levels

---

## 6. Region Classification System

### 6.1 Decision Tree

This is the algorithm for `maps.rs`. Applied to every region before any access (scan or write).

```
1. Is it rw-s (shared)?
   -> NeverTouch. No exceptions. GPU drivers and wineserver communicate via shared memory.

2. Does the path match /dev/*?
   -> NeverTouch. GPU devices, input, sound.

3. Does the path match /dev/shm/*?
   -> NeverTouch. IPC shared memory (Wine, audio, D-Bus).

4. Does the path contain "wineserver"?
   -> NeverTouch.

5. Is it r-xp or r--p (no write permission)?
   -> ReadOnly. Code or read-only data. Scan OK, never write.

6. Does the path contain dxvk/vkd3d/d3d9/d3d10/d3d11/d3d12/dxgi (case-insensitive)?
   -> Risky. Scan with low confidence flag, never write.

7. Does the path contain vulkan/mesa/radeonsi/amdgpu/nvidia (.so files)?
   -> Risky. Scan with low confidence flag, never write.

8. Is it a Wine system DLL? (ntdll, kernel32, user32, gdi32, advapi32, etc.)
   -> Risky. Avoid writing.

9. Is it anonymous rw-p (no file path)?
   a. Labeled [stack] or exactly RLIMIT_STACK size with ---p guard page below?
      -> Skip (thread stack). Writing corrupts local variables and return addresses.
   b. Labeled [heap]?
      -> Safe. (But this is glibc heap, not Wine heap -- low priority for game values.)
   c. Smaller than 4KB?
      -> Skip. Runtime bookkeeping, TLS.
   d. Larger than 1GB?
      -> Risky. Likely DXVK shader cache or GPU staging.
   e. Otherwise?
      -> Safe. This is the Windows heap. PRIMARY SCAN TARGET.

10. Is it rw-p with a path to the game's own .exe or .dll?
    -> Safe. PE writable data sections -- globals and statics.

11. Everything else:
    -> ReadOnly or Skip.
```

### 6.2 Annotated Maps Example

```
# === SAFE: PE writable data (.data/.bss) -- global variables ===
140000000-140001000  r--p  ...  Game.exe          # PE headers (ReadOnly)
140001000-142000000  r-xp  ...  Game.exe          # .text (ReadOnly)
142000000-142800000  r--p  ...  Game.exe          # .rdata (ReadOnly)
142800000-142900000  rw-p  ...  Game.exe          # .data/.bss (SAFE)

# === SAFE: Windows heap -- PRIMARY TARGETS ===
142900000-142a00000  rw-p  00000000 00:00 0       # Anonymous rw-p (Safe)
150000000-158000000  rw-p  00000000 00:00 0       # Large heap (Safe)
160000000-168000000  rw-p  00000000 00:00 0       # Large heap (Safe)

# === SAFE: Game DLL data section ===
180200000-180210000  rw-p  ...  GameLogic.dll     # Game DLL .data (Safe)

# === RISKY: DXVK DLLs -- scan OK, never write ===
7bc800000-7bc820000  rw-p  ...  d3d11.dll         # DXVK data (Risky)

# === RISKY: Wine system DLLs -- avoid writing ===
7bc100000-7bc110000  rw-p  ...  ntdll.dll         # Wine ntdll (Risky)

# === NEVER TOUCH: GPU driver ===
7f2000000000-7f2100000000  rw-s  ...  /dev/nvidia0
7f2100000000-7f2200000000  rw-s  ...  /dev/nvidia-uvm
7f2200000000-7f2200010000  rw-s  ...  /dev/nvidiactl

# === NEVER TOUCH: Wine shared memory ===
7f4000000000-7f4000010000  rw-s  ...  /dev/shm/wine-abcdef123456

# === RISKY: Large anonymous (possible shader cache) ===
7f6000000000-7f6040000000  rw-p  00000000 00:00 0   # 1GB anonymous (Risky)

# === SKIP: Thread stack ===
7f7ff7e00000-7f7ff8600000  rw-p  00000000 00:00 0   # 8MB = stack
7f7ff8600000-7f7ff8601000  ---p  00000000 00:00 0   # Guard page

# === OFF LIMITS: Kernel ===
7ffff7fc0000-7ffff7fc4000  r--p  ...  [vvar]
7ffff7fc4000-7ffff7fc6000  r-xp  ...  [vdso]
7ffffffde000-7ffffffff000  rw-p  ...  [stack]
```

### 6.3 Pre-Flight Write Safety Check

**Mandatory before every `process_vm_writev` call.** DXVK can remap regions between scan
and write (command buffer recycling, resource streaming, shader compilation).

```
1. Re-read /proc/[pid]/maps (the file, NOT a cached copy)
2. Find the region containing the target address
3. Re-classify using the decision tree above
4. ONLY proceed if classification is Safe
5. If classification changed -> abort write, return error to FastAPI
```

This re-check also applies to every iteration of the freeze loop.

---

## 7. Scan Engine Architecture

### 7.1 SIMD Scanning Strategy

**Primary: AVX2 (256-bit, 32 bytes per cycle)**
Available on all modern x86_64 gaming CPUs (Haswell 2013+, Zen 2017+).

For scanning a 4-byte value (i32/u32/f32):
1. Broadcast target value to all 8 lanes of a `__m256i` register
2. Load 32 bytes from buffer (`_mm256_loadu_si256`)
3. Compare all 8 dwords simultaneously (`_mm256_cmpeq_epi32`)
4. Extract bitmask (`_mm256_movemask_epi8`)
5. Decode hit lanes from the 32-bit mask

**Fallback: SSE2 (128-bit, 16 bytes per cycle)**
Available on ALL x86_64 CPUs. Same algorithm with `__m128i` (4 lanes instead of 8).

**Runtime feature detection:**
```rust
fn scan_i32(buffer: &[u8], value: i32) -> Vec<usize> {
    if is_x86_feature_detected!("avx2") {
        unsafe { scan_i32_avx2(buffer, value) }
    } else {
        unsafe { scan_i32_sse2(buffer, value) }
    }
}
```

**Multi-type first scan:** A numeric value (e.g., `100`) has at most 3-4 distinct byte
patterns: i32/u32 (same bytes), f32 (different bytes), i64/u64 (same bytes, 8-byte), f64
(different bytes, 8-byte). All patterns are checked in the same pass over each buffer
chunk. The overhead of additional SIMD comparisons per chunk is negligible vs memory read cost.

**Float epsilon comparison in SIMD:**
For f32 values that may have drifted due to floating-point arithmetic:
1. Load 8 floats from buffer (`_mm256_loadu_ps`)
2. Subtract target (`_mm256_sub_ps`)
3. Absolute value (clear sign bit with `_mm256_and_ps`)
4. Compare against epsilon (`_mm256_cmp_ps` with `_CMP_LE_OQ`)
5. Extract mask

### 7.2 Parallelization with Rayon

**Region-level parallelism:** Each memory region is an independent work unit.

```rust
regions
    .par_iter()
    .filter(|r| r.safety == RegionSafety::Safe)
    .flat_map(|region| scan_region(pid, region, value))
    .collect()
```

**Within each region:** Sequential 4MB chunked reads. Do NOT parallelize within a region --
rayon task scheduling overhead exceeds the benefit for sequential I/O.

**Thread pool sizing:** Rayon default (all cores). Memory bandwidth typically saturates at
2-4 cores for `process_vm_readv` workloads, but the work-stealer handles this naturally.

**Buffer reuse:** Pre-allocate one 4MB buffer per thread via `thread_local!` to avoid
per-chunk heap allocation.

### 7.3 Candidate Storage

**Compact representation (16 bytes per candidate):**
```rust
struct Candidate {
    address: u64,          // 8 bytes
    types: TypeFlags,      // 1 byte (bitflags: I32|U32|F32|I64|U64|F64)
    confidence: u8,        // 1 byte (incremented on each confirming filter pass)
    _pad: [u8; 6],         // alignment padding
}
```
1 million candidates = 16 MB. Sorted by address for cache-friendly sequential access and
binary search lookups.

**JSON serialization:** Addresses as hex strings (JavaScript `Number` loses precision above 2^53).

### 7.4 Filter Pass Optimization

On filter passes, read only candidate addresses (not full regions).

**iovec coalescing:** Group nearby candidates into contiguous reads. If 500 candidates are
within the same 4KB page, that is 1 iovec entry instead of 500. Use a max gap of 64 bytes
for coalescing.

**IOV_MAX limit:** Linux limits each `process_vm_readv` to 1024 local and 1024 remote iovec
entries. Batch candidates accordingly. If a batch fails (one unmapped page aborts the whole
batch), fall back to individual reads for that batch.

**Typical convergence:**
- First scan: 100K-1M+ candidates
- After 1 filter pass: 1K-10K candidates
- After 2-3 filter passes: 1-50 candidates

### 7.5 Pointer Chain Walking

**Algorithm: BFS (breadth-first)** -- finds shortest chains first.

```
Given target address T:
Level 0: T
Level 1: Scan all Safe regions for pointers P where [P] is in [T-4096, T+4096]
Level 2: For each P from level 1, scan for pointers to P
...
Stop when: a chain endpoint is inside a known module (stable base), or max depth reached
```

**Parameters:**
- Max offset: 4096 bytes (game structs rarely exceed this)
- Max depth: 4-5 levels (sufficient for UE4/5, Unity, Source)
- Only scan Safe and ReadOnly regions for pointers
- Prioritize pointers in module `.data` sections (most stable roots)
- Alignment: 8-byte aligned only (x86_64 pointer alignment)

**Performance:** A depth-3 pointer scan of 2GB takes ~2-5 seconds per level. Pre-build
a sorted index of all pointer-sized values for binary search of target ranges.

### 7.6 Freeze Loop

**Runs in a `std::thread` (not tokio):**
- Configurable interval per address (default 100ms)
- Each write iteration must re-check region safety (re-read `/proc/[pid]/maps`)
- Uses `DashMap<u64, FreezeEntry>` for the freeze registry
- Exposed via JSON-RPC: `freeze.start`, `freeze.stop`, `freeze.list`
- The freeze loop is completely independent of the scan engine

---

## 8. Implementation Decisions

### 8.1 Crate Selection

| Crate | Version | Purpose |
|---|---|---|
| `nix` | 0.29+ | `process_vm_readv`/`writev`, ptrace attach/detach, signal handling |
| `rayon` | 1.10+ | Parallel iteration over memory regions |
| `memchr` | 2.x | Baseline byte search (used for AOB scanning) |
| `bytemuck` | 1.x | Safe zero-copy byte buffer to typed value transmutation |
| `capstone` | 0.12+ | x86_64 disassembly for code analysis |
| `serde` / `serde_json` | 1.x | JSON-RPC serialization |
| `tokio` | 1.x | Async Unix socket server, progress channels |
| `anyhow` | 1.x | Application-level error handling |
| `thiserror` | 2.x | Library-facing error types |
| `bitflags` | 2.x | `TypeFlags` for multi-type candidate tracking |
| `dashmap` | 6.x | Concurrent freeze registry |
| `uuid` | 1.x | Scan session identifiers |
| `proc-maps` | 0.4+ | `/proc/[pid]/maps` parsing baseline (extend for Wine classification) |

### 8.2 Architecture: Hybrid Async + CPU-Bound

```
tokio runtime (async I/O)
  |
  |-- Unix socket listener (JSON-RPC server)
  |-- Progress notification channels
  |-- Scanner process lifecycle management
  |
  |-- tokio::task::spawn_blocking() bridge
        |
        rayon thread pool (CPU-bound)
          |-- SIMD scan across regions
          |-- Filter pass with coalesced iovecs
          |-- Pointer chain BFS

std::thread (independent, no tokio)
  |-- Freeze loop (writes every 100ms per address)
```

`spawn_blocking` bridges async to CPU-bound. Inside the blocking closure, rayon's work
stealing handles parallelism. Progress flows back via `tokio::sync::mpsc` channels.

### 8.3 JSON-RPC Server Design

**Line-delimited JSON-RPC 2.0 over Unix socket** (`/tmp/memscout.sock`).

Each request/response is a single JSON object terminated by `\n`. Progress updates sent as
JSON-RPC notifications (no `id` field). Debuggable with:
```bash
echo '{"jsonrpc":"2.0","method":"pid.list","params":{},"id":1}' | socat - UNIX-CONNECT:/tmp/memscout.sock
```

Hand-rolled rather than using `jsonrpsee` framework -- simpler for the single-client use
case and gives full control over progress streaming.

### 8.4 Scan Session Management

Sessions tracked by UUID. Each session holds:
- Candidate list (`Vec<Candidate>`, sorted by address)
- Original scan parameters (value, dtype, pid)
- Region snapshot at scan time (for delta detection)

Sessions are stored in a `HashMap<String, ScanSession>` protected by a `Mutex`. The mutex
is only held briefly for lookup/insert -- the actual scanning does not hold the lock.

`scan.discard` frees a session's memory. Important for long-running processes -- a forgotten
session with 1M candidates holds 16MB.

---

## 9. Risk Analysis and Mitigations

### 9.1 Risk: GPU Deadlock from SIGSTOP

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| `ptrace(PTRACE_ATTACH)` in code | N/A -- architecturally prevented | System freeze | Never use ptrace for reads/writes. Only for disassembly (attach single thread, detach immediately). |
| Accidental SIGSTOP | N/A -- we never signal the target | System freeze | Code review: grep for `kill`, `signal`, `ptrace`. Zero tolerance. |

### 9.2 Risk: Corrupting GPU Driver Memory

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Writing to `/dev/nvidia*` mapping | Prevented by region classifier | GPU crash, system reboot | `NeverTouch` classification for all `/dev/*` paths. `rw-s` rule. Pre-flight re-classify before write. |
| Reading NVIDIA UVM triggers page migration | Prevented by region classifier | GPU stall, performance hit | `NeverTouch` for all `/dev/nvidia-uvm` regions. |
| Writing to AMD DRM GEM buffer | Prevented by region classifier | GPU hang | `NeverTouch` for all `/dev/dri/*` paths. |

### 9.3 Risk: Corrupting Wineserver Shared Memory

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Writing to `/dev/shm/wine*` | Prevented by region classifier | Entire Wine prefix deadlock | `NeverTouch` for all `/dev/shm/*` paths. `rw-s` rule catches all shared memory. |

### 9.4 Risk: DXVK Region Remap Between Scan and Write

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Region re-classified after scan | Low but non-zero (DXVK recycles command buffers) | Write to wrong region type | **Mandatory pre-flight re-classify** before every write. Re-read `/proc/[pid]/maps`, re-classify target address. Abort if not `Safe`. |

### 9.5 Risk: Game Crash from Writing Wrong Address

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Write to game code section | Prevented (ReadOnly classification) | Game crash | Code sections are `r-xp`, classified ReadOnly, write rejected. |
| Write to Wine internal data | Low (user must deliberately target) | Wine malfunction | Wine system DLLs classified Risky, write rejected. |
| Write to wrong heap address | User error possible | Game crash | Claude agent should validate: read address, confirm value matches, then write. |

### 9.6 Risk: Scanner Crash Doesn't Affect Game

The scanner runs in a separate process. If it crashes (panic, OOM, bug), the game process
is completely unaffected. `process_vm_readv`/`writev` are stateless -- no persistent
attachment between scanner and game. The FastAPI backend detects the crash via
`ensure_running()` and restarts the scanner binary transparently.

### 9.7 Risk: Partial Reads from Unmapped Memory

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| `process_vm_readv` returns partial data | Common (dynamic memory layout) | False negatives, not corruption | Always check return value. Process bytes received. Skip rest of region chunk. |
| `EFAULT` on entire region | Occasional (region unmapped between maps read and scan) | Missed region | Log, skip, continue. Not a safety issue. |

---

## Appendix A: Performance Budget

Target: first scan of 2GB game heap completes in < 500ms.

```
Read phase:   2 GB / 8 GB/s throughput = 250ms (process_vm_readv, 4 cores, 4MB chunks)
Scan phase:   2 GB / 12 GB/s SIMD      = 167ms (AVX2, 4 cores via rayon)
Overlap:      read and scan pipeline    = ~300ms total (scan previous chunk while reading next)
Overhead:     maps parsing + session creation = ~10ms
-----------------------------------------------------------------
Total:        ~310ms for 2GB first scan (meets target)
```

Filter pass on 10K candidates:
```
iovec build:  10K candidates, coalesced to ~2K iovecs = ~1ms
Read phase:   ~2K small reads via process_vm_readv = ~5ms
Compare:      10K comparisons = ~0.01ms
Total:        ~6ms
```

---

## Appendix B: Key Kernel Source References

| File | Contains |
|---|---|
| `mm/process_vm_access.c` | `process_vm_readv`/`writev` implementation |
| `kernel/ptrace.c` | `ptrace_may_access()` permission check |
| `security/yama/yama_lsm.c` | Yama ptrace_scope enforcement |
| `mm/memory.c` | `get_user_pages_remote()`, `access_remote_vm()` |
| `include/uapi/linux/uio.h` | `struct iovec`, `UIO_MAXIOV` (1024) |

## Appendix C: Key Wine Source References

| File | Contains |
|---|---|
| `dlls/ntdll/heap.c` | Wine heap manager (HeapAlloc, HeapFree) |
| `dlls/ntdll/unix/virtual.c` | Virtual memory management (VirtualAlloc -> mmap) |
| `loader/preloader.c` | Address space reservation |
| `server/` directory | Wineserver implementation |
| `dlls/ntdll/thread.c` | Thread creation (CreateThread -> clone) |

---

*Analysis date: 2026-04-10*
*Research scope: Linux kernel 5.x+, Wine 8.x+, Proton 8.x+, DXVK 2.x+, VKD3D-Proton 2.x+*
*Target platform: x86_64 Linux gaming rigs with NVIDIA or AMD GPUs*
