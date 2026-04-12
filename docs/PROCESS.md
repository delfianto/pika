# process — Process Discovery, Maps Parsing, and Platform Checks

The `process` module handles everything pika needs to know about target processes
before any memory is read or written: finding Wine/Proton game processes, parsing and
classifying their memory maps, and verifying that the host platform supports the
required system calls.

## Submodules

| Submodule | File | Purpose |
|---|---|---|
| `pid` | `process/pid.rs` | Wine/Proton game process discovery |
| `maps` | `process/maps.rs` | `/proc/[pid]/maps` parsing and region safety classification |
| `platform` | `process/platform.rs` | Platform capability checks (ptrace_scope, CAP_SYS_PTRACE) |

---

## Process discovery (`pid`)

Proton spawns a complex process tree for every game. The challenge is distinguishing
the actual game from Wine infrastructure.

### The process tree

| Process | Role | Target? |
|---|---|---|
| `wineserver` | Kernel analog, manages handles/mutexes/registry | Never |
| `wine64-preloader` | Reserves Windows address space, execs Wine loader | This IS the game |
| `Game.exe` (cmdline) | The actual game | **Yes** |
| `services.exe` | Wine Service Control Manager | No |
| `winedevice.exe` | Kernel-mode driver host | No |
| `explorer.exe` | Desktop shell | No |
| `plugplay.exe`, `svchost.exe`, `conhost.exe` | Wine infrastructure | No |
| `steam.exe`, `steamwebhelper.exe` | Steam overlay | No |

### Discovery algorithm

```
1. Walk /proc/ for all numeric directories (PIDs)
2. Read /proc/[pid]/exe symlink
3. FILTER: exe must resolve to a Wine binary:
   wine, wine64, wine-preloader, wine64-preloader
4. Read /proc/[pid]/cmdline (NUL-separated)
5. Extract .exe name from argv[0] ONLY
6. FILTER: argv[0] must end with .exe (case-insensitive)
7. FILTER: exclude known Wine infrastructure names
8. Return (pid, name, exe_path)
```

### Why argv[0] only

Launcher processes like `systemd-inhibit`, `reaper`, `pressure-vessel`, and `python3`
pass `.exe` paths as arguments (e.g., `python3 /path/to/proton waitforexitandrun
/path/to/Game.exe`). If we searched the entire cmdline for `.exe`, these launchers
would be false positives. Examining only argv[0] — the actual program being run —
eliminates this class of errors.

### Infrastructure filter list

The following process names are excluded as known Wine infrastructure:

```
services.exe, winedevice.exe, explorer.exe, plugplay.exe,
svchost.exe, conhost.exe, rpcss.exe, tabtip.exe, start.exe,
winedbg.exe, winemenubuilder.exe, steam.exe, xalia.exe,
crashpad_handler.exe, steamwebhelper.exe
```

---

## Memory map classification (`maps`)

This is pika's primary safety mechanism. Every memory region is classified into one of
four safety levels before any access.

### Safety levels

| Level | Scan? | Write? | Meaning |
|---|---|---|---|
| `Safe` | Yes | Yes | Windows heap, PE data sections, game DLLs |
| `ReadOnly` | Yes | No | PE code sections, kernel vDSO, read-only data |
| `Risky` | With caution | No | DXVK/VKD3D heaps, Wine system DLLs, GPU driver libs |
| `NeverTouch` | No | No | GPU device mappings, shared memory, wineserver |

### Classification rules (priority-ordered)

Rules are evaluated in order. The first match wins.

**Rule 1 — Shared mappings (`rw-s`): `NeverTouch`**

Any mapping with the shared flag is off-limits, no exceptions. In a Wine/Proton game
process, `rw-s` mappings include GPU device memory, wineserver IPC, PulseAudio/PipeWire
shared buffers, and futex-based IPC. Writing to any of these can crash the GPU,
corrupt the entire Wine prefix, or hang the audio daemon.

**Rule 2 — `/dev/*` paths: `NeverTouch`**

GPU devices (`/dev/nvidia0`, `/dev/dri/renderD128`, `/dev/nvidia-uvm`), input devices,
and sound devices. Reading NVIDIA UVM pages can trigger GPU page migration, stalling
the GPU pipeline. Writing to `/dev/nvidiactl` can corrupt the ioctl channel.

**Rule 3 — Wineserver paths: `NeverTouch`**

Any path containing `wineserver`. The wineserver shares state across all processes in
a Wine prefix. A single bad write cascades to every Wine process.

**Rule 4 — No write permission: `ReadOnly`**

Regions without the write bit (`r--p`, `r-xp`) are code sections or read-only data.
Safe to scan (may find constants or vtable pointers) but must never be written via
`process_vm_writev`. Code patching uses `/proc/pid/mem` instead, which bypasses page
protections.

**Rule 5 — DXVK / VKD3D / D3D translation layers: `Risky`**

Paths containing (case-insensitive): `dxvk`, `vkd3d`, `d3d9`, `d3d10`, `d3d11`,
`d3d12`, `dxgi`. These are the GPU translation layers. Their data sections contain
internal state that, if modified, corrupts GPU command submission.

**Rule 6 — GPU driver userspace libraries: `Risky`**

Shared object files (`.so`) whose paths contain: `vulkan`, `mesa`, `radeonsi`,
`amdgpu`, `nvidia`, `libvulkan`. Only `.so` files are matched — `/dev/` paths are
already caught by Rule 2.

**Rule 7 — Wine system DLLs: `Risky`**

Well-known Wine DLL names: `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `user32.dll`,
`gdi32.dll`, `advapi32.dll`, `msvcrt.dll`, `ucrtbase.dll`, `ws2_32.dll`, `ole32.dll`,
`oleaut32.dll`, `rpcrt4.dll`, `combase.dll`, `sechost.dll`, `bcrypt.dll`, `crypt32.dll`,
`setupapi.dll`, `version.dll`, `imm32.dll`, `winmm.dll`, `dbghelp.dll`, plus patterns
for `xinput`, `xaudio`, `wined3d`, `winevulkan`, `winex11`, `winewayland`.

**Rule 8 — Anonymous `rw-p` regions: size heuristics**

| Condition | Classification | Rationale |
|---|---|---|
| Label `[stack]` or `[stack:<tid>]` | `Risky` | Writing corrupts local variables and return addresses |
| Label `[vdso]`, `[vvar]`, `[vsyscall]` | `ReadOnly` | Kernel-provided |
| Label `[heap]` | `Safe` | glibc heap (low priority for game values but safe) |
| Size < 4 KB | `Risky` | Runtime bookkeeping, TLS, guard pages |
| Size > 1 GB | `Risky` | Likely DXVK shader cache or GPU staging |
| Otherwise | **`Safe`** | **Windows heap — primary scan target** |

**Rule 9 — File-backed `rw-p` game DLLs/EXEs: `Safe`**

If a writable, private, file-backed region reached this point without matching any
system DLL or GPU library pattern, it is a game's own `.exe` or `.dll` data section.
These contain global and static variables — excellent scan targets with stable offsets
from the module base.

### Annotated maps example

```
# Safe: PE writable data (.data/.bss)
142800000-142900000  rw-p  ...  Game.exe

# Safe: Windows heap (anonymous rw-p, primary scan targets)
142900000-14a000000  rw-p  00000000 00:00 0

# ReadOnly: PE code section
140001000-142000000  r-xp  ...  Game.exe

# Risky: DXVK data section
7bc800000-7bc820000  rw-p  ...  /path/to/dxvk/d3d11.dll

# NeverTouch: GPU device mapping (shared)
7f2000000000-7f2100000000  rw-s  ...  /dev/nvidia0

# NeverTouch: Wine shared memory (shared)
7f4000000000-7f4000010000  rw-s  ...  /dev/shm/wine-abc123

# Risky: Thread stack
7ffffffde000-7ffffffff000  rw-p  ...  [stack]
```

---

## Platform checks (`platform`)

Before serving, pika checks whether the host can actually access other processes'
memory.

### What is checked

1. **`/proc/sys/kernel/yama/ptrace_scope`**: Controls `process_vm_readv` permissions.

   | Value | Effect | Common distros |
   |---|---|---|
   | 0 (classic) | Same-UID access unrestricted | Arch, Manjaro, SteamOS |
   | 1 (restricted) | Needs `CAP_SYS_PTRACE` or parent relationship | Ubuntu, Fedora |
   | 2 (admin-only) | Needs `CAP_SYS_PTRACE` | Hardened systems |
   | 3 (no-attach) | Blocked entirely | Rare |

2. **`CAP_SYS_PTRACE`**: Read from `/proc/self/status` `CapEff` field, bit 19.

3. **Root check**: `geteuid() == 0` bypasses Yama restrictions.

4. **`/proc` mounted**: Sanity check that procfs is available.

### Actionable warnings

When the platform check fails, pika prints specific remediation commands:

```
ptrace_scope=1 (restricted). pika needs CAP_SYS_PTRACE to scan.
Fix with:  sudo setcap cap_sys_ptrace=eip /path/to/pika
Or:        sudo sysctl kernel.yama.ptrace_scope=0
```
