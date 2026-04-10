# pika

Non-stopping memory scanner for Wine/Proton games on Linux.

Traditional memory editors (scanmem, PINCE, GameConqueror) use `ptrace PTRACE_ATTACH`
which sends `SIGSTOP` to the target — freezing DXVK/VKD3D mid-GPU-submission and
deadlocking the wineserver. Pika uses `process_vm_readv`/`process_vm_writev` instead,
which read and write another process's memory without stopping it at all.

## Features

- SIMD-accelerated scanning (AVX2/SSE2) — scans multi-GB address spaces in under a second
- Region safety classification — never touches GPU driver mappings, wineserver shm, or DXVK internals
- Multi-type first scan (i32, u32, f32, i64, u64, f64) in a single pass
- Six filter modes: exact, not-equal, increased, decreased, changed, unchanged
- Value freezing with configurable write interval
- AOB/signature scanning with wildcard patterns
- Pointer chain discovery (BFS)
- Disassembly via capstone
- Daemon/client architecture — CLI commands route through a persistent server
- JSON-RPC 2.0 protocol for integration with external tools

## Install

```bash
# Requires Rust 1.85+ (edition 2024)
git clone https://github.com/delfianto/pika.git
cd pika

# Build and install to ~/.local/bin
just install

# Or manually
cargo build --release
cp target/release/pika ~/.local/bin/
```

On Ubuntu or systems with `ptrace_scope=1`:
```bash
sudo setcap cap_sys_ptrace=eip ~/.local/bin/pika
```

## Quick Start

```bash
# Start the daemon
pika serve &

# List game processes
pika ps

# Scan, filter, write
pika scan <pid> <value>
pika filter <session-id> <new-value>
pika write-all <session-id> <value> --dtype i32
```

## Real-World Example: Avowed (Unreal Engine 5)

Setting the player's grenade count from 20 to 90 in a live game session.

### Server (daemon with verbose logging)

```
$ pika --verbose serve
INFO  pika: platform check passed -- memory scanning available
INFO  pika::rpc::server: listening on /tmp/pika.sock
```

### Client (another terminal)

**Find the game process:**
```
$ pika ps
PID      NAME
742467   Avowed.exe
742473   Avowed-Win64-Shipping.exe
```

The actual game is `Avowed-Win64-Shipping.exe` (UE5 naming convention). The other entry
is the launcher stub.

**First scan — player has 20 grenades:**
```
$ pika scan 742473 20
Session: mM72WmZA58qj
Candidates: 763329
```

763K candidates across 9.9 GB of game memory. Server log:
```
DEBUG maps loaded, 9909.9 MB to scan  safe_regions=29171
DEBUG scanning for value  value=20.0 dtype=auto patterns=4
DEBUG scan complete  candidates=763329 elapsed_ms=413 throughput_mb_s=23988
```

**Use a grenade in-game (20 -> 16), filter:**
```
$ pika filter mM72WmZA58qj 16
Candidates remaining: 102
```

**Use another (16 -> 14):**
```
$ pika filter mM72WmZA58qj 14
Candidates remaining: 5
```

**One more (14 -> 12):**
```
$ pika filter mM72WmZA58qj 12
Candidates remaining: 4
  [0] 0x113476178        i32|u32          confidence=3
  [1] 0x113476180        i32|u32          confidence=3
  [2] 0x133a77698        i32|u32          confidence=3
  [3] 0x15b99a998        i32|u32          confidence=3
```

4 addresses — UE5 tracks the value in multiple places. All confirmed i32.

**Write 90 to all of them:**
```
$ pika write-all mM72WmZA58qj 90 --dtype i32
  wrote 90 (i32) -> 0x113476178
  wrote 90 (i32) -> 0x113476180
  wrote 90 (i32) -> 0x133a77698
  wrote 90 (i32) -> 0x15b99a998
4 addresses written.
```

Each write goes through a pre-flight safety check — re-reads `/proc/pid/maps` and
verifies the region is still classified `Safe` before writing.

**Result:** Player now has 90 grenades. Game continues running without any stutter or
GPU interruption.

## CLI Reference

```
pika serve [--stdio]              Start the daemon
pika ps                           List Wine/Proton game processes
pika maps <pid>                   Show classified memory regions
pika scan <pid> <value>           Scan for a value
pika filter <sid> <value>         Filter candidates (--mode exact|increased|decreased|changed|unchanged)
pika sessions                     List active scan sessions
pika write <pid> <addr> <val>     Write a single address (--dtype i32)
pika write-all <sid> <val>        Write all candidates in a session (--dtype i32)
pika freeze <pid> <addr> <val>    Freeze a single address (--dtype i32)
pika freeze-all <sid> <val>       Freeze all candidates (--dtype i32)
pika unfreeze <addr>              Stop freezing an address
pika freeze-list                  List active freezes
pika read <pid> <addr>            Hex dump memory
pika disasm <pid> <addr>          Disassemble instructions
pika aob <pid> "48 89 ?? 24"      Byte pattern scan with wildcards
pika pointer-scan <pid> <addr>    Find pointer chains to an address
```

Global flags: `--verbose`, `--json`, `--socket <path>`

## Safety

- Never uses `ptrace` for reads/writes — no SIGSTOP, no GPU deadlocks
- Region classifier blocks access to GPU driver mappings (`/dev/nvidia*`, `/dev/dri/*`),
  wineserver shared memory, and DXVK/VKD3D internal regions
- All `rw-s` (shared) mappings are classified `NeverTouch` — no exceptions
- Pre-flight re-classification before every write (DXVK can remap regions dynamically)
- `write-all` / `freeze-all` refuse to operate on more than 16 addresses without `--force`

## Architecture

```
CLI commands ──> Unix socket ──> pika serve (daemon)
                                  ├── scan engine (rayon + SIMD)
                                  ├── region classifier (maps.rs)
                                  ├── write engine (pre-flight safety)
                                  ├── freeze threads (std::thread per address)
                                  └── process_vm_readv / process_vm_writev
                                        (no SIGSTOP, no ptrace)
```

## License

GPL-3.0
