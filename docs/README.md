# Pika Technical Documentation

Pika is a non-stopping memory scanner and value patcher for Wine/Proton games on
Linux. It exists because every existing Linux memory editor (scanmem, PINCE,
GameConqueror, CESERVER) relies on `ptrace(PTRACE_ATTACH)`, which sends `SIGSTOP`
to the target process. For Wine/Proton games this freezes DXVK/VKD3D mid-GPU-submission,
deadlocking the wineserver and hanging the GPU driver. Even a 10ms stop has a ~60%
chance of hitting an active `vkQueueSubmit` window on a 60fps game. The result is
`VK_ERROR_DEVICE_LOST`, a frozen Wine prefix, and on NVIDIA sometimes a full system
reboot.

Pika makes GPU deadlocks **structurally impossible** by:

1. Using `process_vm_readv` / `process_vm_writev` (Linux 3.2+) for all memory
   access. These syscalls read/write another process's memory **without sending any
   signal or stopping any thread**.
2. Classifying every memory region before access. A priority-ordered rule set
   identifies GPU driver mappings, wineserver shared memory, DXVK translation layer
   regions, and Wine system DLLs. Only regions classified as `Safe` can be written.
3. Re-checking classification before every write. DXVK can remap regions between a
   scan and a subsequent write, so stale safety data is never trusted.

## Goals

- Scan and patch game values in single-player Wine/Proton games without crashing
  the GPU, the game, or the Wine prefix.
- Support all common value types (`i32`, `u32`, `f32`, `i64`, `u64`, `f64`) with
  simultaneous multi-type scanning so the user doesn't need to guess encodings.
- Achieve high throughput (hundreds of MB/s) on large Wine heaps via SIMD-accelerated
  scanning and rayon parallelism.
- Provide a daemon architecture (JSON-RPC over Unix socket) so the scanner can be
  driven by a CLI, a web frontend, or an AI agent.

## Architecture

```
CLI (pika scan, pika freeze, ...)
     |
     | JSON-RPC 2.0 over Unix socket
     v
Daemon (pika serve)
  |-- rpc/server    Accept connections, dispatch requests
  |-- rpc/methods   Route to handlers, offload heavy work to blocking pool
  |-- scan/engine   SIMD-parallel value scanning across Safe regions
  |-- scan/filter   Multi-pass candidate narrowing
  |-- mem/write     Pre-flight safety check + process_vm_writev
  |-- mem/freeze    Dedicated std::threads writing at configurable intervals
  |-- mem/patch     Code patching via /proc/pid/mem
  |-- mem/watch     Hardware watchpoints via debug registers
  |-- process/maps  /proc/[pid]/maps parsing + region classification
  |-- process/pid   Wine/Proton process discovery
```

## Module Documentation

| Document | Module | Description |
|---|---|---|
| [MEM.md](MEM.md) | `mem` | Memory access abstraction, safe writing, freeze loops, code patching, hardware watchpoints, disassembly |
| [PROCESS.md](PROCESS.md) | `process` | Wine/Proton process discovery, `/proc/[pid]/maps` parsing, region safety classification, platform checks |
| [SCAN.md](SCAN.md) | `scan` | SIMD scan engine, candidate model, multi-pass filtering, AOB pattern scanning, pointer chain resolution |
| [RPC.md](RPC.md) | `rpc` | JSON-RPC 2.0 server/client, method dispatch, session management |
| [TUI.md](TUI.md) | `tui` | Terminal user interface (planned architecture) |

## Reference

| Document | Description |
|---|---|
| [ANALYSIS.md](ANALYSIS.md) | Deep technical research: kernel primitives, GPU safety, Wine internals, scan algorithms. The foundational research that informed pika's design. |
