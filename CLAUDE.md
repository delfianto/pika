# CLAUDE.md — Proton Memory Scout

> Agentic memory scanner and value patcher for Wine/Proton games on Linux.
> Claude acts as the reasoning layer; a Rust binary does the fast, dangerous memory work;
> FastAPI bridges them; Vue 3 + Nuxt UI is the frontend.

---

## Project Overview

Traditional memory editors (scanmem, PINCE, GameConqueror) are unreliable against
Wine/Proton games because they use `ptrace PTRACE_ATTACH` which sends SIGSTOP to the
entire process tree — freezing DXVK/VKD3D mid-GPU-submission and deadlocking the
wineserver. This project avoids all of that by using `process_vm_readv` /
`process_vm_writev` (Linux 3.2+) which read and write another process's memory without
stopping it at all, combined with smart `/proc/[pid]/maps` region classification to
never touch GPU driver mappings or Wine internal shared memory.

Claude (via the Anthropic API) acts as the agentic brain: it receives tool results from
the Rust scanner, reasons about data types, infers struct layouts from hex dumps, walks
pointer chains, and decides what to patch. The human just describes what they want
("I have 847 gold, I spent 50 and now have 797 — find it and freeze it at 999999").

---

## Repository Structure

```
proton-memory-scout/
├── CLAUDE.md                    ← you are here
├── README.md
├── .env.example
│
├── scanner/                     ← Rust binary (the fast, dangerous part)
│   ├── Cargo.toml
│   ├── Cargo.lock
│   └── src/
│       ├── main.rs              ← JSON-RPC entry point over stdio/Unix socket
│       ├── pid.rs               ← Proton process discovery
│       ├── maps.rs              ← /proc/pid/maps parser + region classifier
│       ├── scan.rs              ← process_vm_readv SIMD scan engine
│       ├── filter.rs            ← candidate narrowing between scan passes
│       ├── write.rs             ← process_vm_writev + pre-flight region check
│       ├── freeze.rs            ← background thread value freeze loop
│       └── pointer.rs           ← pointer chain walker
│
├── backend/                     ← Python FastAPI (orchestration + LLM layer)
│   ├── pyproject.toml
│   ├── requirements.txt
│   └── app/
│       ├── main.py              ← FastAPI app, lifespan, CORS
│       ├── agent.py             ← Anthropic tool-use agent loop
│       ├── tools.py             ← tool definitions passed to Claude API
│       ├── scanner_client.py    ← async client for Rust binary IPC
│       ├── ws.py                ← WebSocket handlers (agent stream, live values)
│       └── models.py            ← Pydantic models for all API shapes
│
└── frontend/                    ← Vue 3 + Nuxt UI
    ├── nuxt.config.ts
    ├── package.json
    ├── app.vue
    └── components/
        ├── AgentChat.vue        ← streaming LLM conversation panel
        ├── AddressTable.vue     ← live-updating found addresses + freeze toggles
        ├── HexViewer.vue        ← memory region hex dump with highlights
        ├── ScanControls.vue     ← value input, data type selector, scan/filter btns
        ├── ProcessPicker.vue    ← Proton process selector
        └── PointerMap.vue       ← @vue-flow/core pointer chain visualizer
```

---

## Architecture

```
Browser (Vue 3 + Nuxt UI)  :3000
         │
         │  HTTP REST + WebSocket
         ▼
FastAPI (Python)  :8000
  ├── agent.py          Anthropic streaming API + tool dispatch
  ├── ws.py             WebSocket: token stream + live value polling
  └── scanner_client.py async JSON-RPC over Unix socket
         │
         │  JSON-RPC  /tmp/memscout.sock
         ▼
scanner (Rust binary)
  ├── pid discovery      /proc walk, no ptrace
  ├── maps parser        region classification before any access
  ├── scan engine        process_vm_readv + rayon parallel + SIMD
  ├── filter engine      candidate narrowing across scan passes
  ├── write engine       process_vm_writev + pre-flight safety check
  └── freeze loop        background thread, configurable interval
```

All communication between FastAPI and the Rust binary is **JSON-RPC 2.0 over a Unix
domain socket** (`/tmp/memscout.sock`). This keeps the protocol simple, debuggable with
`socat`, and avoids the overhead of HTTP for high-frequency scan results.

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Memory engine | Rust (stable) | `process_vm_readv`, SIMD, rayon, zero-copy |
| ptrace wrapper | `nix` crate | Safe ptrace bindings when needed for attach/detach |
| Disassembly | `capstone-rs` | x86_64 disassembly for struct/code analysis |
| IPC protocol | JSON-RPC 2.0 over Unix socket | Simple, debuggable, language-agnostic |
| Backend framework | FastAPI + asyncio | Async-native, WebSocket support, OpenAPI docs free |
| LLM integration | `anthropic` Python SDK | Streaming tool use, SSE passthrough |
| WebSockets | FastAPI `websockets` | Scan progress, token stream, live value updates |
| Frontend framework | Vue 3 + Nuxt UI | Reactive tables, composables, Nuxt UI component set |
| State management | Pinia | Scan results, address table, agent history |
| Realtime (frontend) | `useWebSocket` (VueUse) | Auto-reconnect, typed messages |
| Graph viz | `@vue-flow/core` | Pointer chain visualizer |
| Virtual lists | `vue-virtual-scroller` | Handle 10k+ address candidates without jank |
| Model | `claude-sonnet-4-20250514` | Best reasoning-to-cost ratio for agentic loops |

---

## Claude Agent — Role and Responsibilities

Claude is the **reasoning layer**. It does not scan memory directly. It calls tools,
interprets results, and decides the next action.

### What Claude is good at in this project

- Looking at a hex dump of a candidate region and inferring struct layout
  (e.g. `0x00000064 0x00000000 0x3f800000 0x00000032` → int32, padding, float 1.0, int32)
- Deciding whether multiple candidates that changed together belong to the same struct
- Reasoning about data types when the user doesn't know if it's int32, float, or int64
- Walking pointer chains: deciding which stable-address candidates are worth following
- Explaining what it found to the user in plain language
- Handling ambiguous instructions ("find my health" when the user hasn't given a value)

### What Claude must NOT do

- Write memory directly — always goes through the Rust binary's write tool
- Skip the pre-flight region safety check — always enforced by the Rust binary
- Touch regions classified as `NeverTouch` — GPU driver mappings, wineserver shm
- Assume a value is int32 without trying other types if int32 yields no candidates

### System prompt location

`backend/app/agent.py` — `SYSTEM_PROMPT` constant at the top of the file.
Keep it updated when new tools are added. The system prompt should always include:
- Current Proton/Wine memory layout caveats
- Instruction to prefer `process_vm_readv` over any ptrace-based approach
- Region safety classification summary
- Reminder that DXVK/VKD3D regions must be skipped even if `rw-p`

---

## Rust Scanner — Key Design Rules

### Memory access primitives — NEVER use ptrace for reads/writes

```rust
// CORRECT — non-stopping, safe for Proton
process_vm_readv(pid, &local_iov, &remote_iov)?;
process_vm_writev(pid, &local_iov, &remote_iov)?;

// WRONG — sends SIGSTOP, kills DXVK, causes GPU deadlocks
ptrace::read(pid, addr)?;
ptrace::write(pid, addr, val)?;
```

`ptrace` is only acceptable for **attach/detach** when you explicitly need to pause a
thread for disassembly. Even then, detach immediately. Never leave a process ptrace-
stopped.

### Region classification — enforce before every scan AND before every write

```rust
pub enum RegionSafety {
    Safe,        // Windows heap, PE data sections — scan and write OK
    ReadOnly,    // PE code sections — scan OK, never write
    Risky,       // DXVK internal heaps — scan with caution, never write
    NeverTouch,  // GPU driver mappings, wineserver shm, /dev/* — skip entirely
}
```

**Rules for `NeverTouch`:**
- Any region backed by `/dev/nvidia*`, `/dev/dri/*`, `/dev/nvidia-uvm`
- Any region backed by `/dev/shm/wine*` or containing `wineserver` in path
- Any anonymous region named `vulkan`, `dxvk-submit*`, `mesa*`
- Any `rw-s` (shared) mapping — shared mappings with GPU drivers are lethal

**Rules for `Risky`:**
- Paths containing `dxvk`, `vkd3d`, `d3d9`, `d3d11`, `d3d12`
- Do not write to these under any circumstances
- Scanning is allowed but flag results as low-confidence

**Rules for `Safe`:**
- Anonymous `rw-p` regions with no file backing — Windows heap, almost certainly game data
- PE sections from the game `.exe` or game `.dll` that are `rw-p`
- Size > 4KB (skip tiny bookkeeping regions)

**Pre-flight re-classify before write:** DXVK can remap regions between your scan and
your write. Always re-read `/proc/[pid]/maps` and re-classify the target address
immediately before writing. If classification has changed to anything other than `Safe`,
abort the write and return an error to FastAPI.

### Scan engine performance notes

- Use `rayon` to parallelize across memory regions — each region scans independently
- Read regions in 4MB chunks to avoid huge single `process_vm_readv` calls
- For value search: use `memchr`-style SIMD where possible (`memchr` crate or manual
  AVX2 via `std::arch`)
- Always search for multiple data types simultaneously on first scan:
  `i32`, `u32`, `f32`, `i64`, `u64`, `f64` — return all candidates with their type
- Track scan sessions by UUID so filter calls know which previous results to narrow

### Freeze loop

- Runs in a `std::thread` (not tokio), writing every 100ms by default
- Configurable interval per address
- Must itself re-check region safety on each write iteration
- Expose start/stop/list via JSON-RPC

### JSON-RPC methods exposed by the Rust binary

```
pid.list            → list all Proton/Wine processes with name + pid
pid.find            → find game process by exe name substring
maps.get            → return classified map regions for a pid
scan.start          → begin new scan, return session_id + initial candidates
scan.filter         → narrow candidates by new value, return updated list
scan.discard        → free a scan session
memory.read         → read N bytes at address, return as hex + typed interpretations
memory.write        → write bytes to address (pre-flight safety check included)
memory.disassemble  → disassemble N bytes at address via capstone
freeze.start        → begin freeze loop for an address
freeze.stop         → stop freeze loop for an address
freeze.list         → list all active freezes
```

All methods return `{ "ok": true, "result": ... }` or `{ "ok": false, "error": "..." }`.
Never panic on bad input — always return a structured error.

---

## FastAPI Backend — Key Design Rules

### Async all the way down

Every route and WebSocket handler must be `async def`. The scanner client uses
`asyncio` streams to communicate with the Rust binary. Never use blocking I/O on the
event loop — if you need to shell out to something slow, use `asyncio.create_subprocess_exec`.

### Scanner process lifecycle

```python
# backend/app/scanner_client.py
class ScannerClient:
    async def ensure_running(self) -> None:
        """Start the Rust binary if not running or if it crashed."""
        if self._proc is None or self._proc.returncode is not None:
            self._proc = await asyncio.create_subprocess_exec(
                str(SCANNER_BIN_PATH),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
            )
            # give it 500ms to bind the socket
            await asyncio.sleep(0.5)
```

Call `ensure_running()` at the start of every route that needs the scanner. If the
Rust binary crashes mid-scan (it will, eventually), the next call recovers cleanly
rather than leaving the WebSocket in a zombie state.

### WebSocket message types

All WebSocket messages are JSON with a `type` discriminator:

```typescript
// Frontend-facing WS message shapes
{ type: "agent_token",    data: { text: string } }
{ type: "agent_tool_use", data: { tool: string, input: object } }
{ type: "agent_result",   data: { tool: string, output: object } }
{ type: "agent_done",     data: { stop_reason: string } }
{ type: "scan_progress",  data: { scanned_bytes: number, total_bytes: number, candidates: number } }
{ type: "live_value",     data: { address: string, value: number, type: string } }
{ type: "freeze_update",  data: { address: string, active: boolean } }
{ type: "error",          data: { message: string, recoverable: boolean } }
```

### Agent tool definitions

Defined in `backend/app/tools.py` as a list of Anthropic tool dicts. Each tool maps
1:1 to a JSON-RPC method on the Rust binary, with the FastAPI layer handling the IPC.
Claude never calls the Rust binary directly — it calls FastAPI tools, FastAPI calls
the scanner.

Tools available to Claude:

```python
TOOLS = [
    {
        "name": "list_processes",
        "description": "List all Wine/Proton game processes currently running. "
                       "Returns pid, name, and exe path. Call this first.",
        "input_schema": { "type": "object", "properties": {}, "required": [] }
    },
    {
        "name": "find_process",
        "description": "Find a Proton game process by executable name substring.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Substring of the .exe name" }
            },
            "required": ["name"]
        }
    },
    {
        "name": "get_memory_map",
        "description": "Get classified memory regions for a process. "
                       "Returns regions with safety classification. "
                       "Review before scanning to understand memory layout.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pid": { "type": "integer" }
            },
            "required": ["pid"]
        }
    },
    {
        "name": "start_scan",
        "description": "Scan process memory for a specific value. "
                       "Searches Safe regions only by default. "
                       "Tries all numeric types unless dtype specified. "
                       "Returns session_id and candidate count.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pid":     { "type": "integer" },
                "value":   { "type": "number", "description": "The value to find" },
                "dtype":   {
                    "type": "string",
                    "enum": ["i32", "u32", "f32", "i64", "u64", "f64", "auto"],
                    "description": "Data type. Use auto to try all types.",
                    "default": "auto"
                },
                "session_id": {
                    "type": "string",
                    "description": "Reuse existing session to filter candidates further"
                }
            },
            "required": ["pid", "value"]
        }
    },
    {
        "name": "filter_scan",
        "description": "Narrow candidates from a previous scan to addresses "
                       "that now hold a new value. User must change the value "
                       "in-game between start_scan and filter_scan calls.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": { "type": "string" },
                "new_value":  { "type": "number" }
            },
            "required": ["session_id", "new_value"]
        }
    },
    {
        "name": "read_memory",
        "description": "Read bytes at an address. Returns raw hex, "
                       "and interpretations as all numeric types. "
                       "Also reads surrounding 64 bytes for struct inference.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pid":    { "type": "integer" },
                "address": { "type": "string", "description": "Hex address e.g. 0x7f2012340000" },
                "length": { "type": "integer", "default": 128 }
            },
            "required": ["pid", "address"]
        }
    },
    {
        "name": "write_memory",
        "description": "Write a value to an address. "
                       "SAFETY: Pre-flight region check is always performed. "
                       "Write will be rejected if region is not Safe.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pid":     { "type": "integer" },
                "address": { "type": "string" },
                "value":   { "type": "number" },
                "dtype":   { "type": "string", "enum": ["i32", "u32", "f32", "i64", "u64", "f64"] }
            },
            "required": ["pid", "address", "value", "dtype"]
        }
    },
    {
        "name": "freeze_value",
        "description": "Start a freeze loop that repeatedly writes a value "
                       "to an address every 100ms, keeping it locked.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pid":      { "type": "integer" },
                "address":  { "type": "string" },
                "value":    { "type": "number" },
                "dtype":    { "type": "string", "enum": ["i32", "u32", "f32", "i64", "u64", "f64"] },
                "interval_ms": { "type": "integer", "default": 100 }
            },
            "required": ["pid", "address", "value", "dtype"]
        }
    },
    {
        "name": "unfreeze_value",
        "description": "Stop a freeze loop for an address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": { "type": "string" }
            },
            "required": ["address"]
        }
    },
    {
        "name": "disassemble",
        "description": "Disassemble machine code at an address. "
                       "Useful for understanding what code reads/writes a value.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pid":        { "type": "integer" },
                "address":    { "type": "string" },
                "num_instructions": { "type": "integer", "default": 20 }
            },
            "required": ["pid", "address"]
        }
    }
]
```

---

## Frontend — Key Design Rules

### WebSocket composable

All realtime communication goes through a single `useAgentSocket` composable in
`frontend/composables/useAgentSocket.ts`. It wraps `useWebSocket` from VueUse and
exposes typed reactive state:

```typescript
const {
  messages,        // Ref<AgentMessage[]>  — full conversation history
  candidates,      // Ref<Candidate[]>     — current scan candidates
  liveValues,      // Ref<Map<string, LiveValue>>  — polling map
  freezeStates,    // Ref<Map<string, boolean>>
  scanProgress,    // Ref<ScanProgress | null>
  sendPrompt,      // (text: string) => void
  isConnected,     // Ref<boolean>
} = useAgentSocket()
```

### AddressTable

- Use `vue-virtual-scroller` — scans can yield thousands of candidates
- Each row: address (hex), current live value (updates via `live_value` WS messages),
  data type badge, freeze toggle, "watch" button to open in HexViewer
- Freeze toggle calls `freeze_value` / `unfreeze_value` via REST, not directly via WS
- Live value polling: backend polls all watched addresses every 500ms and pushes
  `live_value` messages over the WebSocket

### AgentChat

- Stream tokens as they arrive — no waiting for full response
- Tool use blocks render as collapsible cards:
  - Tool name + input (collapsed by default)
  - Tool result (collapsed, "show result" expander)
- Claude's text responses render as markdown (use `@nuxtjs/mdc` or `marked`)
- The input box sends via `sendPrompt()` on Enter
- Show a spinner while `stop_reason` hasn't arrived yet

### HexViewer

- 16 bytes per row, address gutter on left, ASCII panel on right
- Highlight matched candidate bytes in accent color
- Clicking a byte group (4 bytes / 8 bytes) shows its typed interpretation in a tooltip
- Use a fixed-width font (`font-mono`)

---

## Proton / Wine Specific Notes

### Finding the right PID

Proton spawns multiple processes. The one you want:
- Has the game's `.exe` filename in its cmdline
- Is NOT `wineserver`, `wine-preloader` (the bootstrap stub), or `services.exe`
- Usually appears as `wine64-preloader` or just the `.exe` name in `ps aux`
- Its `/proc/[pid]/maps` will show a large PE executable mapped near `0x140000000`
  (64-bit Windows base) or `0x400000` (32-bit)

When in doubt: find the process whose `maps` file contains the largest anonymous `rw-p`
regions — that's the Windows heap where game values live.

### Address stability across sessions

Windows heap addresses in Wine/Proton are **not stable across game restarts**. ASLR
applies. This means:
- Scan results from one session are useless in the next
- For permanent cheats you need pointer chains back to a stable base (module base
  address from `/proc/[pid]/maps` is stable within a session)
- The `pointer.rs` module handles this: given a value address, walk backwards through
  memory looking for pointers that land near it, building chains to stable module bases

### DXVK shader cache regions

Some games map large `rw-p` anonymous regions for DXVK's shader pipeline cache. These
are safe to scan (no GPU synchronization) but write attempts should still be avoided.
Heuristic: anonymous `rw-p` regions larger than 256MB are likely shader cache, not game
heap. Skip them in the default scan profile, allow with `--include-large-anon` flag.

### Common value encodings in Wine games

| What you think it is | What it often actually is |
|---|---|
| Integer health (100) | `int32` — most common |
| Float stat (1.0 stamina multiplier) | `float32` |
| Money / score (large numbers) | `int64` or `uint64` |
| Boolean flags | `int32` (0 or 1), sometimes `uint8` |
| Timer / cooldown | `float32` in seconds |

Always try `auto` dtype on first scan. Let Claude reason about which candidates make
sense given the context.

---

## Development Workflow

### Prerequisites (gaming rig / dev machine)

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Python 3.11+
sudo apt install python3.11 python3.11-venv
# Node 20+ (for frontend)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt install nodejs
```

### Build and run (dev mode)

```bash
# 1. Build Rust scanner
cd scanner && cargo build --release
# Binary at: scanner/target/release/memscout

# 2. Start FastAPI backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
ANTHROPIC_API_KEY=sk-ant-... uvicorn app.main:app --reload --port 8000

# 3. Start Vue frontend
cd frontend
npm install
npm run dev   # http://localhost:3000
```

### Environment variables

Copy `.env.example` to `.env` in `backend/`:

```env
ANTHROPIC_API_KEY=sk-ant-...
SCANNER_BIN_PATH=../scanner/target/release/memscout
SCANNER_SOCKET_PATH=/tmp/memscout.sock
MODEL=claude-sonnet-4-20250514
MAX_TOKENS=8096
CORS_ORIGINS=http://localhost:3000
```

### Running from a notebook via Claude Code SSH

If coding from a remote machine (sofa workflow):
1. Install Claude Code on the gaming rig: `npm install -g @anthropic-ai/claude-code`
2. Open Claude Code Desktop on notebook → New SSH Session → gaming rig IP
3. Claude runs natively on the rig with full `/proc` access
4. Alternatively: `claude mcp add` with an SSH MCP server pointing at the rig

### Testing without a game running

The `scanner/` crate has a `--mock` flag that spins up a mock target process with known
values at known addresses. Use this for unit testing the scan/filter/write pipeline
without needing a live Proton game:

```bash
./memscout --mock &
# Now connect the backend to it — mock PID printed on startup
```

---

## Safety and Constraints

### What this tool will do

- Read and write the memory of processes you own (same UID)
- Modify game values for single-player entertainment purposes
- Run entirely locally — no data leaves your machine except Anthropic API calls
  (which contain hex dumps and game value descriptions, not personal data)

### What this tool will NOT do

- Attach to processes owned by other users
- Touch GPU driver memory mappings (enforced in `maps.rs`, not bypassable via API)
- Write to any region not classified as `Safe` (pre-flight check in `write.rs`)
- Support online multiplayer games — use in online games violates ToS and is not
  the intended purpose. The tool is for single-player exploration.

### Capabilities required

The backend process needs:
- `CAP_SYS_PTRACE` OR same UID as the target process
- In practice: run the backend as the same user running the game. No sudo needed.

### If something goes wrong

- Game crash: the Rust binary cannot cause this via `process_vm_readv/writev` alone —
  if a crash occurs, you likely wrote to a `Risky` region that slipped through
  classification. File a bug with the address and the maps output.
- GPU deadlock: should be impossible with this architecture since we never SIGSTOP.
  If it happens anyway, check if a rogue `ptrace::attach` call crept into the code.
- Wineserver hang: same as above. The wineserver deadlock vector is exclusively via
  SIGSTOP. If the wineserver hangs, something issued ptrace somewhere.

---

## Coding Conventions

### Rust

- `clippy` clean at all times: `cargo clippy -- -D warnings`
- All public functions documented with `///`
- Errors use `anyhow::Result` for application code, `thiserror` for library-facing types
- No `unwrap()` in production paths — use `?` or explicit error handling
- `unsafe` blocks require a comment explaining why it is safe

### Python

- `ruff` for linting and formatting: `ruff check . && ruff format .`
- Type annotations everywhere — `mypy --strict` clean
- All async functions annotated with return types
- Pydantic models for all request/response shapes — no raw dicts in route handlers

### Vue / TypeScript

- `vue-tsc` clean — no `any` types
- Composables in `composables/`, one concern per file
- Components receive typed props, no prop drilling beyond 2 levels (use Pinia)
- All WebSocket message types defined in `types/ws.ts` and shared

---

## Future Work / Stretch Goals

- **Pointer chain persistence**: save pointer chains to a JSON file so values survive
  game restarts without re-scanning
- **AOB (array of bytes) scanning**: scan for a pattern of bytes rather than a typed
  value — useful for finding code patches
- **WINE module symbol resolution**: parse PE export tables to find named functions
- **Script recording**: record a sequence of scan→filter→write steps and replay them
  automatically on the next session
- **Mobile UI**: since it's a browser app, it already works on phone via LAN
- **Multi-game profiles**: save address table + pointer chains per game title

---

*Last updated: project initialization*
*Model: claude-sonnet-4-20250514*
*Stack: Rust + Python/FastAPI + Vue 3 + Nuxt UI*
