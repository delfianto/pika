# rpc — JSON-RPC 2.0 Server and Client

The `rpc` module provides the daemon interface for all stateful pika operations. The
CLI, future web frontend, and AI agent all communicate with the daemon through this
layer.

## Submodules

| Submodule | File | Purpose |
|---|---|---|
| `server` | `rpc/server.rs` | Unix socket and stdio JSON-RPC server |
| `client` | `rpc/client.rs` | Async client for CLI commands |
| `methods` | `rpc/methods.rs` | Method dispatch and handler implementations |
| `types` | `rpc/types.rs` | JSON-RPC 2.0 wire types and error codes |

---

## Protocol

The wire protocol is **JSON-RPC 2.0** with **newline-delimited framing**. Each request
and response is a single JSON object terminated by `\n`.

```json
{"jsonrpc":"2.0","method":"scan.start","params":{"pid":12345,"value":100},"id":1}
```

```json
{"jsonrpc":"2.0","result":{"session_id":"abc123","candidates":50000},"id":1}
```

This is deliberately simple. It can be debugged with `socat`:

```bash
echo '{"jsonrpc":"2.0","method":"pid.list","params":{},"id":1}' \
  | socat - UNIX-CONNECT:/tmp/pika.sock
```

---

## Transport

### Unix domain socket (default)

The primary transport. Default path: `/tmp/pika.sock`.

Each CLI invocation opens a new connection, sends one request, reads one response,
and disconnects. The server spawns a tokio task per connection, so multiple CLI
invocations can overlap (e.g., running `pika freeze-list` while a scan is in progress).

**Stale socket detection**: On startup, the server checks whether the socket file
already exists. If so, it attempts a probe connection:

- **Connection succeeds**: Another daemon is running. Abort with an error.
- **Connection refused**: Stale file from a crashed daemon. Remove and bind.
- **File disappeared**: Race condition. Proceed normally.

### Stdio

For integration with editors, MCP servers, or remote SSH tunnels. The server reads
from stdin and writes to stdout using the same newline-delimited JSON-RPC format.

```bash
pika serve --stdio
```

---

## Server architecture (`server`)

```
UnixListener::bind("/tmp/pika.sock")
    |
    | accept loop
    v
[Connection 0]  [Connection 1]  [Connection 2]  ...
    |                |                |
    v                v                v
tokio::spawn     tokio::spawn     tokio::spawn
    |                |                |
    v                v                v
handle_connection: read lines, dispatch, write responses
```

Each connection handler:
1. Splits the stream into reader/writer halves
2. Reads newline-delimited lines from the reader
3. Parses each line as a `JsonRpcRequest`
4. Calls `dispatch(state, &request)` to route to the handler
5. Serializes the `JsonRpcResponse` and writes it back with `\n`

---

## Method dispatch (`methods`)

### Light vs heavy handlers

Methods are categorized by their expected execution time:

**Light handlers** (run inline on the tokio worker thread):

| Method | Purpose |
|---|---|
| `pid.list` | List Wine/Proton processes |
| `pid.find` | Find process by name substring |
| `maps.get` | Return classified memory map |
| `memory.read` | Read bytes at address |
| `memory.write` | Write value to address (with safety check) |
| `memory.write_all` | Write value to all candidates in a session |
| `memory.disassemble` | Disassemble instructions at address |
| `scan.list` | List active scan sessions |
| `scan.candidates` | Paginated candidate list for a session |
| `scan.discard` | Free a scan session |
| `freeze.start` | Start freeze loop for one address |
| `freeze.stop` | Stop freeze loop |
| `freeze.list` | List active freezes |
| `freeze.start_all` | Freeze all candidates in a session |
| `watch.start` | Set hardware watchpoint |
| `watch.hits` | Get watchpoint hits |
| `watch.stop` | Remove watchpoint |
| `watch.list` | List active watchpoints |
| `code.nop` | NOP an instruction |
| `code.patch` | Write arbitrary bytes to code |
| `code.restore` | Restore original bytes |
| `code.list` | List active code patches |

**Heavy handlers** (offloaded to `tokio::task::spawn_blocking`):

| Method | Purpose | Why heavy |
|---|---|---|
| `scan.start` | First scan across all Safe regions | Reads GBs of memory, rayon parallel |
| `scan.filter` | Narrow candidates by new value | Re-reads all candidate addresses |
| `scan.aob` | AOB pattern scan | Reads all Safe (+ optionally ReadOnly) regions |
| `pointer.scan` | Find pointer chains via BFS | Multiple scan passes at each BFS level |

The blocking threadpool prevents CPU-bound scan operations from starving the async
executor. Inside the blocking closure, rayon handles parallelism.

### Shared state

All handlers share `RpcState`:

```rust
pub struct RpcState {
    pub mem: Arc<dyn MemoryAccess>,
    pub sessions: SessionRegistry,     // DashMap<String, ScanSession>
    pub freeze: FreezeManager,         // DashMap<u64, FreezeHandle>
    pub patch: PatchManager,           // DashMap<u64, PatchRecord>
    pub watch: WatchManager,           // DashMap<String, WatchHandle>
}
```

`DashMap` provides per-shard locking, so concurrent operations on different sessions,
freeze addresses, or watchpoints never contend.

### Bulk operation safety limits

`memory.write_all` and `freeze.start_all` refuse to operate on more than 16 candidates
by default. This prevents accidentally writing to thousands of addresses when the scan
hasn't been narrowed enough. The `--force` flag overrides this limit.

---

## Client (`client`)

`RpcClient` is a thin async wrapper used by CLI subcommands:

```rust
let client = RpcClient::new("/tmp/pika.sock");
let result = client.call("scan.start", json!({"pid": 12345, "value": 100})).await?;
```

Each call:
1. Connects to the Unix socket
2. Serializes and sends the JSON-RPC request with `\n`
3. Reads one line from the response
4. Parses the `JsonRpcResponse`
5. Returns `result` on success, or an error with the RPC error message

Connection errors produce clear messages:

```
cannot connect to pika daemon at /tmp/pika.sock.
Start it with: pika serve &
```

---

## Wire types (`types`)

### Request

```rust
pub struct JsonRpcRequest {
    pub jsonrpc: String,              // Must be "2.0"
    pub method: String,               // e.g., "scan.start"
    pub params: serde_json::Value,    // Method parameters (default: null)
    pub id: Option<serde_json::Value>, // null for notifications
}
```

### Response

```rust
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<serde_json::Value>,  // Present on success
    pub error: Option<JsonRpcError>,        // Present on failure
    pub id: Option<serde_json::Value>,
}
```

### Error codes

| Code | Constant | Meaning |
|---|---|---|
| -32700 | `PARSE_ERROR` | Invalid JSON |
| -32600 | `INVALID_REQUEST` | Not a valid JSON-RPC 2.0 request |
| -32601 | `METHOD_NOT_FOUND` | Unknown method name |
| -32602 | `INVALID_PARAMS` | Missing or invalid parameters |
| -32603 | `INTERNAL_ERROR` | Handler error (scan failure, write rejected, etc.) |
