//! JSON-RPC method handlers for all pika daemon operations.
//!
//! Each JSON-RPC method (`pid.list`, `scan.start`, `memory.write`, etc.) maps to
//! a handler function in this module. The [`dispatch`] function routes incoming
//! requests by method name, offloading CPU-bound operations (scan, filter, AOB,
//! pointer scan) to the tokio blocking threadpool.
//!
//! All handlers share state through [`RpcState`], which holds the memory access
//! implementation, scan session registry, freeze manager, patch manager, and
//! watch manager.

use std::fmt::Write as _;

use crate::scan::candidate::{CandidateJson, ValueType};
use crate::scan::filter::filter_candidates;
use crate::mem::freeze::{FreezeEntry, FreezeManager};
use crate::mem::patch::{self, PatchManager};
use crate::mem::watch::{WatchConfig, WatchManager, WatchMode, WatchSize};
use crate::mem::access::MemoryAccess;
use crate::process::pid;
use crate::rpc::types::*;
use crate::scan::engine::{SessionRegistry, first_scan};
use crate::mem::write::write_value;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Shared state for RPC method handlers.
pub struct RpcState {
    pub mem: Arc<dyn MemoryAccess>,
    pub sessions: SessionRegistry,
    pub freeze: FreezeManager,
    pub patch: PatchManager,
    pub watch: WatchManager,
}

impl RpcState {
    /// Create a new RPC state with all subsystem managers initialized.
    pub fn new(mem: Arc<dyn MemoryAccess>) -> Self {
        Self {
            sessions: SessionRegistry::new(),
            freeze: FreezeManager::new(mem.clone()),
            patch: PatchManager::new(mem.clone()),
            watch: WatchManager::new(mem.clone()),
            mem,
        }
    }
}

/// Dispatch a JSON-RPC request to the appropriate handler.
///
/// Heavy CPU-bound handlers (scan, filter, AOB, pointer scan) are offloaded to
/// `tokio::task::spawn_blocking` so they don't starve the async executor.
pub async fn dispatch(state: Arc<RpcState>, req: &JsonRpcRequest) -> JsonRpcResponse {
    if let Err(e) = req.validate() {
        return JsonRpcResponse::err(req.id.clone(), INVALID_REQUEST, e);
    }

    // Heavy handlers: offload to the blocking threadpool to avoid starving
    // Tokio worker threads while Rayon parallelises across memory regions.
    match req.method.as_str() {
        "scan.start" | "scan.filter" | "scan.aob" | "pointer.scan" => {
            let state = state.clone();
            let params = req.params.clone();
            let id = req.id.clone();
            let method = req.method.clone();
            return match tokio::task::spawn_blocking(move || {
                dispatch_heavy(&state, &method, &params)
            })
            .await
            {
                Ok(Ok(value)) => JsonRpcResponse::ok(id, value),
                Ok(Err(resp)) => resp,
                Err(e) => {
                    JsonRpcResponse::err(id, INTERNAL_ERROR, format!("task panicked: {e}"))
                }
            };
        }
        _ => {}
    }

    // Light handlers: run inline on the async task (microsecond operations).
    let result = match req.method.as_str() {
        "pid.list" => handle_pid_list(),
        "pid.find" => handle_pid_find(&req.params),
        "maps.get" => handle_maps_get(&state, &req.params),
        "scan.discard" => handle_scan_discard(&state, &req.params),
        "scan.list" => handle_scan_list(&state),
        "scan.candidates" => handle_scan_candidates(&state, &req.params),
        "memory.read" => handle_memory_read(&state, &req.params),
        "memory.write" => handle_memory_write(&state, &req.params),
        "memory.write_all" => handle_memory_write_all(&state, &req.params),
        "freeze.start_all" => handle_freeze_start_all(&state, &req.params),
        "memory.disassemble" => handle_memory_disassemble(&state, &req.params),
        "freeze.start" => handle_freeze_start(&state, &req.params),
        "freeze.stop" => handle_freeze_stop(&state, &req.params),
        "freeze.list" => handle_freeze_list(&state),
        "watch.start" => handle_watch_start(&state, &req.params),
        "watch.hits" => handle_watch_hits(&state, &req.params),
        "watch.stop" => handle_watch_stop(&state, &req.params),
        "watch.list" => handle_watch_list(&state),
        "code.nop" => handle_code_nop(&state, &req.params),
        "code.patch" => handle_code_patch(&state, &req.params),
        "code.restore" => handle_code_restore(&state, &req.params),
        "code.list" => handle_code_list(&state),
        _ => Err(JsonRpcResponse::err(
            req.id.clone(),
            METHOD_NOT_FOUND,
            format!("unknown method: {}", req.method),
        )),
    };

    match result {
        Ok(value) => JsonRpcResponse::ok(req.id.clone(), value),
        Err(resp) => resp,
    }
}

/// Dispatch heavy (CPU-bound) RPC methods. Runs on the blocking threadpool.
fn dispatch_heavy(
    state: &RpcState,
    method: &str,
    params: &serde_json::Value,
) -> MethodResult {
    match method {
        "scan.start" => handle_scan_start(state, params),
        "scan.filter" => handle_scan_filter(state, params),
        "scan.aob" => handle_scan_aob(state, params),
        "pointer.scan" => handle_pointer_scan(state, params),
        _ => unreachable!("dispatch_heavy called with non-heavy method: {method}"),
    }
}

type MethodResult = Result<serde_json::Value, JsonRpcResponse>;

fn handle_pid_list() -> MethodResult {
    let processes = pid::list_wine_processes().map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;
    Ok(json!(processes))
}

fn handle_maps_get(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params
        .get("pid")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid' parameter"))?;

    let regions = state.mem.read_maps(pid).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;

    // Serialize with human-friendly fields
    let result: Vec<serde_json::Value> = regions
        .iter()
        .map(|r| {
            json!({
                "start": r.start,
                "end": r.end,
                "size": r.size(),
                "permissions": r.permissions.as_str(),
                "safety": format!("{:?}", r.safety),
                "pathname": r.pathname,
            })
        })
        .collect();

    Ok(json!(result))
}

fn handle_pid_find(params: &serde_json::Value) -> MethodResult {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'name' parameter"))?;

    let processes = pid::find_process(name).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;
    Ok(json!(processes))
}

fn handle_scan_start(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params
        .get("pid")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid' parameter"))?;

    let value = params
        .get("value")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'value' parameter"))?;

    let dtype: ValueType = params
        .get("dtype")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or(ValueType::Auto);

    let session = first_scan(state.mem.as_ref(), pid, value, dtype).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;

    let response = json!({
        "session_id": session.id,
        "candidates": session.candidates.len(),
    });

    state.sessions.insert(session);
    Ok(response)
}

fn handle_scan_filter(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let session_id = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'session_id'"))?;

    let new_value = params
        .get("new_value")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let mode_str = params
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("exact");
    let mode = crate::scan::filter::FilterMode::from_str_loose(mode_str).map_err(|e| {
        JsonRpcResponse::err(None, INVALID_PARAMS, e.to_string())
    })?;

    let result = state.sessions.with_session(session_id, |session| {
        let retained =
            filter_candidates(state.mem.as_ref(), session.pid, &mut session.candidates, new_value, session.dtype, mode)
                .map_err(|e| JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string()))?;

        let top_candidates: Vec<CandidateJson> =
            session.candidates.iter().take(100).map(|c| c.into()).collect();

        Ok(json!({
            "session_id": session.id,
            "candidates": retained,
            "top": top_candidates,
        }))
    });

    match result {
        Some(inner) => inner,
        None => Err(JsonRpcResponse::err(
            None,
            INVALID_PARAMS,
            format!("session '{session_id}' not found"),
        )),
    }
}

fn handle_scan_aob(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;

    let pattern_str = params.get("pattern").and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pattern'"))?;

    let include_readonly = params.get("include_readonly").and_then(|v| v.as_bool()).unwrap_or(false);

    let pattern = crate::scan::engine::parse_aob_pattern(pattern_str)
        .map_err(|e| JsonRpcResponse::err(None, INVALID_PARAMS, e.to_string()))?;

    let addresses = crate::scan::engine::aob_scan(state.mem.as_ref(), pid, &pattern, include_readonly)
        .map_err(|e| JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string()))?;

    let addr_strings: Vec<String> = addresses.iter().map(|a| format!("{a:#x}")).collect();

    Ok(json!({
        "count": addresses.len(),
        "addresses": addr_strings,
    }))
}

fn handle_scan_list(state: &RpcState) -> MethodResult {
    Ok(json!(state.sessions.list()))
}

fn handle_scan_candidates(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let session_id = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'session_id'"))?;

    let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let limit = limit.min(1000); // Cap per-request

    let result = state.sessions.with_session(session_id, |session| {
        let total = session.candidates.len();
        let end = total.min(offset + limit);
        let page: Vec<CandidateJson> = session.candidates[offset.min(total)..end]
            .iter()
            .map(|c| c.into())
            .collect();
        json!({
            "session_id": session.id,
            "total": total,
            "offset": offset,
            "count": page.len(),
            "candidates": page,
        })
    });

    match result {
        Some(val) => Ok(val),
        None => Err(JsonRpcResponse::err(
            None,
            INVALID_PARAMS,
            format!("session '{session_id}' not found"),
        )),
    }
}

fn handle_scan_discard(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let session_id = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'session_id'"))?;

    let removed = state.sessions.remove(session_id);
    Ok(json!({ "discarded": removed.is_some() }))
}

fn handle_memory_read(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;

    let address = parse_hex_address(params.get("address"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'address'"))?;

    let length = params.get("length").and_then(|v| v.as_u64()).unwrap_or(128) as usize;
    let length = length.min(4096); // Cap at 4KB per read

    let mut buffer = vec![0u8; length];
    let bytes_read = state.mem.read(pid, address, &mut buffer).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;
    buffer.truncate(bytes_read);

    // Provide hex dump and typed interpretations
    let mut hex_str = String::with_capacity(buffer.len() * 2);
    for b in &buffer {
        let _ = write!(hex_str, "{b:02x}");
    }

    let mut interpretations = serde_json::Map::new();
    if bytes_read >= 4 {
        let i32_val = i32::from_le_bytes(buffer[..4].try_into().unwrap());
        let f32_val = f32::from_le_bytes(buffer[..4].try_into().unwrap());
        interpretations.insert("i32".to_string(), json!(i32_val));
        interpretations.insert("u32".to_string(), json!(i32_val as u32));
        interpretations.insert("f32".to_string(), json!(f32_val));
    }
    if bytes_read >= 8 {
        let i64_val = i64::from_le_bytes(buffer[..8].try_into().unwrap());
        let f64_val = f64::from_le_bytes(buffer[..8].try_into().unwrap());
        interpretations.insert("i64".to_string(), json!(i64_val));
        interpretations.insert("u64".to_string(), json!(i64_val as u64));
        interpretations.insert("f64".to_string(), json!(f64_val));
    }

    Ok(json!({
        "address": format!("{address:#x}"),
        "bytes_read": bytes_read,
        "hex": hex_str,
        "interpretations": interpretations,
    }))
}

fn handle_memory_write(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;

    let address = parse_hex_address(params.get("address"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'address'"))?;

    let value = params.get("value").and_then(|v| v.as_f64())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'value'"))?;

    let dtype: ValueType = params.get("dtype")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'dtype'"))?;

    write_value(state.mem.as_ref(), pid, address, value, dtype).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;

    Ok(json!({ "ok": true }))
}

/// Default safety limit — refuse write-all/freeze-all if more candidates than this.
const BULK_WRITE_LIMIT: usize = 16;

fn handle_memory_write_all(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let session_id = params.get("session_id").and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'session_id'"))?;

    let value = params.get("value").and_then(|v| v.as_f64())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'value'"))?;

    let dtype: ValueType = params.get("dtype")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'dtype'"))?;

    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);

    let result = state.sessions.with_session(session_id, |session| {
        let count = session.candidates.len();
        if count > BULK_WRITE_LIMIT && !force {
            return Err(JsonRpcResponse::err(
                None,
                INVALID_PARAMS,
                format!(
                    "refusing to write to {count} addresses (limit: {BULK_WRITE_LIMIT}). \
                     Narrow your scan or use --force"
                ),
            ));
        }

        let mut written = Vec::new();
        let mut errors = Vec::new();

        for candidate in &session.candidates {
            let addr = candidate.address;
            match write_value(state.mem.as_ref(), session.pid, addr, value, dtype) {
                Ok(()) => written.push(format!("{addr:#x}")),
                Err(e) => errors.push(json!({"address": format!("{addr:#x}"), "error": e.to_string()})),
            }
        }

        Ok(json!({
            "written": written.len(),
            "failed": errors.len(),
            "addresses": written,
            "errors": errors,
        }))
    });

    match result {
        Some(inner) => inner,
        None => Err(JsonRpcResponse::err(
            None,
            INVALID_PARAMS,
            format!("session '{session_id}' not found"),
        )),
    }
}

fn handle_freeze_start_all(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let session_id = params.get("session_id").and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'session_id'"))?;

    let value = params.get("value").and_then(|v| v.as_f64())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'value'"))?;

    let dtype: ValueType = params.get("dtype")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'dtype'"))?;

    let interval_ms = params.get("interval_ms").and_then(|v| v.as_u64()).unwrap_or(100);
    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);

    let addresses: Vec<u64> = {
        let result = state.sessions.with_session(session_id, |session| {
            let count = session.candidates.len();
            if count > BULK_WRITE_LIMIT && !force {
                return Err(JsonRpcResponse::err(
                    None,
                    INVALID_PARAMS,
                    format!(
                        "refusing to freeze {count} addresses (limit: {BULK_WRITE_LIMIT}). \
                         Narrow your scan or use --force"
                    ),
                ));
            }
            Ok((session.pid, session.candidates.iter().map(|c| c.address).collect::<Vec<_>>()))
        });
        match result {
            Some(Ok((_, addrs))) => addrs,
            Some(Err(e)) => return Err(e),
            None => return Err(JsonRpcResponse::err(
                None, INVALID_PARAMS, format!("session '{session_id}' not found"),
            )),
        }
    };

    // Get PID from session
    let pid = state.sessions.with_session(session_id, |s| s.pid)
        .unwrap_or(0);

    let mut frozen = Vec::new();
    let mut errors = Vec::new();

    for addr in &addresses {
        match state.freeze.start(crate::mem::freeze::FreezeEntry {
            pid,
            address: *addr,
            value,
            dtype,
            interval: Duration::from_millis(interval_ms),
        }) {
            Ok(()) => frozen.push(format!("{addr:#x}")),
            Err(e) => errors.push(json!({"address": format!("{addr:#x}"), "error": e.to_string()})),
        }
    }

    Ok(json!({
        "frozen": frozen.len(),
        "failed": errors.len(),
        "addresses": frozen,
        "errors": errors,
    }))
}

fn handle_memory_disassemble(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;

    let address = parse_hex_address(params.get("address"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'address'"))?;

    let num_instructions = params
        .get("num_instructions")
        .and_then(|v| v.as_u64())
        .unwrap_or(20) as usize;

    let instructions =
        crate::mem::disassemble::disassemble_at(state.mem.as_ref(), pid, address, num_instructions)
            .map_err(|e| JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string()))?;

    Ok(json!(instructions))
}

fn handle_pointer_scan(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;

    let target = parse_hex_address(params.get("target"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'target'"))?;

    let max_depth = params.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
    let max_offset = params.get("max_offset").and_then(|v| v.as_i64()).unwrap_or(0x1000);

    let regions = state.mem.read_maps(pid).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;

    let scan_params = crate::scan::pointer::PointerScanParams {
        max_offset,
        max_depth,
        max_results: 100,
    };

    let chains = crate::scan::pointer::find_pointer_chains(
        state.mem.as_ref(), pid, target, &regions, &scan_params,
    )
    .map_err(|e| JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string()))?;

    Ok(json!(chains))
}

fn handle_freeze_start(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;

    let address = parse_hex_address(params.get("address"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'address'"))?;

    let value = params.get("value").and_then(|v| v.as_f64())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'value'"))?;

    let dtype: ValueType = params.get("dtype")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'dtype'"))?;

    let interval_ms = params.get("interval_ms").and_then(|v| v.as_u64()).unwrap_or(100);

    state.freeze.start(FreezeEntry {
        pid,
        address,
        value,
        dtype,
        interval: Duration::from_millis(interval_ms),
    }).map_err(|e| JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string()))?;

    Ok(json!({ "ok": true, "address": format!("{address:#x}") }))
}

fn handle_freeze_stop(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let address = parse_hex_address(params.get("address"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'address'"))?;

    state.freeze.stop(address);
    Ok(json!({ "ok": true }))
}

fn handle_freeze_list(state: &RpcState) -> MethodResult {
    Ok(json!(state.freeze.list()))
}

// ─── Watch handlers ─────────────────────────────────────────────────────────

fn handle_watch_start(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;
    let address = parse_hex_address(params.get("address"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'address'"))?;
    let mode = match params.get("mode").and_then(|v| v.as_str()).unwrap_or("write") {
        "write" => WatchMode::Write,
        "access" | "readwrite" | "read_write" => WatchMode::ReadWrite,
        other => return Err(JsonRpcResponse::err(None, INVALID_PARAMS,
            format!("invalid mode: {other} (expected 'write' or 'access')"))),
    };
    let size = match params.get("size").and_then(|v| v.as_u64()).unwrap_or(4) {
        1 => WatchSize::Byte1,
        2 => WatchSize::Byte2,
        4 => WatchSize::Byte4,
        8 => WatchSize::Byte8,
        n => return Err(JsonRpcResponse::err(None, INVALID_PARAMS,
            format!("invalid size: {n} (expected 1, 2, 4, or 8)"))),
    };
    let detail = params.get("detail").and_then(|v| v.as_bool()).unwrap_or(false);

    let config = WatchConfig { pid, address, mode, size, capture_registers: detail };
    let watch_id = state.watch.start(config).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;

    Ok(json!({ "watch_id": watch_id }))
}

fn handle_watch_hits(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let watch_id = params.get("watch_id").and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'watch_id'"))?;
    let hits = state.watch.hits(watch_id).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;
    Ok(json!(hits))
}

fn handle_watch_stop(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let watch_id = params.get("watch_id").and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'watch_id'"))?;
    state.watch.stop(watch_id).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;
    Ok(json!({ "ok": true }))
}

fn handle_watch_list(state: &RpcState) -> MethodResult {
    Ok(json!(state.watch.list()))
}

// ─── Code patch handlers ────────────────────────────────────────────────────

fn handle_code_nop(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;
    let address = parse_hex_address(params.get("address"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'address'"))?;
    let size = params.get("size").and_then(|v| v.as_u64()).map(|v| v as usize);

    let record = state.patch.nop_at(pid, address, size).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;

    Ok(json!({
        "ok": true,
        "address": format!("{:#x}", record.address),
        "original_bytes": patch::hex_encode(&record.original_bytes),
        "patched_bytes": patch::hex_encode(&record.patched_bytes),
    }))
}

fn handle_code_patch(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;
    let address = parse_hex_address(params.get("address"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'address'"))?;
    let bytes_hex = params.get("bytes").and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'bytes'"))?;
    let bytes = patch::hex_decode(bytes_hex).map_err(|e| {
        JsonRpcResponse::err(None, INVALID_PARAMS, format!("invalid hex bytes: {e}"))
    })?;

    let record = state.patch.patch_at(pid, address, &bytes).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;

    Ok(json!({
        "ok": true,
        "address": format!("{:#x}", record.address),
        "original_bytes": patch::hex_encode(&record.original_bytes),
    }))
}

fn handle_code_restore(state: &RpcState, params: &serde_json::Value) -> MethodResult {
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32)
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'pid'"))?;
    let address = parse_hex_address(params.get("address"))
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing or invalid 'address'"))?;
    state.patch.restore_at(pid, address).map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;
    Ok(json!({ "ok": true }))
}

fn handle_code_list(state: &RpcState) -> MethodResult {
    Ok(json!(state.patch.list()))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Parse a hex address string like "0x7f2012340000" or "7f2012340000".
fn parse_hex_address(value: Option<&serde_json::Value>) -> Option<u64> {
    let s = value?.as_str()?;
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::maps::{MapRegion, Permissions, RegionSafety};
    use crate::mem::access::MockMemoryAccess;

    fn make_state() -> Arc<RpcState> {
        let mock = MockMemoryAccess::new(100);
        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(&42_i32.to_le_bytes());
        mock.add_region(0x14000_0000, data);
        mock.set_maps(vec![MapRegion {
            start: 0x14000_0000,
            end: 0x14000_1000,
            permissions: Permissions { read: true, write: true, execute: false, shared: false },
            offset: 0, device: "00:00".to_string(), inode: 0, pathname: String::new(),
            safety: RegionSafety::Safe,
        }]);
        Arc::new(RpcState::new(Arc::new(mock)))
    }

    #[tokio::test]
    async fn dispatch_pid_list() {
        let state = make_state();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "pid.list".to_string(),
            params: json!({}),
            id: Some(json!(1)),
        };
        let resp = dispatch(state, &req).await;
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn dispatch_unknown_method() {
        let state = make_state();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "nonexistent".to_string(),
            params: json!({}),
            id: Some(json!(1)),
        };
        let resp = dispatch(state, &req).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn dispatch_scan_start_and_filter() {
        let state = make_state();

        // Start scan
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "scan.start".to_string(),
            params: json!({"pid": 100, "value": 42}),
            id: Some(json!(1)),
        };
        let resp = dispatch(state.clone(), &req).await;
        assert!(resp.error.is_none(), "scan.start error: {:?}", resp.error);
        let result = resp.result.unwrap();
        let session_id = result["session_id"].as_str().unwrap().to_string();
        assert!(result["candidates"].as_u64().unwrap() > 0);

        // Filter with same value (should retain candidates)
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "scan.filter".to_string(),
            params: json!({"session_id": session_id, "new_value": 42}),
            id: Some(json!(2)),
        };
        let resp = dispatch(state, &req).await;
        assert!(resp.error.is_none(), "scan.filter error: {:?}", resp.error);
    }

    #[tokio::test]
    async fn dispatch_memory_read() {
        let state = make_state();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "memory.read".to_string(),
            params: json!({"pid": 100, "address": "0x140000000", "length": 16}),
            id: Some(json!(1)),
        };
        let resp = dispatch(state, &req).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["bytes_read"], 16);
        assert!(result["hex"].as_str().is_some());
        assert_eq!(result["interpretations"]["i32"], 42);
    }

    #[tokio::test]
    async fn dispatch_memory_write() {
        let state = make_state();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "memory.write".to_string(),
            params: json!({"pid": 100, "address": "0x140000000", "value": 999, "dtype": "i32"}),
            id: Some(json!(1)),
        };
        let resp = dispatch(state.clone(), &req).await;
        assert!(resp.error.is_none(), "write error: {:?}", resp.error);

        // Verify the write
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "memory.read".to_string(),
            params: json!({"pid": 100, "address": "0x140000000", "length": 4}),
            id: Some(json!(2)),
        };
        let resp = dispatch(state, &req).await;
        let result = resp.result.unwrap();
        assert_eq!(result["interpretations"]["i32"], 999);
    }

    #[test]
    fn parse_hex_addresses() {
        assert_eq!(parse_hex_address(Some(&json!("0x1000"))), Some(0x1000));
        assert_eq!(parse_hex_address(Some(&json!("1000"))), Some(0x1000));
        assert_eq!(parse_hex_address(Some(&json!("0X140000000"))), Some(0x14000_0000));
        assert_eq!(parse_hex_address(Some(&json!("DEADBEEF"))), Some(0xDEAD_BEEF));
        assert_eq!(parse_hex_address(None), None);
        assert_eq!(parse_hex_address(Some(&json!(42))), None); // not a string
    }

    #[tokio::test]
    async fn dispatch_scan_discard() {
        let state = make_state();

        // Start a session
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "scan.start".to_string(),
            params: json!({"pid": 100, "value": 42}),
            id: Some(json!(1)),
        };
        let resp = dispatch(state.clone(), &req).await;
        let session_id = resp.result.unwrap()["session_id"].as_str().unwrap().to_string();

        // Discard it
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "scan.discard".to_string(),
            params: json!({"session_id": session_id}),
            id: Some(json!(2)),
        };
        let resp = dispatch(state.clone(), &req).await;
        assert!(resp.result.unwrap()["discarded"].as_bool().unwrap());

        // Discard again -- should be false
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "scan.discard".to_string(),
            params: json!({"session_id": "nonexistent"}),
            id: Some(json!(3)),
        };
        let resp = dispatch(state, &req).await;
        assert!(!resp.result.unwrap()["discarded"].as_bool().unwrap());
    }
}
