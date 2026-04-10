use std::fmt::Write as _;

use crate::candidate::{CandidateJson, ValueType};
use crate::filter::filter_candidates;
use crate::freeze::{FreezeEntry, FreezeManager};
use crate::memory::MemoryAccess;
use crate::pid;
use crate::rpc::types::*;
use crate::scan::{SessionRegistry, first_scan};
use crate::write::write_value;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Shared state for RPC method handlers.
pub struct RpcState {
    pub mem: Arc<dyn MemoryAccess>,
    pub sessions: SessionRegistry,
    pub freeze: FreezeManager,
}

impl RpcState {
    pub fn new(mem: Arc<dyn MemoryAccess>) -> Self {
        Self {
            sessions: SessionRegistry::new(),
            freeze: FreezeManager::new(mem.clone()),
            mem,
        }
    }
}

/// Dispatch a JSON-RPC request to the appropriate handler.
pub fn dispatch(state: &RpcState, req: &JsonRpcRequest) -> JsonRpcResponse {
    if let Err(e) = req.validate() {
        return JsonRpcResponse::err(req.id.clone(), INVALID_REQUEST, e);
    }

    let result = match req.method.as_str() {
        "pid.list" => handle_pid_list(),
        "pid.find" => handle_pid_find(&req.params),
        "scan.start" => handle_scan_start(state, &req.params),
        "scan.filter" => handle_scan_filter(state, &req.params),
        "scan.discard" => handle_scan_discard(state, &req.params),
        "memory.read" => handle_memory_read(state, &req.params),
        "memory.write" => handle_memory_write(state, &req.params),
        "freeze.start" => handle_freeze_start(state, &req.params),
        "freeze.stop" => handle_freeze_stop(state, &req.params),
        "freeze.list" => handle_freeze_list(state),
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

type MethodResult = Result<serde_json::Value, JsonRpcResponse>;

fn handle_pid_list() -> MethodResult {
    let processes = pid::list_wine_processes().map_err(|e| {
        JsonRpcResponse::err(None, INTERNAL_ERROR, e.to_string())
    })?;
    Ok(json!(processes))
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
        .ok_or_else(|| JsonRpcResponse::err(None, INVALID_PARAMS, "missing 'new_value'"))?;

    let result = state.sessions.with_session(session_id, |session| {
        let retained =
            filter_candidates(state.mem.as_ref(), session.pid, &mut session.candidates, new_value, session.dtype)
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

/// Parse a hex address string like "0x7f2012340000" or "7f2012340000".
fn parse_hex_address(value: Option<&serde_json::Value>) -> Option<u64> {
    let s = value?.as_str()?;
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::{MapRegion, Permissions, RegionSafety};
    use crate::memory::MockMemoryAccess;

    fn make_state() -> RpcState {
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
        RpcState::new(Arc::new(mock))
    }

    #[test]
    fn dispatch_pid_list() {
        let state = make_state();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "pid.list".to_string(),
            params: json!({}),
            id: Some(json!(1)),
        };
        let resp = dispatch(&state, &req);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn dispatch_unknown_method() {
        let state = make_state();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "nonexistent".to_string(),
            params: json!({}),
            id: Some(json!(1)),
        };
        let resp = dispatch(&state, &req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn dispatch_scan_start_and_filter() {
        let state = make_state();

        // Start scan
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "scan.start".to_string(),
            params: json!({"pid": 100, "value": 42}),
            id: Some(json!(1)),
        };
        let resp = dispatch(&state, &req);
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
        let resp = dispatch(&state, &req);
        assert!(resp.error.is_none(), "scan.filter error: {:?}", resp.error);
    }

    #[test]
    fn dispatch_memory_read() {
        let state = make_state();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "memory.read".to_string(),
            params: json!({"pid": 100, "address": "0x140000000", "length": 16}),
            id: Some(json!(1)),
        };
        let resp = dispatch(&state, &req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["bytes_read"], 16);
        assert!(result["hex"].as_str().is_some());
        assert_eq!(result["interpretations"]["i32"], 42);
    }

    #[test]
    fn dispatch_memory_write() {
        let state = make_state();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "memory.write".to_string(),
            params: json!({"pid": 100, "address": "0x140000000", "value": 999, "dtype": "i32"}),
            id: Some(json!(1)),
        };
        let resp = dispatch(&state, &req);
        assert!(resp.error.is_none(), "write error: {:?}", resp.error);

        // Verify the write
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "memory.read".to_string(),
            params: json!({"pid": 100, "address": "0x140000000", "length": 4}),
            id: Some(json!(2)),
        };
        let resp = dispatch(&state, &req);
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

    #[test]
    fn dispatch_scan_discard() {
        let state = make_state();

        // Start a session
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "scan.start".to_string(),
            params: json!({"pid": 100, "value": 42}),
            id: Some(json!(1)),
        };
        let resp = dispatch(&state, &req);
        let session_id = resp.result.unwrap()["session_id"].as_str().unwrap().to_string();

        // Discard it
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "scan.discard".to_string(),
            params: json!({"session_id": session_id}),
            id: Some(json!(2)),
        };
        let resp = dispatch(&state, &req);
        assert!(resp.result.unwrap()["discarded"].as_bool().unwrap());

        // Discard again -- should be false
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "scan.discard".to_string(),
            params: json!({"session_id": "nonexistent"}),
            id: Some(json!(3)),
        };
        let resp = dispatch(&state, &req);
        assert!(!resp.result.unwrap()["discarded"].as_bool().unwrap());
    }
}
