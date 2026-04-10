use crate::memory::MemoryAccess;
use crate::rpc::methods::{RpcState, dispatch};
use crate::rpc::types::*;
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Start the JSON-RPC server on a Unix domain socket.
pub async fn serve_unix_socket(
    socket_path: &str,
    mem: Arc<dyn MemoryAccess>,
) -> Result<()> {
    // Clean up stale socket
    let _ = std::fs::remove_file(socket_path);

    let listener = tokio::net::UnixListener::bind(socket_path)?;
    tracing::info!("listening on {socket_path}");

    let state = Arc::new(RpcState::new(mem));

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            tracing::debug!("client connected");
            if let Err(e) = handle_connection(stream, &state).await {
                tracing::error!("connection error: {e}");
            }
            tracing::debug!("client disconnected");
        });
    }
}

/// Start the JSON-RPC server on stdio (stdin/stdout).
pub async fn serve_stdio(mem: Arc<dyn MemoryAccess>) -> Result<()> {
    tracing::info!("serving JSON-RPC on stdio");

    let state = Arc::new(RpcState::new(mem));
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = process_line(&state, &line);
        let json = serde_json::to_string(&response)?;
        stdout.write_all(json.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }

    Ok(())
}

/// Handle a single connection (Unix socket).
async fn handle_connection(
    stream: tokio::net::UnixStream,
    state: &RpcState,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = process_line(state, &line);
        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Parse a JSON-RPC line and dispatch to the method handler.
fn process_line(state: &RpcState, line: &str) -> JsonRpcResponse {
    let request: JsonRpcRequest = match serde_json::from_str(line) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!("JSON parse error: {e}");
            return JsonRpcResponse::err(None, PARSE_ERROR, format!("JSON parse error: {e}"));
        }
    };

    tracing::debug!(method = %request.method, id = ?request.id, "RPC request");
    let start = std::time::Instant::now();
    let response = dispatch(state, &request);
    let elapsed = start.elapsed();

    if response.error.is_some() {
        tracing::warn!(
            method = %request.method,
            elapsed_ms = elapsed.as_millis(),
            error = ?response.error,
            "RPC error"
        );
    } else {
        tracing::debug!(
            method = %request.method,
            elapsed_ms = elapsed.as_millis(),
            "RPC ok"
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::{MapRegion, Permissions, RegionSafety};
    use crate::memory::MockMemoryAccess;

    fn make_state() -> Arc<RpcState> {
        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x1000, vec![0u8; 4096]);
        mock.set_maps(vec![MapRegion {
            start: 0x1000,
            end: 0x2000,
            permissions: Permissions { read: true, write: true, execute: false, shared: false },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: String::new(),
            safety: RegionSafety::Safe,
        }]);
        Arc::new(RpcState::new(Arc::new(mock)))
    }

    #[test]
    fn process_valid_request() {
        let state = make_state();
        let line = r#"{"jsonrpc":"2.0","method":"pid.list","params":{},"id":1}"#;
        let resp = process_line(&state, line);
        assert!(resp.error.is_none());
        assert!(resp.result.is_some());
    }

    #[test]
    fn process_invalid_json() {
        let state = make_state();
        let resp = process_line(&state, "not json at all");
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn process_missing_method() {
        let state = make_state();
        let line = r#"{"jsonrpc":"2.0","method":"does.not.exist","params":{},"id":1}"#;
        let resp = process_line(&state, line);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }
}
