use crate::rpc::types::{JsonRpcRequest, JsonRpcResponse};
use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// A JSON-RPC client that connects to a pika daemon over a Unix socket.
pub struct RpcClient {
    socket_path: String,
}

impl RpcClient {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    /// Send a JSON-RPC request and return the response.
    pub async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "cannot connect to pika daemon at {}.\n\
                     Start it with: pika serve &",
                    self.socket_path
                )
            })?;

        let (reader, mut writer) = stream.into_split();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: Some(serde_json::json!(1)),
        };

        let json = serde_json::to_string(&request)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        let mut lines = BufReader::new(reader).lines();
        let line = lines
            .next_line()
            .await?
            .context("daemon closed connection without response")?;

        let response: JsonRpcResponse = serde_json::from_str(&line)
            .with_context(|| format!("invalid JSON-RPC response: {line}"))?;

        if let Some(error) = response.error {
            anyhow::bail!("RPC error ({}): {}", error.code, error.message);
        }

        response
            .result
            .context("RPC response has neither result nor error")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::access::MockMemoryAccess;
    use crate::process::maps::{MapRegion, Permissions, RegionSafety};
    use crate::rpc::server::serve_unix_socket;
    use std::sync::Arc;

    #[tokio::test]
    async fn client_roundtrip_via_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let sock_str = sock_path.to_str().unwrap().to_string();

        let mock = MockMemoryAccess::new(1);
        mock.add_region(0x1000, vec![0u8; 4096]);
        mock.set_maps(vec![MapRegion {
            start: 0x1000,
            end: 0x2000,
            permissions: Permissions {
                read: true,
                write: true,
                execute: false,
                shared: false,
            },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: String::new(),
            safety: RegionSafety::Safe,
        }]);

        // Start server in background
        let sock_str_clone = sock_str.clone();
        let server_handle = tokio::spawn(async move {
            let _ = serve_unix_socket(&sock_str_clone, Arc::new(mock)).await;
        });

        // Give server time to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Client call
        let client = RpcClient::new(&sock_str);
        let result = client
            .call("pid.list", serde_json::json!({}))
            .await
            .unwrap();
        assert!(result.is_array());

        server_handle.abort();
    }

    #[tokio::test]
    async fn client_error_on_missing_socket() {
        let client = RpcClient::new("/tmp/pika-nonexistent-test.sock");
        let result = client.call("pid.list", serde_json::json!({})).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot connect"), "error: {err}");
    }

    #[tokio::test]
    async fn client_scan_filter_workflow() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test2.sock");
        let sock_str = sock_path.to_str().unwrap().to_string();

        let mock = MockMemoryAccess::new(42);
        let mut data = vec![0u8; 4096];
        // Plant value 100 at offset 0x100
        data[0x100..0x104].copy_from_slice(&100_i32.to_le_bytes());
        mock.add_region(0x0001_4000_0000, data);
        mock.set_maps(vec![MapRegion {
            start: 0x0001_4000_0000,
            end: 0x0001_4000_1000,
            permissions: Permissions {
                read: true,
                write: true,
                execute: false,
                shared: false,
            },
            offset: 0,
            device: "00:00".to_string(),
            inode: 0,
            pathname: String::new(),
            safety: RegionSafety::Safe,
        }]);

        let sock_str_clone = sock_str.clone();
        let server_handle = tokio::spawn(async move {
            let _ = serve_unix_socket(&sock_str_clone, Arc::new(mock)).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = RpcClient::new(&sock_str);

        // Start scan
        let result = client
            .call("scan.start", serde_json::json!({"pid": 42, "value": 100}))
            .await
            .unwrap();
        let session_id = result["session_id"].as_str().unwrap().to_string();
        assert!(result["candidates"].as_u64().unwrap() > 0);

        // Filter (value hasn't changed, so same candidates remain)
        let result = client
            .call(
                "scan.filter",
                serde_json::json!({"session_id": session_id, "new_value": 100}),
            )
            .await
            .unwrap();
        assert!(result["candidates"].as_u64().unwrap() > 0);

        // List sessions
        let result = client
            .call("scan.list", serde_json::json!({}))
            .await
            .unwrap();
        let sessions = result.as_array().unwrap();
        assert!(!sessions.is_empty());

        server_handle.abort();
    }
}
