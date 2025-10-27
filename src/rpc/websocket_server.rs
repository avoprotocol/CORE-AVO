use super::methods::RpcMethods;
use super::types::{RpcError, RpcRequest, RpcResponse};
use crate::consensus::flow_consensus::FlowConsensus;
use crate::AvoResult;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub remote_addr: String,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub request_count: u64,
}

/// WebSocket-based RPC Server
pub struct AvoWebSocketRpcServer {
    methods: Arc<RpcMethods>,
    host: String,
    port: u16,
    active_connections: Arc<tokio::sync::RwLock<HashMap<String, ConnectionInfo>>>,
}

impl AvoWebSocketRpcServer {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            methods: Arc::new(RpcMethods::new()),
            host,
            port,
            active_connections: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    pub fn new_with_consensus(host: String, port: u16, consensus: Arc<FlowConsensus>) -> Self {
        Self {
            methods: Arc::new(RpcMethods::new_with_consensus(consensus)),
            host,
            port,
            active_connections: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Start the WebSocket RPC server
    pub async fn start(&self) -> AvoResult<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", addr, e))?;

        info!("🚀 AVO WebSocket RPC Server starting on {}", addr);
        info!("🔗 WebSocket endpoint: ws://{}", addr);
        info!("📊 Supported methods:");
        info!("   • Ethereum-compatible: eth_getBalance, eth_getTransactionCount, eth_blockNumber, eth_chainId, etc.");
        info!(
            "   • AVO-specific: avo_getTreasuryAccounts, avo_getShardInfo, avo_getCacheStats, etc."
        );
        info!("   • Network: net_version, net_peerCount, net_listening");
        info!("   • WebSocket-specific: ws_ping, ws_getConnections");

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server
                            .handle_connection(stream, peer_addr.to_string())
                            .await
                        {
                            error!("❌ Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("⚠️ Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Handle a new WebSocket connection
    async fn handle_connection(&self, stream: TcpStream, peer_addr: String) -> AvoResult<()> {
        let connection_id = Uuid::new_v4().to_string();

        // Register connection
        {
            let mut connections = self.active_connections.write().await;
            connections.insert(
                connection_id.clone(),
                ConnectionInfo {
                    id: connection_id.clone(),
                    remote_addr: peer_addr.clone(),
                    connected_at: chrono::Utc::now(),
                    request_count: 0,
                },
            );
        }

        info!(
            "🔌 New WebSocket connection: {} from {}",
            connection_id, peer_addr
        );

        // Accept WebSocket handshake
        let ws_stream = accept_async(stream)
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket handshake failed: {}", e))?;

        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        // Send welcome message
        let welcome = json!({
            "jsonrpc": "2.0",
            "method": "server.connected",
            "params": {
                "connection_id": connection_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "server_info": {
                    "name": "AVO Protocol WebSocket RPC Server",
                    "version": "1.0.0",
                    "protocol": "JSON-RPC 2.0 over WebSocket"
                },
                "available_methods": [
                    "eth_getBalance",
                    "eth_sendTransaction",
                    "eth_blockNumber",
                    "eth_getTransactionCount",
                    "eth_chainId",
                    "eth_gasPrice",
                    "eth_estimateGas",
                    "avo_getMetrics",
                    "avo_getTreasuryAccounts",
                    "avo_getShardInfo",
                    "avo_getCacheStats",
                    "avo_getWalletCount",
                    "avo_listWallets",
                    "net_version",
                    "net_peerCount",
                    "net_listening",
                    "ws_ping",
                    "ws_getConnections"
                ]
            }
        });

        if let Err(e) = ws_sender.send(Message::Text(welcome.to_string())).await {
            error!("❌ Failed to send welcome message: {}", e);
        }

        // Handle incoming messages
        while let Some(msg) = ws_receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    // Update request count
                    {
                        let mut connections = self.active_connections.write().await;
                        if let Some(conn) = connections.get_mut(&connection_id) {
                            conn.request_count += 1;
                        }
                    }

                    let response = self.handle_rpc_message(&text, &connection_id).await;
                    if let Err(e) = ws_sender.send(Message::Text(response)).await {
                        error!("❌ Failed to send response: {}", e);
                        break;
                    }
                }
                Ok(Message::Binary(_)) => {
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": "Binary messages not supported. Please use text/JSON format."
                        },
                        "id": null
                    });
                    let _ = ws_sender
                        .send(Message::Text(error_response.to_string()))
                        .await;
                }
                Ok(Message::Close(frame)) => {
                    let reason = frame.map(|f| f.reason.to_string()).unwrap_or_default();
                    info!(
                        "🔌 WebSocket connection closed: {} (reason: {})",
                        connection_id, reason
                    );
                    break;
                }
                Ok(Message::Ping(data)) => {
                    debug!("🏓 Received ping from {}", connection_id);
                    if let Err(e) = ws_sender.send(Message::Pong(data)).await {
                        error!("❌ Failed to send pong: {}", e);
                        break;
                    }
                }
                Ok(Message::Pong(_)) => {
                    debug!("🏓 Received pong from {}", connection_id);
                }
                Ok(Message::Frame(_)) => {
                    // Raw frame - typically handled internally by tungstenite
                    debug!("📦 Received raw frame from {}", connection_id);
                }
                Err(e) => {
                    error!("❌ WebSocket error from {}: {}", connection_id, e);
                    break;
                }
            }
        }

        // Cleanup connection
        {
            let mut connections = self.active_connections.write().await;
            connections.remove(&connection_id);
        }

        info!("🔌 WebSocket connection {} disconnected", connection_id);
        Ok(())
    }

    /// Handle RPC message from WebSocket
    async fn handle_rpc_message(&self, message: &str, connection_id: &str) -> String {
        debug!("📥 Received from {}: {}", connection_id, message);

        // Parse JSON-RPC request
        let rpc_request: RpcRequest = match serde_json::from_str(message) {
            Ok(req) => req,
            Err(e) => {
                warn!("❌ Parse error from {}: {}", connection_id, e);
                let error_response = RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: Some(Value::Null),
                    result: None,
                    error: Some(RpcError {
                        code: -32700,
                        message: "Parse error".to_string(),
                        data: Some(json!({"original_error": e.to_string()})),
                    }),
                };
                return serde_json::to_string(&error_response).unwrap();
            }
        };

        info!(
            "📞 RPC Call from {}: {} {}",
            connection_id,
            rpc_request.method,
            serde_json::to_string(&rpc_request.params).unwrap_or_default()
        );

        // Handle WebSocket-specific methods
        let result = if rpc_request.method.starts_with("ws_") {
            self.handle_websocket_method(&rpc_request, connection_id)
                .await
        } else {
            // Handle standard RPC methods
            let response = self.methods.handle_request(rpc_request.clone()).await;
            match response.error {
                None => Ok(response.result.unwrap_or(Value::Null)),
                Some(error) => Err(error.message),
            }
        };

        // Create response
        let rpc_response = match result {
            Ok(result_value) => RpcResponse {
                jsonrpc: "2.0".to_string(),
                id: rpc_request.id,
                result: Some(result_value),
                error: None,
            },
            Err(error_msg) => RpcResponse {
                jsonrpc: "2.0".to_string(),
                id: rpc_request.id,
                result: None,
                error: Some(RpcError {
                    code: -32603,
                    message: error_msg,
                    data: None,
                }),
            },
        };

        let response_json = serde_json::to_string(&rpc_response).unwrap();
        debug!("📤 Sending to {}: {}", connection_id, response_json);
        response_json
    }

    /// Handle WebSocket-specific methods
    async fn handle_websocket_method(
        &self,
        request: &RpcRequest,
        connection_id: &str,
    ) -> Result<Value, String> {
        match request.method.as_str() {
            "ws_ping" => Ok(json!({
                "pong": true,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "connection_id": connection_id
            })),
            "ws_getConnections" => {
                let connections = self.active_connections.read().await;
                let connection_list: Vec<_> = connections.values().cloned().collect();
                Ok(json!({
                    "total_connections": connection_list.len(),
                    "connections": connection_list
                }))
            }
            "ws_getStats" => {
                let connections = self.active_connections.read().await;
                let total_requests: u64 = connections.values().map(|c| c.request_count).sum();

                Ok(json!({
                    "active_connections": connections.len(),
                    "total_requests": total_requests,
                    "server_uptime": chrono::Utc::now().to_rfc3339(),
                    "endpoint": format!("ws://{}:{}", self.host, self.port),
                    "protocol": "WebSocket JSON-RPC 2.0"
                }))
            }
            _ => Err(format!("Unknown WebSocket method: {}", request.method)),
        }
    }

    /// Get active connections count
    pub async fn get_connection_count(&self) -> usize {
        self.active_connections.read().await.len()
    }

    /// Get server statistics
    pub async fn get_stats(&self) -> serde_json::Value {
        let connections = self.active_connections.read().await;
        let total_requests: u64 = connections.values().map(|c| c.request_count).sum();

        json!({
            "active_connections": connections.len(),
            "total_requests": total_requests,
            "server_uptime": chrono::Utc::now().to_rfc3339(),
            "endpoint": format!("ws://{}:{}", self.host, self.port),
            "protocol": "WebSocket JSON-RPC 2.0"
        })
    }

    /// Broadcast message to all connected clients
    pub async fn broadcast(&self, message: &str) -> usize {
        let connections = self.active_connections.read().await;
        info!(
            "📢 Broadcasting to {} connections: {}",
            connections.len(),
            message
        );
        // Implementation would require storing the WebSocket senders
        // This is a placeholder for the concept
        connections.len()
    }
}

impl Clone for AvoWebSocketRpcServer {
    fn clone(&self) -> Self {
        Self {
            methods: Arc::clone(&self.methods),
            host: self.host.clone(),
            port: self.port,
            active_connections: Arc::clone(&self.active_connections),
        }
    }
}
