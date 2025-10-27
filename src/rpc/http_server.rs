use super::methods::RpcMethods;
use super::types::{RpcRequest, RpcResponse};
use crate::consensus::flow_consensus::FlowConsensus;
use crate::AvoResult;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde_json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// HTTP RPC Server for MetaMask and Web3 compatibility
pub struct AvoHttpRpcServer {
    methods: Arc<RpcMethods>,
    host: String,
    port: u16,
}

impl AvoHttpRpcServer {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            methods: Arc::new(RpcMethods::new()),
            host,
            port,
        }
    }

    pub fn new_with_consensus(host: String, port: u16, consensus: Arc<FlowConsensus>) -> Self {
        Self {
            methods: Arc::new(RpcMethods::new_with_consensus(consensus)),
            host,
            port,
        }
    }

    /// Start the HTTP RPC server
    pub async fn start(&self) -> AvoResult<()> {
        let addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

        let methods = Arc::clone(&self.methods);

        let make_svc = make_service_fn(move |_conn| {
            let methods = Arc::clone(&methods);
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    handle_request(Arc::clone(&methods), req)
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);

        info!("🌐 AVO HTTP RPC Server starting on http://{}", addr);
        info!("📡 JSON-RPC 2.0 endpoint ready for MetaMask and Web3 clients");
        info!("🔗 CORS enabled for browser compatibility");

        if let Err(e) = server.await {
            error!("❌ HTTP RPC server error: {}", e);
            return Err(crate::AvoError::NetworkError {
                reason: format!("HTTP RPC server failed: {}", e),
            });
        }

        Ok(())
    }
}

async fn handle_request(
    methods: Arc<RpcMethods>,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    // Handle CORS preflight
    if req.method() == Method::OPTIONS {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
            .header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization",
            )
            .header("Access-Control-Max-Age", "86400")
            .body(Body::empty())
            .unwrap());
    }

    // Only allow POST for JSON-RPC
    if req.method() != Method::POST {
        warn!(
            "❌ Invalid HTTP method: {} (only POST allowed)",
            req.method()
        );
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("Access-Control-Allow-Origin", "*")
            .header("Allow", "POST, OPTIONS")
            .body(Body::from("Only POST method allowed for JSON-RPC"))
            .unwrap());
    }

    // Get request body
    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("❌ Failed to read request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Access-Control-Allow-Origin", "*")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}"#))
                .unwrap());
        }
    };

    // Parse JSON-RPC request
    let rpc_request: RpcRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(e) => {
            error!("❌ Invalid JSON-RPC request: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Access-Control-Allow-Origin", "*")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}"#))
                .unwrap());
        }
    };

    debug!(
        "📨 HTTP RPC request: {} with params: {:?}",
        rpc_request.method, rpc_request.params
    );

    // Process the request
    let rpc_response = methods.handle_request(rpc_request).await;

    // Serialize response
    let response_json = match serde_json::to_string(&rpc_response) {
        Ok(json) => json,
        Err(e) => {
            error!("❌ Failed to serialize response: {}", e);
            format!(
                r#"{{"jsonrpc":"2.0","error":{{"code":-32603,"message":"Internal error"}},"id":{}}}"#,
                rpc_response
                    .id
                    .as_ref()
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
            )
        }
    };

    debug!("📤 HTTP RPC response: {}", response_json);

    // Return HTTP response with CORS headers
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        .header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization",
        )
        .header("Content-Type", "application/json")
        .body(Body::from(response_json))
        .unwrap())
}

/// Utility function to check if HTTP RPC server is accessible
pub async fn test_http_rpc_connection(host: &str, port: u16) -> bool {
    let url = format!("http://{}:{}", host, port);

    let client = hyper::Client::new();
    let req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#,
        ))
        .unwrap();

    match client.request(req).await {
        Ok(response) => {
            info!("✅ HTTP RPC server test successful: {}", response.status());
            response.status().is_success()
        }
        Err(e) => {
            warn!("⚠️ HTTP RPC server test failed: {}", e);
            false
        }
    }
}
