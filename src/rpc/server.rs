use super::methods::RpcMethods;
use super::types::{RpcError, RpcRequest, RpcResponse, INVALID_REQUEST, PARSE_ERROR};
use crate::AvoResult;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde_json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

pub struct AvoRpcServer {
    methods: Arc<RpcMethods>,
    host: String,
    port: u16,
}

impl AvoRpcServer {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            methods: Arc::new(RpcMethods::new()),
            host,
            port,
        }
    }

    pub async fn start(&self) -> AvoResult<()> {
        let addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse address: {}", e))?;
        let methods = Arc::clone(&self.methods);

        // Define the service that handles requests
        let make_svc = make_service_fn(move |_conn| {
            let methods = Arc::clone(&methods);
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let methods = Arc::clone(&methods);
                    async move { handle_request(req, &methods).await }
                }))
            }
        });

        info!("� AVO RPC Server starting on {}", addr);
        info!("📊 Supported methods:");
        info!("   • Ethereum-compatible: eth_getBalance, eth_getTransactionCount, eth_blockNumber, eth_chainId, etc.");
        info!(
            "   • AVO-specific: avo_getTreasuryAccounts, avo_getShardInfo, avo_getCacheStats, etc."
        );
        info!("   • Network: net_version, net_peerCount, net_listening");

        let server = Server::bind(&addr).serve(make_svc);

        info!("✅ AVO RPC Server bound and listening on {}", addr);

        if let Err(e) = server.await {
            error!("❌ RPC Server error: {}", e);
            return Err(e.into());
        }

        info!("⚠️ RPC Server stopped normally (this should not happen)");
        Ok(())
    }

    pub async fn get_cache_stats(&self) -> serde_json::Value {
        let cache = self.methods.get_cache();
        let cache_stats = cache.stats().await;
        serde_json::json!({
            "cache_hits": cache_stats.hits,
            "cache_misses": cache_stats.misses,
            "total_requests": cache_stats.total_requests,
            "hit_rate": cache.hit_rate(),
            "cache_size": cache.size().await,
            "evictions": cache_stats.evictions
        })
    }

    pub async fn clear_cache(&self) {
        let cache = self.methods.get_cache();
        cache.clear().await;
        info!("🧹 RPC cache cleared");
    }
}

async fn handle_request(
    req: Request<Body>,
    methods: &Arc<RpcMethods>,
) -> Result<Response<Body>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::POST, "/") => {
            // Handle JSON-RPC request
            match hyper::body::to_bytes(req.into_body()).await {
                Ok(body) => {
                    let body_str = match std::str::from_utf8(&body) {
                        Ok(s) => s,
                        Err(_) => {
                            return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .header("Content-Type", "application/json")
                                .body(Body::from(r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}"#))
                                .unwrap());
                        }
                    };

                    debug!("📥 Received request: {}", body_str);

                    match serde_json::from_str::<RpcRequest>(body_str) {
                        Ok(rpc_request) => {
                            let rpc_response = methods.handle_request(rpc_request).await;
                            let response_json = serde_json::to_string(&rpc_response).unwrap_or_else(|_| {
                                r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#.to_string()
                            });

                            debug!("📤 Sending response: {}", response_json);

                            Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "application/json")
                                .header("Access-Control-Allow-Origin", "*")
                                .header("Access-Control-Allow-Methods", "POST, OPTIONS")
                                .header("Access-Control-Allow-Headers", "Content-Type")
                                .body(Body::from(response_json))
                                .unwrap()
                        }
                        Err(e) => {
                            warn!("❌ Failed to parse JSON-RPC request: {}", e);
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .header("Content-Type", "application/json")
                                .body(Body::from(r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}"#))
                                .unwrap()
                        }
                    }
                }
                Err(e) => {
                    warn!("❌ Failed to read request body: {}", e);
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", "application/json")
                        .body(Body::from(r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}"#))
                        .unwrap()
                }
            }
        }
        (&Method::OPTIONS, "/") => {
            // Handle CORS preflight
            Response::builder()
                .status(StatusCode::OK)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "POST, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type")
                .body(Body::empty())
                .unwrap()
        }
        _ => {
            // Method not allowed
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Method not allowed"))
                .unwrap()
        }
    };

    Ok(response)
}
