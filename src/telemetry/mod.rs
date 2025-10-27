//! # Telemetry and Monitoring
//!
//! FASE 13.1: Prometheus metrics exporter and monitoring infrastructure

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Enable Prometheus metrics
    pub enable_prometheus: bool,
    /// Metrics HTTP endpoint port
    pub metrics_port: u16,
    /// Metrics endpoint path
    pub metrics_path: String,
    /// Enable detailed tracing
    pub enable_tracing: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enable_prometheus: true,
            metrics_port: 9090,
            metrics_path: "/metrics".to_string(),
            enable_tracing: true,
        }
    }
}

/// Core metrics for AVO Protocol
pub struct AvoMetrics {
    // Transaction metrics
    pub transactions_total: IntCounterVec,
    pub transactions_pending: IntGauge,
    pub transaction_duration: HistogramVec,
    pub transaction_bytes: Histogram,

    // Block metrics
    pub blocks_produced: IntCounterVec,
    pub block_height: IntGaugeVec,
    pub block_size_bytes: HistogramVec,
    pub block_transactions: HistogramVec,

    // Consensus metrics
    pub consensus_rounds: IntCounterVec,
    pub consensus_duration: HistogramVec,
    pub validator_votes: IntCounterVec,
    pub finality_duration: Histogram,

    // Shard metrics
    pub shard_count: IntGauge,
    pub cross_shard_transactions: IntCounterVec,
    pub shard_load_factor: GaugeVec,

    // Network metrics
    pub peer_count: IntGaugeVec,
    pub network_bytes_sent: IntCounterVec,
    pub network_bytes_received: IntCounterVec,
    pub rpc_requests: IntCounterVec,
    pub rpc_duration: HistogramVec,

    // Storage metrics
    pub storage_size_bytes: IntGaugeVec,
    pub state_root_calculations: IntCounter,
    pub checkpoint_operations: IntCounterVec,

    // ZK metrics
    pub zk_proof_generation_duration: Histogram,
    pub zk_proof_verification_duration: Histogram,
    pub zk_proofs_generated: IntCounter,
    pub zk_proofs_verified: IntCounter,

    // Data availability metrics
    pub da_chunks_published: IntCounterVec,
    pub da_chunks_retrieved: IntCounterVec,
    pub da_sampling_success_rate: Gauge,

    // L1 checkpoint metrics
    pub l1_checkpoints_submitted: IntCounter,
    pub l1_checkpoints_finalized: IntCounter,
    pub l1_gas_used: Histogram,

    // Error metrics
    pub errors_total: IntCounterVec,
}

impl AvoMetrics {
    /// Create new metrics registry
    pub fn new(registry: &Registry) -> prometheus::Result<Self> {
        let metrics = Self {
            // Transactions
            transactions_total: IntCounterVec::new(
                Opts::new("avo_transactions_total", "Total number of transactions"),
                &["shard", "type", "status"],
            )?,
            transactions_pending: IntGauge::new(
                "avo_transactions_pending",
                "Number of pending transactions",
            )?,
            transaction_duration: HistogramVec::new(
                HistogramOpts::new(
                    "avo_transaction_duration_seconds",
                    "Transaction processing duration",
                )
                .buckets(vec![0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
                &["shard"],
            )?,
            transaction_bytes: Histogram::with_opts(
                HistogramOpts::new("avo_transaction_bytes", "Transaction size in bytes")
                    .buckets(vec![100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0]),
            )?,

            // Blocks
            blocks_produced: IntCounterVec::new(
                Opts::new("avo_blocks_produced_total", "Total blocks produced"),
                &["shard"],
            )?,
            block_height: IntGaugeVec::new(
                Opts::new("avo_block_height", "Current block height"),
                &["shard"],
            )?,
            block_size_bytes: HistogramVec::new(
                HistogramOpts::new("avo_block_size_bytes", "Block size in bytes")
                    .buckets(vec![1000.0, 10000.0, 100000.0, 1000000.0]),
                &["shard"],
            )?,
            block_transactions: HistogramVec::new(
                HistogramOpts::new("avo_block_transactions", "Transactions per block")
                    .buckets(vec![10.0, 50.0, 100.0, 500.0, 1000.0]),
                &["shard"],
            )?,

            // Consensus
            consensus_rounds: IntCounterVec::new(
                Opts::new("avo_consensus_rounds_total", "Total consensus rounds"),
                &["shard", "result"],
            )?,
            consensus_duration: HistogramVec::new(
                HistogramOpts::new("avo_consensus_duration_seconds", "Consensus round duration")
                    .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0]),
                &["shard"],
            )?,
            validator_votes: IntCounterVec::new(
                Opts::new("avo_validator_votes_total", "Total validator votes"),
                &["validator_id", "vote_type"],
            )?,
            finality_duration: Histogram::with_opts(
                HistogramOpts::new("avo_finality_duration_seconds", "Time to finality")
                    .buckets(vec![1.0, 5.0, 10.0, 30.0, 60.0]),
            )?,

            // Shards
            shard_count: IntGauge::new("avo_shard_count", "Number of active shards")?,
            cross_shard_transactions: IntCounterVec::new(
                Opts::new(
                    "avo_cross_shard_transactions_total",
                    "Total cross-shard transactions",
                ),
                &["from_shard", "to_shard", "status"],
            )?,
            shard_load_factor: GaugeVec::new(
                Opts::new("avo_shard_load_factor", "Shard load factor (0-1)"),
                &["shard"],
            )?,

            // Network
            peer_count: IntGaugeVec::new(
                Opts::new("avo_peer_count", "Number of connected peers"),
                &["type"],
            )?,
            network_bytes_sent: IntCounterVec::new(
                Opts::new("avo_network_bytes_sent_total", "Total bytes sent"),
                &["protocol"],
            )?,
            network_bytes_received: IntCounterVec::new(
                Opts::new("avo_network_bytes_received_total", "Total bytes received"),
                &["protocol"],
            )?,
            rpc_requests: IntCounterVec::new(
                Opts::new("avo_rpc_requests_total", "Total RPC requests"),
                &["method", "status"],
            )?,
            rpc_duration: HistogramVec::new(
                HistogramOpts::new("avo_rpc_duration_seconds", "RPC request duration")
                    .buckets(vec![0.001, 0.01, 0.05, 0.1, 0.5, 1.0]),
                &["method"],
            )?,

            // Storage
            storage_size_bytes: IntGaugeVec::new(
                Opts::new("avo_storage_size_bytes", "Storage size in bytes"),
                &["type"],
            )?,
            state_root_calculations: IntCounter::new(
                "avo_state_root_calculations_total",
                "Total state root calculations",
            )?,
            checkpoint_operations: IntCounterVec::new(
                Opts::new("avo_checkpoint_operations_total", "Checkpoint operations"),
                &["operation"],
            )?,

            // ZK Proofs
            zk_proof_generation_duration: Histogram::with_opts(
                HistogramOpts::new(
                    "avo_zk_proof_generation_duration_seconds",
                    "ZK proof generation time",
                )
                .buckets(vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0]),
            )?,
            zk_proof_verification_duration: Histogram::with_opts(
                HistogramOpts::new(
                    "avo_zk_proof_verification_duration_seconds",
                    "ZK proof verification time",
                )
                .buckets(vec![0.001, 0.01, 0.05, 0.1, 0.5]),
            )?,
            zk_proofs_generated: IntCounter::new(
                "avo_zk_proofs_generated_total",
                "Total ZK proofs generated",
            )?,
            zk_proofs_verified: IntCounter::new(
                "avo_zk_proofs_verified_total",
                "Total ZK proofs verified",
            )?,

            // Data Availability
            da_chunks_published: IntCounterVec::new(
                Opts::new("avo_da_chunks_published_total", "DA chunks published"),
                &["shard"],
            )?,
            da_chunks_retrieved: IntCounterVec::new(
                Opts::new("avo_da_chunks_retrieved_total", "DA chunks retrieved"),
                &["shard"],
            )?,
            da_sampling_success_rate: Gauge::new(
                "avo_da_sampling_success_rate",
                "Data availability sampling success rate",
            )?,

            // L1 Checkpoints
            l1_checkpoints_submitted: IntCounter::new(
                "avo_l1_checkpoints_submitted_total",
                "L1 checkpoints submitted",
            )?,
            l1_checkpoints_finalized: IntCounter::new(
                "avo_l1_checkpoints_finalized_total",
                "L1 checkpoints finalized",
            )?,
            l1_gas_used: Histogram::with_opts(
                HistogramOpts::new("avo_l1_gas_used", "Gas used for L1 transactions")
                    .buckets(vec![21000.0, 50000.0, 100000.0, 500000.0, 1000000.0]),
            )?,

            // Errors
            errors_total: IntCounterVec::new(
                Opts::new("avo_errors_total", "Total errors"),
                &["component", "type"],
            )?,
        };

        // Register all metrics
        registry.register(Box::new(metrics.transactions_total.clone()))?;
        registry.register(Box::new(metrics.transactions_pending.clone()))?;
        registry.register(Box::new(metrics.transaction_duration.clone()))?;
        registry.register(Box::new(metrics.transaction_bytes.clone()))?;

        registry.register(Box::new(metrics.blocks_produced.clone()))?;
        registry.register(Box::new(metrics.block_height.clone()))?;
        registry.register(Box::new(metrics.block_size_bytes.clone()))?;
        registry.register(Box::new(metrics.block_transactions.clone()))?;

        registry.register(Box::new(metrics.consensus_rounds.clone()))?;
        registry.register(Box::new(metrics.consensus_duration.clone()))?;
        registry.register(Box::new(metrics.validator_votes.clone()))?;
        registry.register(Box::new(metrics.finality_duration.clone()))?;

        registry.register(Box::new(metrics.shard_count.clone()))?;
        registry.register(Box::new(metrics.cross_shard_transactions.clone()))?;
        registry.register(Box::new(metrics.shard_load_factor.clone()))?;

        registry.register(Box::new(metrics.peer_count.clone()))?;
        registry.register(Box::new(metrics.network_bytes_sent.clone()))?;
        registry.register(Box::new(metrics.network_bytes_received.clone()))?;
        registry.register(Box::new(metrics.rpc_requests.clone()))?;
        registry.register(Box::new(metrics.rpc_duration.clone()))?;

        registry.register(Box::new(metrics.storage_size_bytes.clone()))?;
        registry.register(Box::new(metrics.state_root_calculations.clone()))?;
        registry.register(Box::new(metrics.checkpoint_operations.clone()))?;

        registry.register(Box::new(metrics.zk_proof_generation_duration.clone()))?;
        registry.register(Box::new(metrics.zk_proof_verification_duration.clone()))?;
        registry.register(Box::new(metrics.zk_proofs_generated.clone()))?;
        registry.register(Box::new(metrics.zk_proofs_verified.clone()))?;

        registry.register(Box::new(metrics.da_chunks_published.clone()))?;
        registry.register(Box::new(metrics.da_chunks_retrieved.clone()))?;
        registry.register(Box::new(metrics.da_sampling_success_rate.clone()))?;

        registry.register(Box::new(metrics.l1_checkpoints_submitted.clone()))?;
        registry.register(Box::new(metrics.l1_checkpoints_finalized.clone()))?;
        registry.register(Box::new(metrics.l1_gas_used.clone()))?;

        registry.register(Box::new(metrics.errors_total.clone()))?;

        Ok(metrics)
    }
}

/// Main telemetry manager
pub struct TelemetryManager {
    config: TelemetryConfig,
    registry: Arc<Registry>,
    metrics: Arc<AvoMetrics>,
}

impl TelemetryManager {
    /// Create new telemetry manager
    pub fn new(config: TelemetryConfig) -> prometheus::Result<Self> {
        let registry = Registry::new();
        let metrics = AvoMetrics::new(&registry)?;

        Ok(Self {
            config,
            registry: Arc::new(registry),
            metrics: Arc::new(metrics),
        })
    }

    /// Get metrics instance
    pub fn metrics(&self) -> Arc<AvoMetrics> {
        self.metrics.clone()
    }

    /// Get registry for exporter
    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    /// Start metrics HTTP server
    pub async fn start_metrics_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Body, Request, Response, Server, StatusCode};
        use prometheus::Encoder;

        let registry = self.registry.clone();
        let metrics_path = self.config.metrics_path.clone();

        let make_svc = make_service_fn(move |_| {
            let registry = registry.clone();
            let metrics_path = metrics_path.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                    let registry = registry.clone();
                    let metrics_path = metrics_path.clone();
                    async move {
                        if req.uri().path() == metrics_path {
                            let encoder = prometheus::TextEncoder::new();
                            let metric_families = registry.gather();
                            let mut buffer = Vec::new();
                            if let Err(err) = encoder.encode(&metric_families, &mut buffer) {
                                tracing::error!("Failed to encode metrics: {}", err);
                                return Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from("metrics encoding error"))
                                        .unwrap(),
                                );
                            }

                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                                    .body(Body::from(buffer))
                                    .unwrap(),
                            )
                        } else {
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::from("not found"))
                                    .unwrap(),
                            )
                        }
                    }
                }))
            }
        });

        tracing::info!(
            "📊 Starting metrics server on http://0.0.0.0:{}{}",
            self.config.metrics_port,
            self.config.metrics_path
        );

        let addr = ([0, 0, 0, 0], self.config.metrics_port).into();
        Server::bind(&addr).serve(make_svc).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_creation() {
        let config = TelemetryConfig::default();
        let telemetry = TelemetryManager::new(config).unwrap();

        // Verify metrics can be accessed
        let metrics = telemetry.metrics();
        metrics
            .transactions_total
            .with_label_values(&["0", "transfer", "success"])
            .inc();
        metrics.shard_count.set(4);
    }

    #[test]
    fn test_metrics_collection() {
        let registry = Registry::new();
        let metrics = AvoMetrics::new(&registry).unwrap();

        // Record some metrics
        metrics.blocks_produced.with_label_values(&["0"]).inc();
        metrics.block_height.with_label_values(&["0"]).set(100);
        metrics
            .transaction_duration
            .with_label_values(&["0"])
            .observe(0.15);

        // Verify metrics are registered
        let metric_families = registry.gather();
        assert!(!metric_families.is_empty());
    }
}
