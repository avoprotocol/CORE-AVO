use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// ⚡ ZK METRICS FOR BLOCKCHAIN EXPLORER ⚡
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMetrics {
    pub constraint_batching: ConstraintBatchingMetrics,
    pub recursive_proofs: RecursiveProofMetrics,
    pub hardware_acceleration: HardwareAccelerationMetrics,
    pub zk_vm: ZkVmMetrics,
    pub plonk_implementation: PlonkMetrics,
    pub overall_performance: OverallZkPerformance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintBatchingMetrics {
    pub total_constraints_before: u64,
    pub total_constraints_after: u64,
    pub reduction_percentage: f64,
    pub batches_processed: u64,
    pub avg_batch_size: f64,
    pub last_optimization_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveProofMetrics {
    pub proofs_aggregated: u64,
    pub recursive_levels: u32,
    pub compression_ratio: f64,
    pub verification_time_ms: u64,
    pub proof_size_reduction: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAccelerationMetrics {
    pub gpu_acceleration_enabled: bool,
    pub simd_optimization_enabled: bool,
    pub parallel_operations: u32,
    pub speedup_factor: f64,
    pub operations_per_second: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVmMetrics {
    pub programs_executed: u64,
    pub total_instructions: u64,
    pub avg_constraints_per_instruction: f64,
    pub execution_time_ms: u64,
    pub circuit_optimization_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlonkMetrics {
    pub universal_setup_size: u64,
    pub custom_gates_used: u32,
    pub lookup_tables_active: u32,
    pub proof_generation_time_ms: u64,
    pub verification_time_ms: u64,
    pub proof_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallZkPerformance {
    pub total_proofs_generated: u64,
    pub total_verification_time_ms: u64,
    pub avg_proof_size_reduction: f64,
    pub total_gas_savings: u64,
    pub zk_enabled_transactions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
    pub transactions: Vec<String>,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub shard_id: u32,
    // NEW: ZK metrics per block
    pub zk_metrics: Option<ZkMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub gas: u64,
    pub gas_price: u64,
    pub nonce: u64,
    pub block_hash: Option<String>,
    pub block_number: Option<u64>,
    pub transaction_index: Option<u64>,
    pub shard_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub address: String,
    pub balance: String,
    pub nonce: u64,
    pub code_hash: Option<String>,
    pub storage_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub chain_id: u64,
    pub network_id: u64,
    pub protocol_version: String,
    pub node_id: String,
    pub peer_count: usize,
    pub is_syncing: bool,
    pub current_block: u64,
    pub highest_block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardInfo {
    pub shard_id: u32,
    pub validator_count: usize,
    pub current_block: u64,
    pub pending_transactions: usize,
    pub total_gas_used: u64,
    pub avg_block_time: f64,
}

// Standard Ethereum-compatible error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

// AVO-specific error codes
pub const SHARD_NOT_FOUND: i32 = -33001;
pub const ACCOUNT_NOT_FOUND: i32 = -33002;
pub const TRANSACTION_FAILED: i32 = -33003;
pub const INSUFFICIENT_BALANCE: i32 = -33004;
pub const INVALID_SIGNATURE: i32 = -33005;
