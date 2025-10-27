#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

pub mod consensus;
pub mod crypto;
pub mod da; // Data Availability Layer
pub mod data_availability; // Data Availability Layer - Nueva implementación
pub mod economics; // On-chain Economics - Phase 5
pub mod governance;
pub mod monitoring;
pub mod network;
pub mod performance;
pub mod rpc;
pub mod sharding;
pub mod staking; // Sistema de Staking Avanzado
pub mod state;
pub mod storage; // RocksDB storage backend - Phase 9.3
pub mod telemetry; // FASE 13.1: Prometheus/Grafana telemetry
pub mod transaction; // Transaction validation - Phase 9
pub mod ui;
pub mod vm; // Console UI Display

pub mod benchmark_types;
pub mod error;
pub mod traits;
pub mod types;
pub mod utils;

pub mod integration;

pub use error::{AvoError, AvoResult};
pub use traits::{
    ConsensusParticipant, ExecutionResult, FinalityGadget, ProtocolConfig, Storage,
    TransactionValidator, VirtualMachine,
};
pub use types::{
    Address, Block, BlockId, Epoch, Hash, MerkleProof, NetworkInfo, NetworkMessage, ProtocolParams,
    ShardId, Transaction, TransactionId, Validator, ValidatorInfo,
};

pub use consensus::{
    FinalityEngine as Finality, FlowConsensus, InterShardConsensus, IntraShardConsensus,
};

pub use utils::{consensus as consensus_utils, encoding, hash, math, time, validation};

pub const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const PROTOCOL_SPEC_VERSION: u32 = 1;

pub fn default_protocol_params() -> ProtocolParams {
    ProtocolParams::default()
}

/// Inicializa el logging para la librería
pub fn init_logging() {
    tracing_subscriber::fmt::init();
}

pub fn initialize_protocol(params: ProtocolParams) -> AvoResult<()> {
    // Validar parámetros
    if !validation::is_valid_threshold(params.quorum_threshold) {
        return Err(AvoError::config("Invalid quorum threshold"));
    }

    if !validation::is_valid_threshold(params.finality_threshold) {
        return Err(AvoError::config("Invalid finality threshold"));
    }

    if params.epoch_duration_ms == 0 {
        return Err(AvoError::config("Epoch duration must be > 0"));
    }

    if params.max_shard_count == 0 {
        return Err(AvoError::config("Max shard count must be > 0"));
    }

    tracing::info!(
        "AVO Protocol initialized - Version: {}, Spec: {}",
        PROTOCOL_VERSION,
        PROTOCOL_SPEC_VERSION
    );

    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProtocolInfo {
    pub version: String,
    pub spec_version: u32,
    pub build_time: String,
    pub features: Vec<String>,
}

impl Default for ProtocolInfo {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            spec_version: PROTOCOL_SPEC_VERSION,
            build_time: env!("BUILD_TIME").to_string(),
            features: vec![
                "hybrid-consensus".to_string(),
                "threshold-encryption".to_string(),
                "cross-shard-atomicity".to_string(),
                "dynamic-sharding".to_string(),
                "wasm-vm".to_string(),
                "mev-protection".to_string(),
            ],
        }
    }
}

pub fn get_protocol_info() -> ProtocolInfo {
    ProtocolInfo::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_initialization() {
        let params = default_protocol_params();
        assert!(initialize_protocol(params).is_ok());
    }

    #[test]
    fn test_invalid_protocol_params() {
        let mut params = default_protocol_params();
        params.quorum_threshold = 2.0; // Invalid threshold > 1.0
        assert!(initialize_protocol(params).is_err());
    }

    #[test]
    fn test_protocol_info() {
        let info = get_protocol_info();
        assert_eq!(info.version, PROTOCOL_VERSION);
        assert_eq!(info.spec_version, PROTOCOL_SPEC_VERSION);
        assert!(!info.features.is_empty());
    }

    #[test]
    fn test_default_params_valid() {
        let params = default_protocol_params();
        assert!(params.quorum_threshold > 0.0 && params.quorum_threshold <= 1.0);
        assert!(params.finality_threshold > 0.0 && params.finality_threshold <= 1.0);
        assert!(params.epoch_duration_ms > 0);
        assert!(params.max_shard_count > 0);
    }
}
