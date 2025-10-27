//! Pruebas básicas para garantizar que FlowConsensus se inicializa correctamente.

#[cfg(test)]
mod tests {
    use super::super::flow_consensus::FlowConsensus;
    use crate::state::storage::{AvocadoStorage, StorageConfig};
    use crate::types::ProtocolParams;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn protocol_params() -> ProtocolParams {
        ProtocolParams {
            epoch_duration_ms: 1_000,
            quorum_threshold: 0.67,
            finality_threshold: 0.67,
            sync_validator_ratio: 0.1,
            cross_shard_timeout_ms: 2_000,
            max_shard_count: 4,
            min_validator_stake: 1_000,
            min_bootstrap_stake: 5_000,
            min_delegation_amount: 100,
            slash_percentage: 0.05,
            bootstrap_apr: 0.15,
            validator_apr: 0.12,
            delegator_apr: 0.08,
            max_validators: 16,
            network_id: 9_999,
        }
    }

    fn setup_storage() -> (TempDir, Arc<AvocadoStorage>) {
        let temp_dir = TempDir::new().expect("failed to create temp directory for consensus tests");
        let mut config = StorageConfig::with_path(temp_dir.path());
        config.enable_wal = false;
        let storage = AvocadoStorage::new(config).expect("failed to initialize storage");
        (temp_dir, Arc::new(storage))
    }

    #[tokio::test]
    async fn initializes_and_hashes_blocks() {
        let (_dir_guard, storage) = setup_storage();
        let consensus = FlowConsensus::new_async(protocol_params(), storage)
            .await
            .expect("consensus should initialize with clean storage");

        let block_hash =
            consensus.calculate_block_hash(1, 1_234, "root", "parent", "validator", 42);
        assert!(block_hash.starts_with("0x"));
        assert!(block_hash.len() > 10);
    }
}
