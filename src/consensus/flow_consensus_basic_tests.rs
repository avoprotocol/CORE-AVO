//! Tests básicos y actualizados para FlowConsensus basados en la API vigente.

#[cfg(test)]
mod tests {
    use super::super::flow_consensus::FlowConsensus;
    use crate::state::storage::{AvocadoStorage, StorageConfig};
    use crate::types::{Address, ProtocolParams};
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
    async fn initializes_with_storage() {
        let (_dir_guard, storage) = setup_storage();
        let consensus = FlowConsensus::new_async(protocol_params(), storage)
            .await
            .expect("consensus should initialize with clean storage");

        // Clonar la instancia para asegurar que la implementación de Clone funciona.
        let cloned = consensus.clone();
        assert_eq!(cloned.calculate_block_hash(0, 0, "", "", "", 0).len(), 66);
    }

    #[tokio::test]
    async fn calculates_block_and_transaction_hashes() {
        let (_dir_guard, storage) = setup_storage();
        let consensus = FlowConsensus::new_async(protocol_params(), storage)
            .await
            .expect("consensus should initialize with clean storage");

        let block_hash =
            consensus.calculate_block_hash(1, 1_234, "root", "parent", "validator", 42);
        assert!(block_hash.starts_with("0x"));
        assert_eq!(block_hash.len(), 66);

        let tx_hash = consensus.calculate_transaction_hash(
            &Address::zero(),
            &Address::from_public_key(&[1, 2, 3, 4]),
            500,
            999,
            12,
        );
        assert!(tx_hash.starts_with("0x"));
        assert_eq!(tx_hash.len(), 66);
    }

    #[tokio::test]
    async fn parent_hash_defaults_to_genesis() {
        let (_dir_guard, storage) = setup_storage();
        let params = protocol_params();
        let consensus = FlowConsensus::new_async(params, storage)
            .await
            .expect("consensus should initialize with clean storage");

        let parent_hash = consensus.get_parent_hash().await;
        assert_eq!(
            parent_hash,
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
