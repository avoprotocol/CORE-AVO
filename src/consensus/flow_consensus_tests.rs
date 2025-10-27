//! Pruebas enfocadas en validar los puntos críticos de la API moderna de FlowConsensus.

#[cfg(test)]
mod tests {
    use super::super::flow_consensus::FlowConsensus;
    use crate::crypto::bls_signatures::BlsAggregator;
    use crate::error::AvoError;
    use crate::network::p2p::NetworkMessage as P2PNetworkMessage;
    use crate::state::storage::{AvocadoStorage, StorageConfig};
    use crate::types::{
        Address, AggregatedSignature, AggregatedVote, Block, BlockId, CrossShardStatus,
        FinalityProofSummary, ProtocolParams, ShardConfig, ShardSpecialization, Transaction,
        TransactionId, TransactionType, ValidatorId, VoteType,
    };
    use bincode::serialize;
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
            max_validators: 32,
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

    fn sample_transaction() -> Transaction {
        Transaction {
            id: TransactionId::new(b"sample_tx"),
            from: Address::zero(),
            to: Some(Address::from_public_key(&[1, 2, 3, 4, 5, 6])),
            value: 1_000,
            data: Some(vec![1, 2, 3]),
            gas_limit: 21_000,
            gas_price: 1,
            nonce: 0,
            signature: vec![0u8; 65],
            parents: vec![],
            shard_id: 0,
            cross_shard_deps: vec![],
            transaction_type: TransactionType::Transfer,
        }
    }

    fn shard_config(shard_id: u32, validator_count: u32) -> ShardConfig {
        ShardConfig {
            shard_id,
            validator_count,
            specialization: ShardSpecialization::General,
            max_transactions_per_block: 128,
            block_time_ms: 1_000,
            gas_limit: 1_000_000,
            load_threshold_split: 0.75,
            load_threshold_merge: 0.25,
        }
    }

    fn make_block(block_id: BlockId) -> Block {
        Block {
            id: block_id,
            shard_id: 0,
            epoch: 0,
            timestamp: 0,
            height: 1,
            transactions: Vec::new(),
            parents: vec![BlockId::zero()],
            state_root: [0u8; 32],
            transaction_merkle_root: [0u8; 32],
            validator_set_hash: [0u8; 32],
            proposer_signature: Vec::new(),
        }
    }

    fn make_finality_summary(block_id: BlockId, vote: AggregatedVote) -> FinalityProofSummary {
        FinalityProofSummary {
            block_id,
            block_height: 1,
            shard_id: 0,
            aggregated_vote: vote,
            merkle_root: [0u8; 32],
            merkle_leaf: [0u8; 32],
            merkle_leaf_index: 0,
            merkle_proof: vec![[0u8; 32]; 2],
        }
    }

    fn aggregated_vote_for_block(
        consensus: &FlowConsensus,
        block_id: BlockId,
        participants: &[ValidatorId],
        support_ratio: f64,
    ) -> AggregatedVote {
        let crypto = consensus.test_crypto_system();
        let message = block_id.as_bytes();
        let ratio = support_ratio.clamp(0.0, 1.0);

        let mut signatures = Vec::with_capacity(participants.len());
        for validator_id in participants {
            let (private_key, _) = crypto
                .bls_keys
                .get(validator_id)
                .expect("validator key must exist for test");
            let signature = private_key
                .sign(message)
                .expect("signature generation should succeed");
            signatures.push(signature);
        }

        let aggregated_signature =
            BlsAggregator::aggregate_signatures(&signatures).expect("aggregation should succeed");
        let total_power = (participants.len().max(1) as u128) * 100;
        let mut supporting_power = ((total_power as f64) * ratio).round() as u128;
        supporting_power = supporting_power.clamp(1, total_power);

        AggregatedVote {
            block_id,
            epoch: 0,
            vote_type: VoteType::Commit,
            aggregated_signature: AggregatedSignature {
                signature: aggregated_signature.to_bytes(),
                participants: participants.to_vec(),
                supporting_voting_power: supporting_power,
                total_voting_power: total_power,
                quorum_threshold: consensus.test_quorum_threshold(),
            },
        }
    }

    #[tokio::test]
    async fn optimized_initialization_runs() {
        let (_dir_guard, storage) = setup_storage();
        let consensus = FlowConsensus::new_optimized(protocol_params(), storage)
            .await
            .expect("optimized consensus should initialize");

        let parent_hash = consensus.get_parent_hash().await;
        assert_eq!(
            parent_hash,
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[tokio::test]
    async fn processes_transactions_without_error() {
        let (_dir_guard, storage) = setup_storage();
        let consensus = FlowConsensus::new_async(protocol_params(), storage)
            .await
            .expect("consensus should initialize with clean storage");

        for _ in 0..3 {
            consensus
                .process_transaction(sample_transaction())
                .await
                .expect("transaction should be accepted into the pending queue");
        }

        let block_hash =
            consensus.calculate_block_hash(2, 2_468, "root", "parent", "validator", 84);
        assert!(block_hash.starts_with("0x"));
        assert_eq!(block_hash.len(), 66);
    }

    #[tokio::test]
    async fn applies_pending_finality_summary_after_remote_block() {
        let (_dir_guard, storage) = setup_storage();
        let consensus = FlowConsensus::new_async(protocol_params(), storage)
            .await
            .expect("consensus should initialize");

        let block_id = BlockId::new(b"remote-block");
        let participants: Vec<ValidatorId> = (0..4).collect();
        let aggregated_vote = aggregated_vote_for_block(&consensus, block_id, &participants, 1.0);
        let summary = make_finality_summary(block_id, aggregated_vote.clone());

        consensus
            .handle_p2p_message(P2PNetworkMessage::FinalitySummary(summary))
            .await
            .expect("summary should be accepted for pending storage");

        assert_eq!(consensus.pending_finality_summary_count().await, 1);
        assert_eq!(consensus.remote_vote_count().await, 1);

        let block = make_block(block_id);
        let message = P2PNetworkMessage::Block {
            block_hash: block_id.0,
            block_data: serialize(&block).expect("block serialization"),
        };

        consensus
            .handle_p2p_message(message)
            .await
            .expect("remote block should be processed");

        assert_eq!(consensus.pending_finality_summary_count().await, 0);
        assert_eq!(consensus.remote_vote_count().await, 0);
    }

    #[tokio::test]
    async fn rejects_remote_vote_without_quorum() {
        let (_dir_guard, storage) = setup_storage();
        let consensus = FlowConsensus::new_async(protocol_params(), storage)
            .await
            .expect("consensus should initialize");

        let block_id = BlockId::new(b"insufficient-quorum");
        let participants: Vec<ValidatorId> = (0..4).collect();
        let aggregated_vote = aggregated_vote_for_block(&consensus, block_id, &participants, 0.4);

        let error = consensus
            .handle_p2p_message(P2PNetworkMessage::AggregatedVote {
                shard_id: 0,
                vote: aggregated_vote,
            })
            .await
            .expect_err("vote should be rejected due to quorum threshold");

        match error {
            AvoError::InvalidVote { .. } => {}
            other => panic!("unexpected error: {:?}", other),
        }

        assert_eq!(consensus.remote_vote_count().await, 0);
        assert_eq!(consensus.pending_finality_summary_count().await, 0);
    }

    #[tokio::test]
    async fn cross_shard_transaction_executes_with_zk() {
        let (_dir_guard, storage) = setup_storage();
        let consensus = FlowConsensus::new_async(protocol_params(), storage)
            .await
            .expect("consensus should initialize");

        let shard0_validators = consensus
            .create_real_validators_for_shard(0, 2)
            .await
            .expect("shard 0 validators");
        consensus
            .add_shard(shard_config(0, 2), shard0_validators)
            .await
            .expect("add shard 0");

        let shard1_validators = consensus
            .create_real_validators_for_shard(1, 2)
            .await
            .expect("shard 1 validators");
        consensus
            .add_shard(shard_config(1, 2), shard1_validators)
            .await
            .expect("add shard 1");

        let mut tx = sample_transaction();
        tx.id = TransactionId::new(b"cross-shard");
        tx.shard_id = 0;
        tx.cross_shard_deps = vec![1];

        consensus
            .process_transaction(tx.clone())
            .await
            .expect("cross-shard transaction should succeed");

        let state = consensus
            .get_consensus_state()
            .await
            .expect("consensus state");

        let op = state
            .pending_cross_shard_ops
            .iter()
            .find(|op| op.id == tx.id)
            .cloned()
            .expect("operation stored in state");

        assert!(matches!(
            op.status,
            CrossShardStatus::Committed | CrossShardStatus::Aborted
        ));
        assert!(op.state_changes.contains_key(&0));
        assert!(op.state_changes.contains_key(&1));
    }
}
