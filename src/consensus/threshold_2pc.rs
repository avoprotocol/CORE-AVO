//! # Threshold Encryption for Cross-Shard 2PC
//!
//! FASE 11.2: Integration of threshold encryption with two-phase commit protocol
//! for secure cross-shard transactions. Prevents MEV by keeping transaction details
//! encrypted until commit phase.

use crate::crypto::{
    ThresholdCiphertext, ThresholdDecryptionShare, ThresholdKeyGenerator, ThresholdKeyShare,
    ThresholdMasterKey,
};
use crate::error::{AvoError, AvoResult};
use crate::types::{Epoch, ShardId, Transaction, TransactionId, ValidatorId};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for threshold 2PC
#[derive(Debug, Clone)]
pub struct Threshold2PCConfig {
    /// Minimum number of shards that must decrypt for commit
    pub threshold: usize,
    /// Total number of participating shards
    pub total_shards: usize,
    /// Epoch duration for key rotation
    pub key_rotation_epochs: u64,
}

impl Default for Threshold2PCConfig {
    fn default() -> Self {
        Self {
            threshold: 3, // Need 3 out of 4 shards minimum
            total_shards: 4,
            key_rotation_epochs: 100, // Rotate keys every 100 epochs
        }
    }
}

/// Encrypted cross-shard transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCrossShardTx {
    pub tx_id: TransactionId,
    pub encrypted_data: ThresholdCiphertext,
    pub involved_shards: Vec<ShardId>,
    pub epoch: Epoch,
}

/// Decryption share for a cross-shard transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardDecryptionShare {
    pub tx_id: TransactionId,
    pub shard_id: ShardId,
    pub share: ThresholdDecryptionShare,
}

/// State of a threshold 2PC transaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Threshold2PCState {
    /// Encrypted and waiting for prepare votes
    Encrypted,
    /// Prepare phase: gathering decryption shares
    Preparing { shares_received: usize },
    /// Ready to commit: threshold met
    ReadyToCommit,
    /// Committed and finalized
    Committed,
    /// Aborted
    Aborted,
}

/// Tracker for a threshold 2PC transaction
#[derive(Debug, Clone)]
struct Threshold2PCTracker {
    encrypted_tx: EncryptedCrossShardTx,
    state: Threshold2PCState,
    decryption_shares: HashMap<ShardId, ThresholdDecryptionShare>,
    decrypted_tx: Option<Transaction>,
}

/// Manager for threshold encryption in 2PC
pub struct Threshold2PCManager {
    config: Threshold2PCConfig,
    master_key: ThresholdMasterKey,
    shard_keys: HashMap<ShardId, ThresholdKeyShare>,
    active_transactions: Arc<RwLock<HashMap<TransactionId, Threshold2PCTracker>>>,
    current_epoch: Arc<RwLock<Epoch>>,
}

impl Threshold2PCManager {
    /// Create a new threshold 2PC manager
    pub fn new(config: Threshold2PCConfig) -> AvoResult<Self> {
        let mut rng = OsRng;

        // Generate threshold keys for shards
        let shard_ids: Vec<ValidatorId> = (0..config.total_shards)
            .map(|id| id as ValidatorId)
            .collect();
        let (master_key, validator_keys) =
            ThresholdKeyGenerator::generate_validator_threshold_keys(
                &mut rng,
                &shard_ids,
                config.threshold,
            )?;

        // Map validator IDs to shard IDs
        let shard_keys: HashMap<ShardId, ThresholdKeyShare> = validator_keys
            .into_iter()
            .map(|(validator_id, key_share)| (validator_id as ShardId, key_share))
            .collect();

        Ok(Self {
            config,
            master_key,
            shard_keys,
            active_transactions: Arc::new(RwLock::new(HashMap::new())),
            current_epoch: Arc::new(RwLock::new(0)),
        })
    }

    /// Encrypt a cross-shard transaction
    pub async fn encrypt_transaction(
        &self,
        tx: &Transaction,
        involved_shards: Vec<ShardId>,
    ) -> AvoResult<EncryptedCrossShardTx> {
        let mut rng = OsRng;
        let current_epoch = *self.current_epoch.read().await;

        // Serialize transaction
        let tx_bytes = bincode::serialize(tx)?;

        // Encrypt using threshold encryption
        let encrypted_data = self.master_key.encrypt(&mut rng, &tx_bytes, current_epoch);

        let encrypted_tx = EncryptedCrossShardTx {
            tx_id: tx.id,
            encrypted_data,
            involved_shards,
            epoch: current_epoch,
        };

        // Track the transaction
        let mut active = self.active_transactions.write().await;
        active.insert(
            tx.id,
            Threshold2PCTracker {
                encrypted_tx: encrypted_tx.clone(),
                state: Threshold2PCState::Encrypted,
                decryption_shares: HashMap::new(),
                decrypted_tx: None,
            },
        );

        Ok(encrypted_tx)
    }

    /// Generate a decryption share for a shard
    pub async fn generate_decryption_share(
        &self,
        tx_id: TransactionId,
        shard_id: ShardId,
    ) -> AvoResult<CrossShardDecryptionShare> {
        let active = self.active_transactions.read().await;
        let tracker = active
            .get(&tx_id)
            .ok_or_else(|| AvoError::TransactionNotFound { tx_id: tx_id.0 })?;

        // Verify this shard is involved
        if !tracker.encrypted_tx.involved_shards.contains(&shard_id) {
            return Err(AvoError::consensus(format!(
                "Shard {} is not part of cross-shard transaction {:?}",
                shard_id, tx_id
            )));
        }

        // Get the key share for this shard
        let key_share = self.shard_keys.get(&shard_id).ok_or_else(|| {
            AvoError::consensus(format!(
                "Missing threshold key share for shard {}",
                shard_id
            ))
        })?;

        // Generate decryption share
        let share = key_share.create_decryption_share(&tracker.encrypted_tx.encrypted_data)?;

        Ok(CrossShardDecryptionShare {
            tx_id,
            shard_id,
            share,
        })
    }

    /// Add a decryption share from a shard
    pub async fn add_decryption_share(
        &self,
        share: CrossShardDecryptionShare,
    ) -> AvoResult<Threshold2PCState> {
        let mut active = self.active_transactions.write().await;
        let tracker =
            active
                .get_mut(&share.tx_id)
                .ok_or_else(|| AvoError::TransactionNotFound {
                    tx_id: share.tx_id.0,
                })?;

        // Verify the share is valid
        if !self
            .master_key
            .verify_decryption_share(&tracker.encrypted_tx.encrypted_data, &share.share)
        {
            return Err(AvoError::validation("Invalid threshold decryption share"));
        }

        // Add the share
        tracker
            .decryption_shares
            .insert(share.shard_id, share.share);

        // Update state
        let shares_count = tracker.decryption_shares.len();
        if shares_count >= self.config.threshold {
            // Try to decrypt
            if let Ok(decrypted) = self.try_decrypt(tracker).await {
                tracker.decrypted_tx = Some(decrypted);
                tracker.state = Threshold2PCState::ReadyToCommit;
            } else {
                tracker.state = Threshold2PCState::Preparing {
                    shares_received: shares_count,
                };
            }
        } else {
            tracker.state = Threshold2PCState::Preparing {
                shares_received: shares_count,
            };
        }

        Ok(tracker.state.clone())
    }

    /// Try to decrypt a transaction once threshold is met
    async fn try_decrypt(&self, tracker: &Threshold2PCTracker) -> AvoResult<Transaction> {
        if tracker.decryption_shares.len() < self.config.threshold {
            return Err(AvoError::consensus(
                "Not enough decryption shares to recover transaction",
            ));
        }

        // Collect shares in the correct order
        let shares: Vec<_> = tracker.decryption_shares.values().cloned().collect();

        // Decrypt using threshold decryption
        let plaintext = self
            .master_key
            .combine_decryption_shares(&tracker.encrypted_tx.encrypted_data, &shares)?;

        // Deserialize transaction
        let tx: Transaction = bincode::deserialize(&plaintext)?;

        Ok(tx)
    }

    /// Get the decrypted transaction if threshold is met
    pub async fn get_decrypted_transaction(
        &self,
        tx_id: TransactionId,
    ) -> AvoResult<Option<Transaction>> {
        let active = self.active_transactions.read().await;
        let tracker = active
            .get(&tx_id)
            .ok_or_else(|| AvoError::TransactionNotFound { tx_id: tx_id.0 })?;

        Ok(tracker.decrypted_tx.clone())
    }

    /// Mark a transaction as committed
    pub async fn commit_transaction(&self, tx_id: TransactionId) -> AvoResult<()> {
        let mut active = self.active_transactions.write().await;
        if let Some(tracker) = active.get_mut(&tx_id) {
            if tracker.state != Threshold2PCState::ReadyToCommit {
                return Err(AvoError::consensus(format!(
                    "Cannot commit transaction {:?} in state {:?}",
                    tx_id, tracker.state
                )));
            }
            tracker.state = Threshold2PCState::Committed;
        }
        Ok(())
    }

    /// Abort a transaction
    pub async fn abort_transaction(&self, tx_id: TransactionId) -> AvoResult<()> {
        let mut active = self.active_transactions.write().await;
        if let Some(tracker) = active.get_mut(&tx_id) {
            tracker.state = Threshold2PCState::Aborted;
        }
        Ok(())
    }

    /// Get the state of a transaction
    pub async fn get_transaction_state(&self, tx_id: TransactionId) -> Option<Threshold2PCState> {
        self.active_transactions
            .read()
            .await
            .get(&tx_id)
            .map(|t| t.state.clone())
    }

    /// Advance to a new epoch (triggers key rotation if needed)
    pub async fn advance_epoch(&self, new_epoch: Epoch) -> AvoResult<()> {
        let mut current = self.current_epoch.write().await;
        *current = new_epoch;

        // Check if we need to rotate keys
        if new_epoch % self.config.key_rotation_epochs == 0 {
            tracing::info!("🔄 Epoch {}: Key rotation checkpoint", new_epoch);
            // In a real implementation, we would perform DKG here
            // For now, we just log the checkpoint
        }

        Ok(())
    }

    /// Clean up old committed/aborted transactions
    pub async fn cleanup_old_transactions(&self, before_epoch: Epoch) -> usize {
        let mut active = self.active_transactions.write().await;
        let before_count = active.len();

        active.retain(|_, tracker| {
            tracker.encrypted_tx.epoch >= before_epoch
                && (tracker.state != Threshold2PCState::Committed
                    && tracker.state != Threshold2PCState::Aborted)
        });

        before_count - active.len()
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> Threshold2PCStatistics {
        let active = self.active_transactions.read().await;

        let mut by_state: HashMap<String, usize> = HashMap::new();
        for tracker in active.values() {
            let state_name = format!("{:?}", tracker.state);
            *by_state.entry(state_name).or_insert(0) += 1;
        }

        Threshold2PCStatistics {
            total_active: active.len(),
            current_epoch: *self.current_epoch.read().await,
            transactions_by_state: by_state,
            threshold: self.config.threshold,
            total_shards: self.config.total_shards,
        }
    }
}

/// Statistics for threshold 2PC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threshold2PCStatistics {
    pub total_active: usize,
    pub current_epoch: Epoch,
    pub transactions_by_state: HashMap<String, usize>,
    pub threshold: usize,
    pub total_shards: usize,
}

#[cfg(all(test, feature = "run-tests"))]
mod tests {
    use super::*;
    use crate::types::{Address, TransactionType};

    fn create_test_transaction() -> Transaction {
        Transaction {
            id: TransactionId::zero(),
            from: Address([1u8; 20]),
            to: Some(Address([2u8; 20])),
            value: 1000,
            nonce: 0,
            gas_limit: 21000,
            gas_price: 1_000_000_000,
            data: Some(vec![]),
            signature: vec![0; 64],
            parents: vec![],
            shard_id: 0,
            cross_shard_deps: vec![],
            transaction_type: TransactionType::Transfer,
        }
    }

    #[tokio::test]
    async fn test_threshold_2pc_creation() {
        let config = Threshold2PCConfig::default();
        let manager = Threshold2PCManager::new(config).unwrap();

        let stats = manager.get_statistics().await;
        assert_eq!(stats.total_active, 0);
        assert_eq!(stats.threshold, 3);
    }

    #[tokio::test]
    async fn test_encrypt_transaction() {
        let config = Threshold2PCConfig::default();
        let manager = Threshold2PCManager::new(config).unwrap();

        let tx = create_test_transaction();
        let involved_shards = vec![0, 1, 2, 3];

        let encrypted = manager
            .encrypt_transaction(&tx, involved_shards.clone())
            .await
            .unwrap();

        assert_eq!(encrypted.tx_id, tx.id);
        assert_eq!(encrypted.involved_shards, involved_shards);

        let state = manager.get_transaction_state(tx.id).await;
        assert_eq!(state, Some(Threshold2PCState::Encrypted));
    }

    #[tokio::test]
    async fn test_threshold_decryption() {
        let config = Threshold2PCConfig {
            threshold: 2,
            total_shards: 4,
            key_rotation_epochs: 100,
        };
        let manager = Threshold2PCManager::new(config).unwrap();

        let tx = create_test_transaction();
        let involved_shards = vec![0, 1, 2, 3];

        // Encrypt
        let encrypted = manager
            .encrypt_transaction(&tx, involved_shards)
            .await
            .unwrap();

        // Generate shares from 3 shards (exceeds threshold of 2)
        for shard_id in 0..3 {
            let share = manager
                .generate_decryption_share(tx.id, shard_id)
                .await
                .unwrap();

            let state = manager.add_decryption_share(share).await.unwrap();

            if shard_id >= 1 {
                // After 2 shares, should be ready
                assert_eq!(state, Threshold2PCState::ReadyToCommit);
            }
        }

        // Should be able to get decrypted transaction
        let decrypted = manager.get_decrypted_transaction(tx.id).await.unwrap();
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap().id, tx.id);
    }

    #[tokio::test]
    async fn test_commit_and_cleanup() {
        let config = Threshold2PCConfig::default();
        let manager = Threshold2PCManager::new(config).unwrap();

        let tx = create_test_transaction();
        manager
            .encrypt_transaction(&tx, vec![0, 1, 2, 3])
            .await
            .unwrap();

        // Generate enough shares
        for shard_id in 0..3 {
            let share = manager
                .generate_decryption_share(tx.id, shard_id)
                .await
                .unwrap();
            manager.add_decryption_share(share).await.unwrap();
        }

        // Commit
        manager.commit_transaction(tx.id).await.unwrap();

        let state = manager.get_transaction_state(tx.id).await;
        assert_eq!(state, Some(Threshold2PCState::Committed));

        // Advance epoch and cleanup
        manager.advance_epoch(200).await.unwrap();
        let cleaned = manager.cleanup_old_transactions(0).await;
        assert_eq!(cleaned, 1);
    }
}
