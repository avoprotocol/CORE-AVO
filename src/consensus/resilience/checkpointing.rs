use crate::consensus::hybrid_clock::HlcTimestamp;
use crate::crypto::bls_signatures::{
    AggregatedBlsSignature, BlsAggregator, BlsPrivateKey, BlsPublicKey,
};
use crate::error::{AvoError, AvoResult};
use crate::state::storage::AvocadoStorage;
use crate::types::{Epoch, ValidatorId};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckpointStatus {
    Pending,
    Finalized,
    Challenged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRecord {
    pub epoch: Epoch,
    pub block_number: u64,
    pub block_hash: String,
    pub state_root: String,
    pub hlc_physical_micros: u64,
    pub hlc_logical: u64,
    pub aggregated_signature: AggregatedBlsSignature,
    pub signer_count: usize,
    pub status: CheckpointStatus,
    pub submitted_at: u64,
    pub challenge_deadline: u64,
    pub finalized_at: Option<u64>,
    pub challenge_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitProof {
    pub checkpoint: CheckpointRecord,
    pub validator_id: ValidatorId,
}

#[derive(Debug)]
pub struct CheckpointManager {
    storage: Arc<AvocadoStorage>,
    validator_keys: Arc<RwLock<HashMap<ValidatorId, (BlsPrivateKey, BlsPublicKey)>>>,
    challenge_window: Duration,
    pending: Arc<RwLock<VecDeque<CheckpointRecord>>>,
    finalized: Arc<RwLock<VecDeque<CheckpointRecord>>>,
}

impl CheckpointManager {
    pub fn new(
        storage: Arc<AvocadoStorage>,
        validator_keys: HashMap<ValidatorId, (BlsPrivateKey, BlsPublicKey)>,
        challenge_window: Duration,
    ) -> Self {
        Self {
            storage,
            validator_keys: Arc::new(RwLock::new(validator_keys)),
            challenge_window,
            pending: Arc::new(RwLock::new(VecDeque::new())),
            finalized: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    pub async fn set_validator_keys(
        &self,
        keys: HashMap<ValidatorId, (BlsPrivateKey, BlsPublicKey)>,
    ) {
        *self.validator_keys.write().await = keys;
    }

    pub async fn submit_checkpoint(
        &self,
        epoch: Epoch,
        block_number: u64,
        block_hash: String,
        state_root: String,
        timestamp: HlcTimestamp,
    ) -> AvoResult<CheckpointRecord> {
        let message =
            self.build_checkpoint_message(epoch, block_number, &block_hash, &state_root, timestamp);

        let keys_guard = self.validator_keys.read().await;
        if keys_guard.is_empty() {
            return Err(AvoError::crypto(
                "No validator keys available for checkpoint signing",
            ));
        }

        let mut signatures = Vec::with_capacity(keys_guard.len());
        let mut public_keys = Vec::with_capacity(keys_guard.len());

        for (_id, (private_key, public_key)) in keys_guard.iter() {
            let signature = private_key.sign(&message)?;
            signatures.push(signature);
            public_keys.push(public_key.clone());
        }

        let aggregated_signature =
            BlsAggregator::create_aggregated_signature(signatures, public_keys, &message)?;

        let record = CheckpointRecord {
            epoch,
            block_number,
            block_hash,
            state_root,
            hlc_physical_micros: timestamp.physical_micros(),
            hlc_logical: timestamp.logical_counter(),
            aggregated_signature,
            signer_count: keys_guard.len(),
            status: CheckpointStatus::Pending,
            submitted_at: current_unix_millis(),
            challenge_deadline: current_unix_millis()
                .saturating_add(self.challenge_window.as_millis() as u64),
            finalized_at: None,
            challenge_reason: None,
        };

        drop(keys_guard);

        self.persist_checkpoint(&record).await?;
        self.pending.write().await.push_back(record.clone());

        info!(
            "✅ Checkpoint submitted | block={} epoch={} signers={} deadline={}",
            record.block_number, record.epoch, record.signer_count, record.challenge_deadline
        );

        Ok(record)
    }

    pub async fn finalize_due_checkpoints(&self) -> AvoResult<Vec<CheckpointRecord>> {
        let mut pending = self.pending.write().await;
        let mut finalized = Vec::new();
        let now = current_unix_millis();

        pending.retain(|checkpoint| {
            if checkpoint.status != CheckpointStatus::Pending {
                return true;
            }

            if checkpoint.challenge_deadline <= now {
                let mut finalized_checkpoint = checkpoint.clone();
                finalized_checkpoint.status = CheckpointStatus::Finalized;
                finalized_checkpoint.finalized_at = Some(now);
                finalized.push(finalized_checkpoint.clone());
                false
            } else {
                true
            }
        });

        drop(pending);

        if finalized.is_empty() {
            return Ok(Vec::new());
        }

        let mut finalized_queue = self.finalized.write().await;
        for checkpoint in finalized.iter() {
            finalized_queue.push_back(checkpoint.clone());
            self.persist_checkpoint(checkpoint).await?;
        }

        Ok(finalized)
    }

    pub async fn challenge_checkpoint(
        &self,
        block_number: u64,
        reason: String,
    ) -> AvoResult<Option<CheckpointRecord>> {
        let mut pending = self.pending.write().await;
        if let Some(pos) = pending
            .iter()
            .position(|cp| cp.block_number == block_number)
        {
            let mut checkpoint = pending.remove(pos).unwrap();
            checkpoint.status = CheckpointStatus::Challenged;
            checkpoint.challenge_reason = Some(reason.clone());
            self.persist_checkpoint(&checkpoint).await?;
            warn!(
                "⚠️ Checkpoint challenged | block={} reason={}",
                block_number, reason
            );
            return Ok(Some(checkpoint));
        }

        Ok(None)
    }

    pub async fn latest_finalized(&self) -> Option<CheckpointRecord> {
        self.finalized.read().await.back().cloned()
    }

    pub async fn produce_exit_proof(
        &self,
        validator_id: ValidatorId,
    ) -> AvoResult<Option<ExitProof>> {
        let finalized = self.latest_finalized().await;
        match finalized {
            Some(checkpoint) => {
                let validator_keys = self.validator_keys.read().await;
                let total_validators = validator_keys.len();
                let min_signers = ((total_validators as f64) * (2.0 / 3.0)).ceil() as usize;
                drop(validator_keys);

                if checkpoint.signer_count < min_signers {
                    return Err(AvoError::crypto(
                        "Finalized checkpoint does not meet quorum requirements",
                    ));
                }

                Ok(Some(ExitProof {
                    checkpoint,
                    validator_id,
                }))
            }
            None => Ok(None),
        }
    }

    async fn persist_checkpoint(&self, checkpoint: &CheckpointRecord) -> AvoResult<()> {
        let key = match checkpoint.status {
            CheckpointStatus::Pending | CheckpointStatus::Challenged => {
                format!("checkpoint:pending:{}", checkpoint.block_number)
            }
            CheckpointStatus::Finalized => {
                format!("checkpoint:finalized:{}", checkpoint.block_number)
            }
        };

        let bytes = serde_json::to_vec(checkpoint)
            .map_err(|e| AvoError::storage(format!("Failed to serialize checkpoint: {}", e)))?;
        self.storage.store_state(&key, &bytes).await
    }

    fn build_checkpoint_message(
        &self,
        epoch: Epoch,
        block_number: u64,
        block_hash: &str,
        state_root: &str,
        timestamp: HlcTimestamp,
    ) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(epoch.to_le_bytes());
        hasher.update(block_number.to_le_bytes());
        hasher.update(block_hash.as_bytes());
        hasher.update(state_root.as_bytes());
        hasher.update(timestamp.physical_micros().to_le_bytes());
        hasher.update(timestamp.logical_counter().to_le_bytes());
        hasher.finalize().to_vec()
    }
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[tokio::test]
    async fn checkpoint_submission_and_finalization() {
        let storage = Arc::new(
            AvocadoStorage::new(crate::state::storage::StorageConfig::with_path(
                "./.tmp_checkpoints",
            ))
            .expect("failed to init storage"),
        );
        let mut rng = StdRng::seed_from_u64(42);
        let mut validator_keys = HashMap::new();
        for validator in 0..4 {
            let (priv_key, pub_key) =
                crate::crypto::bls_signatures::BlsKeyGenerator::generate_keypair(&mut rng);
            validator_keys.insert(validator as ValidatorId, (priv_key, pub_key));
        }

        let manager = CheckpointManager::new(storage, validator_keys, Duration::from_millis(10));
        let timestamp = HlcTimestamp::new(1_000_000, 0);
        let checkpoint = manager
            .submit_checkpoint(1, 100, "0xabc".to_string(), "0xdef".to_string(), timestamp)
            .await
            .expect("submit checkpoint");

        assert_eq!(checkpoint.status, CheckpointStatus::Pending);

        tokio::time::sleep(Duration::from_millis(15)).await;
        let finalized = manager
            .finalize_due_checkpoints()
            .await
            .expect("finalize checkpoints");

        assert_eq!(finalized.len(), 1);
        assert_eq!(finalized[0].status, CheckpointStatus::Finalized);
    }
}
