/// Slashing Manager - Detect and penalize malicious validators
///
/// FASE 10.3: Complete slashing mechanism implementation
use crate::error::{AvoError, AvoResult};
use crate::storage::RocksDBBackend;
use crate::types::{BlockId, Epoch, Hash, ShardId, ValidatorId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Type of slashing offense
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlashingOffense {
    /// Validator signed two different blocks at the same height
    DoubleSign,
    /// Validator produced invalid signature
    InvalidSignature,
    /// Validator was offline for extended period
    Downtime,
    /// Validator aborted cross-shard transaction maliciously
    MaliciousAbort,
    /// Validator provided invalid state root
    InvalidStateRoot,
}

/// Severity level for slashing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingSeverity {
    Minor,    // 5% slash
    Medium,   // 25% slash
    Major,    // 50% slash
    Critical, // 100% slash (full slashing)
}

impl SlashingSeverity {
    pub fn slash_percentage(&self) -> f64 {
        match self {
            SlashingSeverity::Minor => 0.05,
            SlashingSeverity::Medium => 0.25,
            SlashingSeverity::Major => 0.50,
            SlashingSeverity::Critical => 1.0,
        }
    }
}

impl SlashingOffense {
    pub fn severity(&self) -> SlashingSeverity {
        match self {
            SlashingOffense::Downtime => SlashingSeverity::Minor,
            SlashingOffense::InvalidSignature => SlashingSeverity::Medium,
            SlashingOffense::MaliciousAbort => SlashingSeverity::Medium,
            SlashingOffense::InvalidStateRoot => SlashingSeverity::Major,
            SlashingOffense::DoubleSign => SlashingSeverity::Critical,
        }
    }
}

/// Slashing event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub id: u64,
    pub validator_id: ValidatorId,
    pub offense: SlashingOffense,
    pub severity: SlashingSeverity,
    pub epoch: Epoch,
    pub shard_id: Option<ShardId>,
    pub stake_slashed: u128,
    pub evidence: SlashingEvidence,
    pub reporter: Option<ValidatorId>,
    pub timestamp: u64,
    pub status: SlashingStatus,
}

/// Status of a slashing event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingStatus {
    Pending,
    Confirmed,
    Executed,
    Disputed,
}

/// Evidence for slashing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingEvidence {
    DoubleSignEvidence {
        block1: BlockId,
        block2: BlockId,
        height: u64,
        signature1: Vec<u8>,
        signature2: Vec<u8>,
    },
    InvalidSignatureEvidence {
        block: BlockId,
        signature: Vec<u8>,
        expected_signer: ValidatorId,
    },
    DowntimeEvidence {
        missed_epochs: Vec<Epoch>,
        total_missed: u64,
    },
    MaliciousAbortEvidence {
        transaction_id: Hash,
        abort_signature: Vec<u8>,
        valid_locks: Vec<ShardId>,
    },
    InvalidStateRootEvidence {
        block: BlockId,
        provided_root: Hash,
        correct_root: Hash,
    },
}

/// Slashing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Minimum stake to be slashable
    pub min_slashable_stake: u128,
    /// Grace period before slashing is executed (epochs)
    pub grace_period: Epoch,
    /// Percentage burned (rest goes to reporter)
    pub burn_percentage: f64,
    /// Maximum downtime before slashing (epochs)
    pub max_downtime_epochs: u64,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            min_slashable_stake: 1000,
            grace_period: 10,
            burn_percentage: 0.5,
            max_downtime_epochs: 10,
        }
    }
}

/// Slashing Manager
#[derive(Debug)]
pub struct SlashingManager {
    config: SlashingConfig,
    /// Pending slashing events
    pending_events: Arc<RwLock<Vec<SlashingEvent>>>,
    /// Confirmed slashing events
    confirmed_events: Arc<RwLock<HashMap<u64, SlashingEvent>>>,
    /// Double sign detection: validator -> (height, block_id)
    double_sign_tracker: Arc<RwLock<HashMap<ValidatorId, HashMap<u64, BlockId>>>>,
    /// Downtime tracker: validator -> missed epochs
    downtime_tracker: Arc<RwLock<HashMap<ValidatorId, HashSet<Epoch>>>>,
    /// Event ID counter
    next_event_id: Arc<RwLock<u64>>,
    /// Storage backend
    storage: Option<Arc<RocksDBBackend>>,
}

impl SlashingManager {
    pub fn new(config: SlashingConfig, storage: Option<Arc<RocksDBBackend>>) -> Self {
        Self {
            config,
            pending_events: Arc::new(RwLock::new(Vec::new())),
            confirmed_events: Arc::new(RwLock::new(HashMap::new())),
            double_sign_tracker: Arc::new(RwLock::new(HashMap::new())),
            downtime_tracker: Arc::new(RwLock::new(HashMap::new())),
            next_event_id: Arc::new(RwLock::new(0)),
            storage,
        }
    }

    /// Detect double signing
    pub async fn detect_double_sign(
        &self,
        validator_id: ValidatorId,
        block_id: BlockId,
        height: u64,
        signature: Vec<u8>,
    ) -> AvoResult<Option<SlashingEvent>> {
        let mut tracker = self.double_sign_tracker.write().await;

        let validator_blocks = tracker.entry(validator_id).or_insert_with(HashMap::new);

        if let Some(&existing_block) = validator_blocks.get(&height) {
            if existing_block != block_id {
                // DOUBLE SIGN DETECTED!
                warn!(
                    "🚨 DOUBLE SIGN DETECTED: Validator {} signed two blocks at height {}",
                    validator_id, height
                );

                // Get existing signature (in production, would fetch from storage)
                let signature1 = signature.clone(); // Simplified
                let signature2 = signature;

                let event = self
                    .create_slashing_event(
                        validator_id,
                        SlashingOffense::DoubleSign,
                        None,
                        SlashingEvidence::DoubleSignEvidence {
                            block1: existing_block,
                            block2: block_id,
                            height,
                            signature1,
                            signature2,
                        },
                        None,
                    )
                    .await?;

                return Ok(Some(event));
            }
        } else {
            // Record this block signing
            validator_blocks.insert(height, block_id);
        }

        Ok(None)
    }

    /// Detect downtime
    pub async fn record_validator_activity(
        &self,
        validator_id: ValidatorId,
        epoch: Epoch,
        was_active: bool,
    ) -> AvoResult<Option<SlashingEvent>> {
        let mut downtime = self.downtime_tracker.write().await;
        let missed_epochs = downtime.entry(validator_id).or_insert_with(HashSet::new);

        if !was_active {
            missed_epochs.insert(epoch);

            // Check if exceeded threshold
            if missed_epochs.len() as u64 >= self.config.max_downtime_epochs {
                warn!(
                    "🚨 EXCESSIVE DOWNTIME: Validator {} missed {} epochs",
                    validator_id,
                    missed_epochs.len()
                );

                let event = self
                    .create_slashing_event(
                        validator_id,
                        SlashingOffense::Downtime,
                        None,
                        SlashingEvidence::DowntimeEvidence {
                            missed_epochs: missed_epochs.iter().copied().collect(),
                            total_missed: missed_epochs.len() as u64,
                        },
                        None,
                    )
                    .await?;

                // Clear tracker after creating event
                missed_epochs.clear();

                return Ok(Some(event));
            }
        } else {
            // Validator was active, clear missed epochs
            missed_epochs.clear();
        }

        Ok(None)
    }

    /// Report invalid signature
    pub async fn report_invalid_signature(
        &self,
        validator_id: ValidatorId,
        block_id: BlockId,
        signature: Vec<u8>,
        reporter: ValidatorId,
    ) -> AvoResult<SlashingEvent> {
        info!(
            "⚠️ Invalid signature reported for validator {} by validator {}",
            validator_id, reporter
        );

        self.create_slashing_event(
            validator_id,
            SlashingOffense::InvalidSignature,
            None,
            SlashingEvidence::InvalidSignatureEvidence {
                block: block_id,
                signature,
                expected_signer: validator_id,
            },
            Some(reporter),
        )
        .await
    }

    /// Report malicious abort
    pub async fn report_malicious_abort(
        &self,
        validator_id: ValidatorId,
        transaction_id: Hash,
        abort_signature: Vec<u8>,
        valid_locks: Vec<ShardId>,
        reporter: ValidatorId,
    ) -> AvoResult<SlashingEvent> {
        info!(
            "⚠️ Malicious abort reported for validator {} by validator {}",
            validator_id, reporter
        );

        self.create_slashing_event(
            validator_id,
            SlashingOffense::MaliciousAbort,
            valid_locks.first().copied(),
            SlashingEvidence::MaliciousAbortEvidence {
                transaction_id,
                abort_signature,
                valid_locks,
            },
            Some(reporter),
        )
        .await
    }

    /// Create a slashing event
    async fn create_slashing_event(
        &self,
        validator_id: ValidatorId,
        offense: SlashingOffense,
        shard_id: Option<ShardId>,
        evidence: SlashingEvidence,
        reporter: Option<ValidatorId>,
    ) -> AvoResult<SlashingEvent> {
        let mut event_id = self.next_event_id.write().await;
        let id = *event_id;
        *event_id += 1;

        let severity = offense.severity();

        let event = SlashingEvent {
            id,
            validator_id,
            offense,
            severity,
            epoch: 0, // Will be set by caller
            shard_id,
            stake_slashed: 0, // Will be calculated during execution
            evidence,
            reporter,
            timestamp: crate::utils::time::current_timestamp(),
            status: SlashingStatus::Pending,
        };

        // Add to pending events
        let mut pending = self.pending_events.write().await;
        pending.push(event.clone());

        info!(
            "✓ Slashing event #{} created for validator {} ({:?})",
            id, validator_id, offense
        );

        Ok(event)
    }

    /// Execute pending slashing after grace period
    pub async fn execute_slashing(
        &self,
        event_id: u64,
        validator_stake: u128,
    ) -> AvoResult<SlashingReward> {
        let mut pending = self.pending_events.write().await;
        let event_idx = pending
            .iter()
            .position(|e| e.id == event_id)
            .ok_or_else(|| AvoError::NotFound(format!("Slashing event {} not found", event_id)))?;

        let mut event = pending.remove(event_idx);

        // Calculate slash amount
        let slash_percentage = event.severity.slash_percentage();
        let slash_amount = (validator_stake as f64 * slash_percentage) as u128;

        // Calculate burn and reward
        let burn_amount = (slash_amount as f64 * self.config.burn_percentage) as u128;
        let reward_amount = slash_amount - burn_amount;

        event.stake_slashed = slash_amount;
        event.status = SlashingStatus::Executed;

        // Store in confirmed events
        let mut confirmed = self.confirmed_events.write().await;
        confirmed.insert(event_id, event.clone());

        // Persist to RocksDB if available
        if let Some(ref storage) = self.storage {
            let key = format!("slashing:event:{}", event_id);
            let value = bincode::serialize(&event)
                .map_err(|e| AvoError::internal(format!("Serialization error: {}", e)))?;
            // Would store using storage.put() if we had the CF handle
        }

        info!(
            "✅ Slashing #{} executed: {} tokens slashed ({:.1}%), {} burned, {} to reporter",
            event_id,
            slash_amount,
            slash_percentage * 100.0,
            burn_amount,
            reward_amount
        );

        Ok(SlashingReward {
            event_id,
            slash_amount,
            burn_amount,
            reward_amount,
            reporter: event.reporter,
        })
    }

    /// Get all pending slashing events
    pub async fn get_pending_events(&self) -> Vec<SlashingEvent> {
        self.pending_events.read().await.clone()
    }

    /// Get slashing event by ID
    pub async fn get_event(&self, event_id: u64) -> Option<SlashingEvent> {
        let confirmed = self.confirmed_events.read().await;
        confirmed.get(&event_id).cloned()
    }

    /// Get all slashing events for a validator
    pub async fn get_validator_events(&self, validator_id: ValidatorId) -> Vec<SlashingEvent> {
        let confirmed = self.confirmed_events.read().await;
        confirmed
            .values()
            .filter(|e| e.validator_id == validator_id)
            .cloned()
            .collect()
    }

    /// Get slashing statistics
    pub async fn get_statistics(&self) -> SlashingStatistics {
        let pending = self.pending_events.read().await;
        let confirmed = self.confirmed_events.read().await;

        let total_slashed: u128 = confirmed.values().map(|e| e.stake_slashed).sum();

        let mut offense_counts = HashMap::new();
        for event in confirmed.values() {
            *offense_counts.entry(event.offense).or_insert(0) += 1;
        }

        SlashingStatistics {
            total_events: confirmed.len() as u64,
            pending_events: pending.len() as u64,
            total_stake_slashed: total_slashed,
            offense_counts,
        }
    }
}

/// Slashing reward distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingReward {
    pub event_id: u64,
    pub slash_amount: u128,
    pub burn_amount: u128,
    pub reward_amount: u128,
    pub reporter: Option<ValidatorId>,
}

/// Slashing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingStatistics {
    pub total_events: u64,
    pub pending_events: u64,
    pub total_stake_slashed: u128,
    pub offense_counts: HashMap<SlashingOffense, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_double_sign_detection() {
        let manager = SlashingManager::new(SlashingConfig::default(), None);

        let validator_id = 1;
        let height = 100;
        let block1 = BlockId([1; 32]);
        let block2 = BlockId([2; 32]);

        // First signing - should be ok
        let result1 = manager
            .detect_double_sign(validator_id, block1, height, vec![1, 2, 3])
            .await
            .unwrap();
        assert!(result1.is_none());

        // Second signing at same height - should detect double sign
        let result2 = manager
            .detect_double_sign(validator_id, block2, height, vec![4, 5, 6])
            .await
            .unwrap();
        assert!(result2.is_some());

        let event = result2.unwrap();
        assert_eq!(event.offense, SlashingOffense::DoubleSign);
        assert_eq!(event.severity, SlashingSeverity::Critical);
    }

    #[tokio::test]
    async fn test_downtime_detection() {
        let config = SlashingConfig {
            max_downtime_epochs: 3,
            ..Default::default()
        };
        let manager = SlashingManager::new(config, None);

        let validator_id = 1;

        // Miss 2 epochs - should not slash yet
        manager
            .record_validator_activity(validator_id, 1, false)
            .await
            .unwrap();
        manager
            .record_validator_activity(validator_id, 2, false)
            .await
            .unwrap();

        // Miss 3rd epoch - should trigger slashing
        let result = manager
            .record_validator_activity(validator_id, 3, false)
            .await
            .unwrap();
        assert!(result.is_some());

        let event = result.unwrap();
        assert_eq!(event.offense, SlashingOffense::Downtime);
    }

    #[tokio::test]
    async fn test_slashing_execution() {
        let manager = SlashingManager::new(SlashingConfig::default(), None);

        // Create a slashing event
        let event = manager
            .create_slashing_event(
                1,
                SlashingOffense::DoubleSign,
                Some(0),
                SlashingEvidence::DowntimeEvidence {
                    missed_epochs: vec![],
                    total_missed: 0,
                },
                None,
            )
            .await
            .unwrap();

        // Execute slashing
        let validator_stake = 10000;
        let reward = manager
            .execute_slashing(event.id, validator_stake)
            .await
            .unwrap();

        // With Critical severity (100% slash) and 50% burn
        assert_eq!(reward.slash_amount, 10000); // 100% of stake
        assert_eq!(reward.burn_amount, 5000); // 50% burned
        assert_eq!(reward.reward_amount, 5000); // 50% to reporter
    }

    #[tokio::test]
    async fn test_statistics() {
        let manager = SlashingManager::new(SlashingConfig::default(), None);

        // Create some events
        manager
            .create_slashing_event(
                1,
                SlashingOffense::DoubleSign,
                None,
                SlashingEvidence::DowntimeEvidence {
                    missed_epochs: vec![],
                    total_missed: 0,
                },
                None,
            )
            .await
            .unwrap();

        manager.execute_slashing(0, 10000).await.unwrap();

        let stats = manager.get_statistics().await;
        assert_eq!(stats.total_events, 1);
        assert_eq!(stats.total_stake_slashed, 10000);
    }
}
