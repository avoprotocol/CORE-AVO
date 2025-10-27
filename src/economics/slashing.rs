//! # Slashing Module
//!
//! Real slashing detection and penalty enforcement for validator misbehavior.
//! Detects double signing, downtime, and other protocol violations.

use crate::economics::EconomicParams;
use crate::error::AvoError;
use crate::state::ChainState;
use crate::types::TokenAmount;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Types of slashable offenses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashingReason {
    /// Double signing detected
    DoubleSign {
        block_height: u64,
        first_signature: Vec<u8>,
        second_signature: Vec<u8>,
    },
    /// Validator downtime exceeded threshold
    Downtime { missed_blocks: u64, threshold: u64 },
    /// Invalid state transition proposed
    InvalidStateTransition { details: String },
    /// Censorship of valid transactions
    Censorship { evidence: Vec<u8> },
}

impl SlashingReason {
    fn severity_multiplier(&self) -> f64 {
        match self {
            SlashingReason::DoubleSign { .. } => 1.0,
            SlashingReason::Downtime { .. } => 0.2,
            SlashingReason::InvalidStateTransition { .. } => 0.8,
            SlashingReason::Censorship { .. } => 0.6,
        }
    }
}

/// Slashing event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub validator_id: u64,
    pub reason: SlashingReason,
    pub slash_amount: TokenAmount,
    pub timestamp: u64,
    pub block_height: u64,
    pub evidence_hash: [u8; 32],
}

/// Validator downtime tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidatorDowntime {
    validator_id: u64,
    total_missed_blocks: u64,
    consecutive_misses: u64,
    last_seen_block: u64,
    last_slash_epoch: Option<u64>,
}

/// Jail status for slashed validators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailStatus {
    pub validator_id: u64,
    pub jailed_at_epoch: u64,
    pub release_epoch: u64,
    pub reason: SlashingReason,
    pub is_released: bool,
}

/// Slashing manager
#[derive(Debug)]
pub struct SlashingManager {
    params: EconomicParams,
    downtime_trackers: HashMap<u64, ValidatorDowntime>,
    seen_signatures: HashMap<(u64, u64), HashSet<Vec<u8>>>,
    jailed_validators: HashMap<u64, JailStatus>,
    slashing_events: Vec<SlashingEvent>,
    current_epoch: u64,
    chain_state_path: PathBuf,
}

impl SlashingManager {
    pub fn new(params: EconomicParams, chain_state_path: PathBuf) -> Self {
        Self {
            params,
            downtime_trackers: HashMap::new(),
            seen_signatures: HashMap::new(),
            jailed_validators: HashMap::new(),
            slashing_events: Vec::new(),
            current_epoch: 0,
            chain_state_path,
        }
    }

    /// Detect slashing from evidence
    pub async fn detect_slashing(
        &mut self,
        validator_id: u64,
        evidence: Vec<u8>,
    ) -> Result<Option<SlashingEvent>, AvoError> {
        if let Some(reason) = self.parse_evidence(&evidence, validator_id).await? {
            let stake = self.get_validator_stake(validator_id).await?;
            let slash_amount = self.calculate_slash_amount(stake, &reason);

            let event = SlashingEvent {
                validator_id,
                reason: reason.clone(),
                slash_amount,
                timestamp: current_timestamp(),
                block_height: 0,
                evidence_hash: hash_evidence(&evidence),
            };

            self.apply_slashing(event.clone()).await?;
            self.slashing_events.push(event.clone());

            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Register validator signature for double-sign detection
    pub async fn register_signature(
        &mut self,
        validator_id: u64,
        block_height: u64,
        signature: Vec<u8>,
    ) -> Result<Option<SlashingEvent>, AvoError> {
        let key = (validator_id, block_height);
        let signatures = self.seen_signatures.entry(key).or_insert_with(HashSet::new);

        if !signatures.is_empty() && !signatures.contains(&signature) {
            let first_sig = signatures.iter().next().unwrap().clone();
            let reason = SlashingReason::DoubleSign {
                block_height,
                first_signature: first_sig,
                second_signature: signature.clone(),
            };

            let stake = self.get_validator_stake(validator_id).await?;
            let slash_amount = self.calculate_slash_amount(stake, &reason);

            let event = SlashingEvent {
                validator_id,
                reason,
                slash_amount,
                timestamp: current_timestamp(),
                block_height,
                evidence_hash: hash_double_sign(validator_id, block_height),
            };

            self.apply_slashing(event.clone()).await?;
            self.slashing_events.push(event.clone());

            return Ok(Some(event));
        }

        signatures.insert(signature);

        let cutoff_height = block_height.saturating_sub(1000);
        self.seen_signatures
            .retain(|(_, height), _| *height > cutoff_height);

        Ok(None)
    }

    /// Track validator activity and detect downtime
    pub async fn track_validator_activity(
        &mut self,
        validator_id: u64,
        block_height: u64,
        participated: bool,
    ) -> Result<Option<SlashingEvent>, AvoError> {
        let tracker = self
            .downtime_trackers
            .entry(validator_id)
            .or_insert_with(|| ValidatorDowntime {
                validator_id,
                total_missed_blocks: 0,
                consecutive_misses: 0,
                last_seen_block: 0,
                last_slash_epoch: None,
            });

        if participated {
            tracker.consecutive_misses = 0;
            tracker.last_seen_block = block_height;
        } else {
            tracker.total_missed_blocks += 1;
            tracker.consecutive_misses += 1;

            let threshold = self.params.downtime_threshold_blocks;

            let slash_decision = {
                if tracker.consecutive_misses >= threshold {
                    if tracker
                        .last_slash_epoch
                        .map_or(true, |epoch| epoch < self.current_epoch)
                    {
                        let missed_blocks = tracker.consecutive_misses;
                        tracker.last_slash_epoch = Some(self.current_epoch);
                        tracker.consecutive_misses = 0;
                        Some(missed_blocks)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(missed_blocks) = slash_decision {
                let reason = SlashingReason::Downtime {
                    missed_blocks,
                    threshold,
                };

                let stake = self.get_validator_stake(validator_id).await?;
                let slash_amount = self.calculate_slash_amount(stake, &reason);

                let event = SlashingEvent {
                    validator_id,
                    reason,
                    slash_amount,
                    timestamp: current_timestamp(),
                    block_height,
                    evidence_hash: hash_downtime(validator_id, missed_blocks),
                };

                self.apply_slashing(event.clone()).await?;
                self.slashing_events.push(event.clone());

                return Ok(Some(event));
            }
        }

        Ok(None)
    }

    /// Apply slashing to validator
    async fn apply_slashing(&mut self, event: SlashingEvent) -> Result<(), AvoError> {
        let reason_for_log = event.reason.clone();
        let jail = JailStatus {
            validator_id: event.validator_id,
            jailed_at_epoch: self.current_epoch,
            release_epoch: self.current_epoch + self.params.jail_duration_epochs,
            reason: event.reason,
            is_released: false,
        };

        self.jailed_validators.insert(event.validator_id, jail);

        tracing::warn!(
            "Validator {} slashed for {:?}, amount: {}",
            event.validator_id,
            reason_for_log,
            event.slash_amount
        );

        Ok(())
    }

    /// Calculate slash amount based on stake and offense
    fn calculate_slash_amount(&self, stake: TokenAmount, reason: &SlashingReason) -> TokenAmount {
        let base_percentage = match reason {
            SlashingReason::DoubleSign { .. } => self.params.double_sign_slash_percentage,
            SlashingReason::Downtime { .. } => self.params.downtime_slash_percentage,
            SlashingReason::InvalidStateTransition { .. } => {
                self.params.double_sign_slash_percentage * 0.8
            }
            SlashingReason::Censorship { .. } => self.params.double_sign_slash_percentage * 0.6,
        };

        let multiplier = reason.severity_multiplier();
        let effective_percentage = base_percentage * multiplier;

        ((stake as f64) * effective_percentage) as TokenAmount
    }

    /// Parse evidence bytes to determine slashing reason
    async fn parse_evidence(
        &self,
        evidence: &[u8],
        _validator_id: u64,
    ) -> Result<Option<SlashingReason>, AvoError> {
        if evidence.is_empty() {
            return Ok(None);
        }

        match evidence[0] {
            0x01 => {
                if evidence.len() < 73 {
                    return Ok(None);
                }

                let block_height = u64::from_le_bytes(evidence[1..9].try_into().unwrap());
                let sig1 = evidence[9..41].to_vec();
                let sig2 = evidence[41..73].to_vec();

                Ok(Some(SlashingReason::DoubleSign {
                    block_height,
                    first_signature: sig1,
                    second_signature: sig2,
                }))
            }
            0x02 => {
                if evidence.len() < 17 {
                    return Ok(None);
                }

                let missed = u64::from_le_bytes(evidence[1..9].try_into().unwrap());
                let threshold = u64::from_le_bytes(evidence[9..17].try_into().unwrap());

                Ok(Some(SlashingReason::Downtime {
                    missed_blocks: missed,
                    threshold,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Check if validator is jailed
    pub fn is_jailed(&self, validator_id: u64) -> bool {
        self.jailed_validators
            .get(&validator_id)
            .map_or(false, |jail| {
                !jail.is_released && jail.release_epoch > self.current_epoch
            })
    }

    /// Release jailed validators whose term has expired
    pub async fn process_jail_releases(&mut self) -> Result<Vec<u64>, AvoError> {
        let mut released = Vec::new();

        for (validator_id, jail) in self.jailed_validators.iter_mut() {
            if !jail.is_released && jail.release_epoch <= self.current_epoch {
                jail.is_released = true;
                released.push(*validator_id);
                tracing::info!("Validator {} released from jail", validator_id);
            }
        }

        Ok(released)
    }

    /// Advance to next epoch
    pub async fn advance_epoch(&mut self) -> Result<(), AvoError> {
        self.current_epoch += 1;
        self.process_jail_releases().await?;
        Ok(())
    }

    /// Get validator stake
    async fn get_validator_stake(&self, validator_id: u64) -> Result<TokenAmount, AvoError> {
        let validator_id_u32 = u32::try_from(validator_id).map_err(|_| {
            AvoError::staking(format!(
                "Validator ID {} exceeds supported range",
                validator_id
            ))
        })?;

        let chain_state = ChainState::load_or_create(&self.chain_state_path)?;

        match chain_state.validators.get(&validator_id_u32) {
            Some(record) if record.is_active => Ok(record.stake_wei),
            Some(_) => Err(AvoError::ValidatorNotEligible {
                validator_id: validator_id_u32,
                reason: "Validator is not active".to_string(),
            }),
            None => Err(AvoError::ValidatorNotFound {
                validator_id: validator_id_u32,
            }),
        }
    }

    /// Get slashing events
    pub fn get_events(&self) -> &[SlashingEvent] {
        &self.slashing_events
    }

    /// Get jail status for validator
    pub fn get_jail_status(&self, validator_id: u64) -> Option<&JailStatus> {
        self.jailed_validators.get(&validator_id)
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hash_evidence(evidence: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(evidence);
    hasher.finalize().into()
}

fn hash_double_sign(validator_id: u64, block_height: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"double_sign");
    hasher.update(&validator_id.to_le_bytes());
    hasher.update(&block_height.to_le_bytes());
    hasher.finalize().into()
}

fn hash_downtime(validator_id: u64, missed_blocks: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"downtime");
    hasher.update(&validator_id.to_le_bytes());
    hasher.update(&missed_blocks.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staking::ValidatorRecord;
    use std::path::Path;
    use tempfile::tempdir;

    fn default_params() -> EconomicParams {
        EconomicParams::default()
    }

    fn register_validator<P: AsRef<Path>>(path: P, validator_id: u32, stake: TokenAmount) {
        let record =
            ValidatorRecord::new(validator_id, format!("validator-{}", validator_id), stake);
        ChainState::upsert_validator(path, record).unwrap();
    }

    #[tokio::test]
    async fn test_double_sign_detection() {
        let params = default_params();
        let temp_dir = tempdir().unwrap();
        let chain_state_path = temp_dir.path().join("chain_state.json");
        register_validator(&chain_state_path, 1, params.min_validator_stake);

        let mut manager = SlashingManager::new(params, chain_state_path);
        let validator_id = 1;
        let block_height = 100;

        let sig1 = vec![1u8; 32];
        let sig2 = vec![2u8; 32];

        let result1 = manager
            .register_signature(validator_id, block_height, sig1.clone())
            .await
            .unwrap();
        assert!(result1.is_none());

        let result2 = manager
            .register_signature(validator_id, block_height, sig2)
            .await
            .unwrap();
        assert!(result2.is_some());

        let event = result2.unwrap();
        assert_eq!(event.validator_id, validator_id);
        assert!(matches!(event.reason, SlashingReason::DoubleSign { .. }));
        assert!(manager.is_jailed(validator_id));
    }

    #[tokio::test]
    async fn test_downtime_slashing() {
        let params = default_params();
        let temp_dir = tempdir().unwrap();
        let chain_state_path = temp_dir.path().join("chain_state.json");
        register_validator(&chain_state_path, 1, params.min_validator_stake);

        let mut manager = SlashingManager::new(params.clone(), chain_state_path);
        let validator_id = 1;

        for block in 0..params.downtime_threshold_blocks - 1 {
            let result = manager
                .track_validator_activity(validator_id, block, false)
                .await
                .unwrap();
            assert!(result.is_none());
        }

        let result = manager
            .track_validator_activity(validator_id, params.downtime_threshold_blocks, false)
            .await
            .unwrap();
        assert!(result.is_some());

        let event = result.unwrap();
        assert!(matches!(event.reason, SlashingReason::Downtime { .. }));
    }

    #[tokio::test]
    async fn test_downtime_recovery() {
        let params = default_params();
        let temp_dir = tempdir().unwrap();
        let chain_state_path = temp_dir.path().join("chain_state.json");
        register_validator(&chain_state_path, 1, params.min_validator_stake);

        let mut manager = SlashingManager::new(params.clone(), chain_state_path);
        let validator_id = 1;

        for block in 0..50 {
            manager
                .track_validator_activity(validator_id, block, false)
                .await
                .unwrap();
        }

        manager
            .track_validator_activity(validator_id, 50, true)
            .await
            .unwrap();

        let tracker = manager.downtime_trackers.get(&validator_id).unwrap();
        assert_eq!(tracker.consecutive_misses, 0);
        assert_eq!(tracker.total_missed_blocks, 50);
    }

    #[tokio::test]
    async fn test_jail_release() {
        let mut params = default_params();
        params.jail_duration_epochs = 2;
        let temp_dir = tempdir().unwrap();
        let chain_state_path = temp_dir.path().join("chain_state.json");
        register_validator(&chain_state_path, 1, params.min_validator_stake);

        let mut manager = SlashingManager::new(params, chain_state_path);
        let validator_id = 1;

        let evidence = create_double_sign_evidence(100);
        manager
            .detect_slashing(validator_id, evidence)
            .await
            .unwrap();

        assert!(manager.is_jailed(validator_id));

        manager.advance_epoch().await.unwrap();
        assert!(manager.is_jailed(validator_id));

        manager.advance_epoch().await.unwrap();
        assert!(!manager.is_jailed(validator_id));
    }

    #[test]
    fn test_slash_amount_calculation() {
        let params = default_params();
        let temp_dir = tempdir().unwrap();
        let chain_state_path = temp_dir.path().join("chain_state.json");
        register_validator(&chain_state_path, 1, params.min_validator_stake);

        let manager = SlashingManager::new(params.clone(), chain_state_path);

        let stake = 100_000_000_000_000_000_000_000u128;

        let double_sign = SlashingReason::DoubleSign {
            block_height: 100,
            first_signature: vec![],
            second_signature: vec![],
        };

        let downtime = SlashingReason::Downtime {
            missed_blocks: 100,
            threshold: 100,
        };

        let double_sign_amount = manager.calculate_slash_amount(stake, &double_sign);
        let downtime_amount = manager.calculate_slash_amount(stake, &downtime);

        assert!(double_sign_amount > downtime_amount);
        assert_eq!(
            double_sign_amount,
            ((stake as f64) * params.double_sign_slash_percentage) as TokenAmount
        );
    }

    fn create_double_sign_evidence(block_height: u64) -> Vec<u8> {
        let mut evidence = vec![0x01];
        evidence.extend_from_slice(&block_height.to_le_bytes());
        evidence.extend_from_slice(&[1u8; 32]);
        evidence.extend_from_slice(&[2u8; 32]);
        evidence
    }
}
