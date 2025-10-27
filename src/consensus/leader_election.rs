/// Leader Election - VRF-based block proposer selection
///
/// FASE 10.2: VRF end-to-end implementation for fair leader selection
use crate::crypto::vrf::{VrfOutput, VrfPrivateKey, VrfProof, VrfPublicKey};
use crate::error::{AvoError, AvoResult};
use crate::types::{Epoch, ShardId, Validator, ValidatorId};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::collections::HashMap;
use tracing::{debug, info};

/// Leader election result with VRF proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderElectionResult {
    pub epoch: Epoch,
    pub shard_id: ShardId,
    pub proposer_id: ValidatorId,
    pub vrf_output: VrfOutput,
    pub timestamp: u64,
}

/// Leader election manager using VRF
pub struct LeaderElection {
    /// VRF keys for this validator
    vrf_private_key: Option<VrfPrivateKey>,
    vrf_public_key: Option<VrfPublicKey>,
    /// Cache of recent elections
    election_cache: HashMap<(Epoch, ShardId), LeaderElectionResult>,
}

impl LeaderElection {
    pub fn new() -> Self {
        Self {
            vrf_private_key: None,
            vrf_public_key: None,
            election_cache: HashMap::new(),
        }
    }

    /// Initialize with VRF keys
    pub fn init_with_keys(&mut self, private_key: VrfPrivateKey, public_key: VrfPublicKey) {
        self.vrf_private_key = Some(private_key);
        self.vrf_public_key = Some(public_key);
    }

    /// Select block proposer for an epoch using VRF
    /// FASE 10.2: Real VRF-based selection
    pub fn select_proposer(
        &mut self,
        epoch: Epoch,
        shard_id: ShardId,
        validators: &[Validator],
    ) -> AvoResult<LeaderElectionResult> {
        // Check cache first
        if let Some(cached) = self.election_cache.get(&(epoch, shard_id)) {
            debug!(
                "Using cached leader election for epoch {} shard {}",
                epoch, shard_id
            );
            return Ok(cached.clone());
        }

        if validators.is_empty() {
            return Err(AvoError::validation(
                "No validators available for leader selection",
            ));
        }

        // Create VRF input from epoch and shard
        let vrf_input = self.create_vrf_input(epoch, shard_id);

        // Calculate total stake for weighted selection
        let total_stake: u128 = validators.iter().map(|v| v.stake).sum();

        if total_stake == 0 {
            return Err(AvoError::validation(
                "Total stake is zero, cannot select leader",
            ));
        }

        // Get VRF private key
        let vrf_key = self
            .vrf_private_key
            .as_ref()
            .ok_or_else(|| AvoError::internal("VRF private key not initialized"))?;

        // Evaluate VRF to get random output
        let vrf_output = vrf_key.evaluate(&vrf_input)?;

        // Use VRF output to select proposer (weighted by stake)
        let random_value = vrf_output.to_range(total_stake as u64) as u128;

        // Select validator based on weighted random value
        let mut cumulative_stake = 0u128;
        let mut selected_validator = &validators[0];

        for validator in validators {
            cumulative_stake += validator.stake;
            if random_value < cumulative_stake {
                selected_validator = validator;
                break;
            }
        }

        let result = LeaderElectionResult {
            epoch,
            shard_id,
            proposer_id: selected_validator.id,
            vrf_output,
            timestamp: crate::utils::time::current_timestamp(),
        };

        info!(
            "✓ VRF leader election: epoch={}, shard={}, proposer={}, stake={}",
            epoch, shard_id, selected_validator.id, selected_validator.stake
        );

        // Cache the result
        self.election_cache
            .insert((epoch, shard_id), result.clone());

        Ok(result)
    }

    /// Verify a leader election result
    pub fn verify_election(
        &self,
        result: &LeaderElectionResult,
        validators: &[Validator],
        public_key: &VrfPublicKey,
    ) -> AvoResult<bool> {
        // Verify VRF proof
        let vrf_input = self.create_vrf_input(result.epoch, result.shard_id);

        if result.vrf_output.proof.input != vrf_input {
            return Ok(false);
        }

        if !public_key.verify(&result.vrf_output.proof)? {
            return Ok(false);
        }

        // Verify the selected proposer matches the VRF output
        let total_stake: u128 = validators.iter().map(|v| v.stake).sum();

        if total_stake == 0 {
            return Ok(false);
        }

        let random_value = result.vrf_output.to_range(total_stake as u64) as u128;

        // Recalculate which validator should be selected
        let mut cumulative_stake = 0u128;
        for validator in validators {
            cumulative_stake += validator.stake;
            if random_value < cumulative_stake {
                return Ok(validator.id == result.proposer_id);
            }
        }

        Ok(false)
    }

    /// Create VRF input from epoch and shard
    fn create_vrf_input(&self, epoch: Epoch, shard_id: ShardId) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(b"AVO_LEADER_ELECTION");
        input.extend_from_slice(&epoch.to_le_bytes());
        input.extend_from_slice(&shard_id.to_le_bytes());
        input
    }

    /// Get VRF proof for this validator as proposer
    pub fn get_vrf_proof(&self, epoch: Epoch, shard_id: ShardId) -> AvoResult<VrfProof> {
        if let Some(cached) = self.election_cache.get(&(epoch, shard_id)) {
            return Ok(cached.vrf_output.proof.clone());
        }

        let vrf_key = self
            .vrf_private_key
            .as_ref()
            .ok_or_else(|| AvoError::internal("VRF private key not initialized"))?;

        let vrf_input = self.create_vrf_input(epoch, shard_id);
        let vrf_output = vrf_key.evaluate(&vrf_input)?;

        Ok(vrf_output.proof)
    }

    /// Clear old election cache (keep last 100 epochs)
    pub fn cleanup_cache(&mut self, current_epoch: Epoch) {
        let cutoff_epoch = current_epoch.saturating_sub(100);
        self.election_cache
            .retain(|(epoch, _), _| *epoch >= cutoff_epoch);
    }
}

impl Default for LeaderElection {
    fn default() -> Self {
        Self::new()
    }
}

/// Sortition using VRF for validator selection
pub struct VrfSortition;

impl VrfSortition {
    /// Select a committee of validators using VRF
    pub fn select_committee(
        vrf_output: &VrfOutput,
        validators: &[Validator],
        committee_size: usize,
    ) -> AvoResult<Vec<ValidatorId>> {
        if validators.is_empty() {
            return Ok(Vec::new());
        }

        if committee_size == 0 {
            return Ok(Vec::new());
        }

        let actual_size = committee_size.min(validators.len());
        let mut selected = Vec::with_capacity(actual_size);
        let mut rng_state = vrf_output.randomness;

        // Use VRF output as seed for deterministic shuffling
        for i in 0..actual_size {
            // Update RNG state
            rng_state = sha3::Sha3_256::digest(&rng_state).into();

            // Convert to index
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&rng_state[0..8]);
            let random_value = u64::from_le_bytes(bytes);

            let remaining = validators.len() - i;
            let index = (random_value as usize % remaining) + i;

            // Select validator
            selected.push(validators[index].id);
        }

        Ok(selected)
    }

    /// Calculate if a validator is selected based on VRF and threshold
    pub fn is_selected(
        vrf_output: &VrfOutput,
        validator_stake: u128,
        total_stake: u128,
        target_committee_size: usize,
    ) -> bool {
        if total_stake == 0 || target_committee_size == 0 {
            return false;
        }

        // Calculate selection probability
        let probability =
            (validator_stake as f64 / total_stake as f64) * target_committee_size as f64;

        // Use VRF output to determine if selected
        let threshold = (probability * u64::MAX as f64) as u64;
        let vrf_value = u64::from_le_bytes(vrf_output.randomness[0..8].try_into().unwrap());

        vrf_value < threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vrf::VrfKeyGenerator;
    use rand::thread_rng;

    fn create_test_validators() -> Vec<Validator> {
        vec![
            Validator {
                id: 0,
                public_key: vec![0; 32],
                bls_public_key: vec![0; 96],
                stake: 1000,
                shard_assignments: vec![0],
                is_sync_validator: true,
                reputation_score: 1.0,
                uptime_percentage: 100.0,
            },
            Validator {
                id: 1,
                public_key: vec![1; 32],
                bls_public_key: vec![1; 96],
                stake: 2000,
                shard_assignments: vec![0],
                is_sync_validator: true,
                reputation_score: 1.0,
                uptime_percentage: 100.0,
            },
            Validator {
                id: 2,
                public_key: vec![2; 32],
                bls_public_key: vec![2; 96],
                stake: 3000,
                shard_assignments: vec![0],
                is_sync_validator: true,
                reputation_score: 1.0,
                uptime_percentage: 100.0,
            },
        ]
    }

    #[test]
    fn test_leader_selection() {
        let mut rng = thread_rng();
        let (private_key, public_key) = VrfKeyGenerator::generate_keypair(&mut rng);

        let mut election = LeaderElection::new();
        election.init_with_keys(private_key, public_key.clone());

        let validators = create_test_validators();

        // Select leader for epoch 1, shard 0
        let result = election.select_proposer(1, 0, &validators).unwrap();

        assert_eq!(result.epoch, 1);
        assert_eq!(result.shard_id, 0);
        assert!(validators.iter().any(|v| v.id == result.proposer_id));

        // Verify the election
        let is_valid = election
            .verify_election(&result, &validators, &public_key)
            .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_deterministic_selection() {
        let mut rng = thread_rng();
        let (private_key, _) = VrfKeyGenerator::generate_keypair(&mut rng);

        let mut election1 = LeaderElection::new();
        election1.init_with_keys(private_key.clone(), private_key.public_key().unwrap());

        let mut election2 = LeaderElection::new();
        election2.init_with_keys(private_key.clone(), private_key.public_key().unwrap());

        let validators = create_test_validators();

        // Same epoch and shard should give same result
        let result1 = election1.select_proposer(10, 0, &validators).unwrap();
        let result2 = election2.select_proposer(10, 0, &validators).unwrap();

        assert_eq!(result1.proposer_id, result2.proposer_id);
        assert_eq!(result1.vrf_output.randomness, result2.vrf_output.randomness);
    }

    #[test]
    fn test_committee_selection() {
        let mut rng = thread_rng();
        let (private_key, _) = VrfKeyGenerator::generate_keypair(&mut rng);

        let vrf_input = b"test_committee";
        let vrf_output = private_key.evaluate(vrf_input).unwrap();

        let validators = create_test_validators();

        // Select committee of size 2
        let committee = VrfSortition::select_committee(&vrf_output, &validators, 2).unwrap();

        assert_eq!(committee.len(), 2);
        // No duplicates
        assert_ne!(committee[0], committee[1]);
    }

    #[test]
    fn test_cache_cleanup() {
        let mut rng = thread_rng();
        let (private_key, public_key) = VrfKeyGenerator::generate_keypair(&mut rng);

        let mut election = LeaderElection::new();
        election.init_with_keys(private_key, public_key);

        let validators = create_test_validators();

        // Create elections for multiple epochs
        for epoch in 0..150 {
            election.select_proposer(epoch, 0, &validators).unwrap();
        }

        assert_eq!(election.election_cache.len(), 150);

        // Cleanup old elections
        election.cleanup_cache(150);

        // Should only keep last 100
        assert!(election.election_cache.len() <= 100);
    }
}
