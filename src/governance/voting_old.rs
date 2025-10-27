use crate::types::{NodeId};
use crate::error::AvoError;
use crate::governance::proposals::{ProposalId, VotingPower, VoteChoice, VoteRecord};
use crate::state::storage::AvocadoStorage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Get the global storage instance for governance operations
async fn get_storage() -> Option<Arc<AvocadoStorage>> {
    // Try to create a new storage instance
    if let Ok(storage) = crate::state::storage::AvocadoStorage::new(Default::default()) {
        return Some(Arc::new(storage));
    }
    
    None
}

/// Delegation record for vote delegation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRecord {
    pub delegator: NodeId,
    pub delegate: NodeId,
    pub voting_power: VotingPower,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub active: bool,
    pub delegation_type: DelegationType,
}

/// Types of delegation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DelegationType {
    /// Full delegation of all voting power
    Full,
    /// Partial delegation of specific amount
    Partial { amount: VotingPower },
    /// Category-specific delegation
    Categorical { categories: Vec<String> },
    /// Time-limited delegation
    Temporary { expires_at: u64 },
}

/// Voting power calculation factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingPowerFactors {
    pub base_stake: VotingPower,
    pub validator_bonus: VotingPower,
    pub delegation_received: VotingPower,
    pub delegation_given: VotingPower,
    pub lock_time_multiplier: f64,
    pub participation_bonus: VotingPower,
}

/// Voter profile and statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterProfile {
    pub node_id: NodeId,
    pub total_voting_power: VotingPower,
    pub available_voting_power: VotingPower,
    pub delegated_voting_power: VotingPower,
    pub received_delegations: VotingPower,
    pub participation_rate: f64,
    pub voting_history: VotingHistory,
    pub reputation_score: u32,
    pub is_validator: bool,
    pub stake_lock_end: Option<u64>,
}

/// Historical voting data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingHistory {
    pub total_votes_cast: u32,
    pub proposals_participated: Vec<ProposalId>,
    pub voting_streak: u32,
    pub last_vote_time: Option<u64>,
    pub average_response_time: Option<u64>,
    pub vote_distribution: VoteDistribution,
}

/// Distribution of vote choices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteDistribution {
    pub votes_for: u32,
    pub votes_against: u32,
    pub votes_abstain: u32,
}

/// Quorum calculation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumConfig {
    pub base_quorum_percentage: u8,
    pub dynamic_adjustment: bool,
    pub participation_threshold: u8,
    pub validator_weight: f64,
    pub minimum_absolute_quorum: VotingPower,
    pub maximum_quorum_percentage: u8,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            base_quorum_percentage: 33,
            dynamic_adjustment: true,
            participation_threshold: 50,
            validator_weight: 1.5,
            minimum_absolute_quorum: 100_000,
            maximum_quorum_percentage: 67,
        }
    }
}

/// Voting system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingConfig {
    pub delegation_enabled: bool,
    pub max_delegations_per_account: u32,
    pub delegation_cooldown: u64,
    pub vote_change_allowed: bool,
    pub vote_privacy: VotePrivacy,
    pub quorum_config: QuorumConfig,
    pub reputation_enabled: bool,
    pub participation_rewards: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VotePrivacy {
    Public,
    Private,
    Configurable,
}

impl Default for VotingConfig {
    fn default() -> Self {
        Self {
            delegation_enabled: true,
            max_delegations_per_account: 10,
            delegation_cooldown: 24 * 60 * 60, // 24 hours
            vote_change_allowed: false,
            vote_privacy: VotePrivacy::Public,
            quorum_config: QuorumConfig::default(),
            reputation_enabled: true,
            participation_rewards: true,
        }
    }
}

/// Main voting system
#[derive(Debug)]
pub struct VotingSystem {
    config: VotingConfig,
}

impl VotingSystem {
    /// Create a new voting system
    pub fn new(config: VotingConfig) -> Self {
        Self {
            config,
        }
    }

    /// Create or update delegation
    pub async fn delegate_voting_power(
        &self,
        delegator: NodeId,
        delegate: NodeId,
        delegation_type: DelegationType,
        duration: Option<u64>,
    ) -> Result<(), AvoError> {
        let storage = get_storage().await.ok_or_else(|| AvoError::StorageError { 
            reason: "Storage not available".to_string() 
        })?;
        
        if !self.config.delegation_enabled {
            return Err(AvoError::GovernanceError(
                "Delegation is not enabled".to_string()
            ));
        }

        // Validate delegation
        if delegator == delegate {
            return Err(AvoError::GovernanceError(
                "Cannot delegate to self".to_string()
            ));
        }

        // Check delegation limits
        let delegations_key = format!("delegations_{}", delegator);
        let current_delegations = if let Ok(Some(data)) = storage.get_governance_voting(&delegations_key).await {
            if let Ok(delegations) = serde_json::from_slice::<Vec<DelegationRecord>>(&data) {
                delegations.len()
            } else {
                0
            }
        } else {
            0
        };

        if current_delegations >= self.config.max_delegations_per_account as usize {
            return Err(AvoError::GovernanceError(
                "Maximum delegations exceeded".to_string()
            ));
        }

        // Calculate voting power to delegate
        let delegator_profile = self.get_voter_profile(&delegator).await?;
        let voting_power = match &delegation_type {
            DelegationType::Full => delegator_profile.available_voting_power,
            DelegationType::Partial { amount } => {
                if *amount > delegator_profile.available_voting_power {
                    return Err(AvoError::GovernanceError(
                        "Insufficient voting power for delegation".to_string()
                    ));
                }
                *amount
            }
            DelegationType::Categorical { .. } => delegator_profile.available_voting_power,
            DelegationType::Temporary { .. } => delegator_profile.available_voting_power,
        };

        let current_time = current_timestamp();
        let expires_at = duration.map(|d| current_time + d);

        // Create delegation record
        let delegation_record = DelegationRecord {
            delegator: delegator.clone(),
            delegate: delegate.clone(),
            voting_power,
            created_at: current_time,
            expires_at,
            active: true,
            delegation_type,
        };

        // Store delegation in RocksDB
        let mut delegations = if let Ok(Some(data)) = storage.get_governance_voting(&delegations_key).await {
            serde_json::from_slice::<Vec<DelegationRecord>>(&data).unwrap_or_default()
        } else {
            Vec::new()
        };
        delegations.push(delegation_record);
        
        let delegations_data = serde_json::to_vec(&delegations).map_err(|e| AvoError::StorageError {
            reason: format!("Failed to serialize delegations: {}", e)
        })?;
        storage.store_governance_voting(&delegations_key, &delegations_data).await?;

        // Update delegation index
        let index_key = format!("delegation_index_{}", delegate);
        let mut index = if let Ok(Some(data)) = storage.get_governance_voting(&index_key).await {
            serde_json::from_slice::<Vec<NodeId>>(&data).unwrap_or_default()
        } else {
            Vec::new()
        };
        index.push(delegator.clone());
        
        let index_data = serde_json::to_vec(&index).map_err(|e| AvoError::StorageError {
            reason: format!("Failed to serialize delegation index: {}", e)
        })?;
        storage.store_governance_voting(&index_key, &index_data).await?;

        // Update voter profiles
        self.update_voter_profile_delegation(&delegator, &delegate, voting_power, true).await?;

        Ok(())
    }

    /// Revoke delegation
    pub async fn revoke_delegation(
        &self,
        delegator: NodeId,
        delegate: NodeId,
    ) -> Result<(), AvoError> {
        let storage = get_storage().await.ok_or_else(|| AvoError::StorageError { 
            reason: "Storage not available".to_string() 
        })?;
        
        // Get and update delegations
        let delegations_key = format!("delegations_{}", delegator);
        let mut delegations = if let Ok(Some(data)) = storage.get_governance_voting(&delegations_key).await {
            serde_json::from_slice::<Vec<DelegationRecord>>(&data).map_err(|e| AvoError::StorageError {
                reason: format!("Failed to deserialize delegations: {}", e)
            })?
        } else {
            return Err(AvoError::GovernanceError(
                "No delegations found for delegator".to_string()
            ));
        };

        let voting_power = if let Some(delegation) = delegations.iter_mut().find(|d| d.delegate == delegate && d.active) {
            delegation.active = false;
            delegation.voting_power
        } else {
            return Err(AvoError::GovernanceError(
                "Delegation not found".to_string()
            ));
        };

        // Save updated delegations
        let delegations_data = serde_json::to_vec(&delegations).map_err(|e| AvoError::StorageError {
            reason: format!("Failed to serialize delegations: {}", e)
        })?;
        storage.store_governance_voting(&delegations_key, &delegations_data).await?;

        // Update delegation index
        let index_key = format!("delegation_index_{}", delegate);
        if let Ok(Some(data)) = storage.get_governance_voting(&index_key).await {
            let mut index: Vec<NodeId> = serde_json::from_slice(&data).unwrap_or_default();
            index.retain(|d| d != &delegator);
            
            let index_data = serde_json::to_vec(&index).map_err(|e| AvoError::StorageError {
                reason: format!("Failed to serialize delegation index: {}", e)
            })?;
            storage.store_governance_voting(&index_key, &index_data).await?;
        }

        // Update voter profiles
        self.update_voter_profile_delegation(&delegator, &delegate, voting_power, false).await?;

        Ok(())
    }

    /// Get effective voting power for a voter
    pub async fn get_effective_voting_power(&self, voter: &NodeId) -> Result<VotingPower, AvoError> {
        let storage = get_storage().await.ok_or_else(|| AvoError::StorageError { 
            reason: "Storage not available".to_string() 
        })?;
        
        // Check cache in RocksDB first
        let cache_ttl = 300; // 5 minutes
        let current_time = current_timestamp();
        let cache_key = format!("voting_power_cache_{}", voter);
        
        if let Ok(Some(data)) = storage.get_governance_voting(&cache_key).await {
            if let Ok((power, timestamp)) = serde_json::from_slice::<(VotingPower, u64)>(&data) {
                if current_time - timestamp < cache_ttl {
                    return Ok(power);
                }
            }
        }

        // Calculate voting power (placeholder implementation)
        let voting_power = 1000; // This would integrate with actual stake calculation
        
        // Cache the result
        let cache_data = serde_json::to_vec(&(voting_power, current_time)).map_err(|e| AvoError::StorageError {
            reason: format!("Failed to serialize voting power cache: {}", e)
        })?;
        storage.store_governance_voting(&cache_key, &cache_data).await?;

        Ok(voting_power)
    }

        // Calculate voting power
        let voter_profile = self.get_voter_profile(voter).await?;
        let mut total_power = voter_profile.total_voting_power;

        // Add delegated power
        let delegated_power = self.calculate_delegated_power(voter).await?;
        total_power += delegated_power;

        // Subtract delegated away power
        total_power -= voter_profile.delegated_voting_power;

        // Update cache
        {
            let mut cache = self.voting_power_cache.write().await;
            cache.insert(voter.clone(), (total_power, current_time));
        }

        Ok(total_power)
    }

    /// Cast a vote with delegation support
    pub async fn cast_vote(
        &self,
        voter: NodeId,
        proposal_id: ProposalId,
        choice: VoteChoice,
        signature: Vec<u8>,
    ) -> Result<VoteRecord, AvoError> {
        let current_time = current_timestamp();

        // Get effective voting power
        let voting_power = self.get_effective_voting_power(&voter).await?;

        if voting_power == 0 {
            return Err(AvoError::GovernanceError(
                "No voting power available".to_string()
            ));
        }

        // Check if vote already exists
        {
            let active_votes = self.active_votes.read().await;
            if let Some(proposal_votes) = active_votes.get(&proposal_id) {
                if proposal_votes.contains_key(&voter) {
                    if !self.config.vote_change_allowed {
                        return Err(AvoError::GovernanceError(
                            "Vote already cast and changes not allowed".to_string()
                        ));
                    }
                }
            }
        }

        // Create vote record
        let vote_record = VoteRecord {
            voter: voter.clone(),
            proposal_id,
            choice,
            voting_power,
            timestamp: current_time,
            signature,
            delegated_from: None, // This would be populated if the vote is on behalf of delegators
        };

        // Store the vote
        {
            let mut active_votes = self.active_votes.write().await;
            active_votes.entry(proposal_id)
                .or_insert_with(HashMap::new)
                .insert(voter.clone(), vote_record.clone());
        }

        // Update voter profile participation
        self.update_voter_participation(&voter, proposal_id).await?;

        Ok(vote_record)
    }

    /// Get voter profile
    pub async fn get_voter_profile(&self, node_id: &NodeId) -> Result<VoterProfile, AvoError> {
        let profiles = self.voter_profiles.read().await;
        
        if let Some(profile) = profiles.get(node_id) {
            Ok(profile.clone())
        } else {
            // Create new profile
            drop(profiles);
            self.create_voter_profile(node_id.clone()).await
        }
    }

    /// Calculate quorum for a proposal
    pub async fn calculate_quorum(&self, total_voting_power: VotingPower) -> Result<VotingPower, AvoError> {
        let config = &self.config.quorum_config;
        
        let base_quorum = (total_voting_power * config.base_quorum_percentage as VotingPower) / 100;
        
        if config.dynamic_adjustment {
            // Adjust based on recent participation
            let recent_participation = self.calculate_recent_participation().await?;
            
            let adjustment_factor = if recent_participation < config.participation_threshold as f64 {
                0.8 // Lower quorum if participation is low
            } else {
                1.0
            };
            
            let adjusted_quorum = (base_quorum as f64 * adjustment_factor) as VotingPower;
            Ok(std::cmp::max(adjusted_quorum, config.minimum_absolute_quorum))
        } else {
            Ok(std::cmp::max(base_quorum, config.minimum_absolute_quorum))
        }
    }

    /// Get voting statistics for a proposal
    pub async fn get_voting_statistics(&self, proposal_id: ProposalId) -> Result<VotingStatistics, AvoError> {
        let active_votes = self.active_votes.read().await;
        
        if let Some(proposal_votes) = active_votes.get(&proposal_id) {
            let mut stats = VotingStatistics {
                total_votes: proposal_votes.len() as u32,
                total_voting_power: 0,
                votes_for: 0,
                votes_against: 0,
                votes_abstain: 0,
                power_for: 0,
                power_against: 0,
                power_abstain: 0,
                validator_participation: 0,
                average_response_time: 0,
                participation_rate: 0.0,
            };

            let mut response_times = Vec::new();
            let mut validator_votes = 0;

            for vote in proposal_votes.values() {
                stats.total_voting_power += vote.voting_power;
                
                match vote.choice {
                    VoteChoice::For => {
                        stats.votes_for += 1;
                        stats.power_for += vote.voting_power;
                    }
                    VoteChoice::Against => {
                        stats.votes_against += 1;
                        stats.power_against += vote.voting_power;
                    }
                    VoteChoice::Abstain => {
                        stats.votes_abstain += 1;
                        stats.power_abstain += vote.voting_power;
                    }
                }

                // Check if voter is validator
                let voter_profile = self.get_voter_profile(&vote.voter).await?;
                if voter_profile.is_validator {
                    validator_votes += 1;
                }

                response_times.push(vote.timestamp);
            }

            stats.validator_participation = validator_votes;
            
            if !response_times.is_empty() {
                stats.average_response_time = response_times.iter().sum::<u64>() / response_times.len() as u64;
            }

            // Calculate participation rate
            let total_eligible_power = self.calculate_total_eligible_power().await?;
            stats.participation_rate = (stats.total_voting_power as f64 / total_eligible_power as f64) * 100.0;

            Ok(stats)
        } else {
            Ok(VotingStatistics::default())
        }
    }

    /// Get delegations for a delegator
    pub async fn get_delegations(&self, delegator: &NodeId) -> Result<Vec<DelegationRecord>, AvoError> {
        let delegations = self.delegations.read().await;
        Ok(delegations.get(delegator)
            .map(|d| d.iter().filter(|r| r.active).cloned().collect())
            .unwrap_or_default())
    }

    /// Get delegators for a delegate
    pub async fn get_delegators(&self, delegate: &NodeId) -> Result<Vec<NodeId>, AvoError> {
        let index = self.delegation_index.read().await;
        Ok(index.get(delegate).cloned().unwrap_or_default())
    }

    // Private helper methods

    async fn calculate_delegated_power(&self, delegate: &NodeId) -> Result<VotingPower, AvoError> {
        let delegations = self.delegations.read().await;
        let mut total_power = 0;

        // Check all active delegations to this delegate
        for delegator_delegations in delegations.values() {
            for delegation in delegator_delegations {
                if delegation.delegate == *delegate && delegation.active {
                    // Check if delegation has expired
                    if let Some(expires_at) = delegation.expires_at {
                        if current_timestamp() > expires_at {
                            continue;
                        }
                    }
                    total_power += delegation.voting_power;
                }
            }
        }

        Ok(total_power)
    }

    async fn create_voter_profile(&self, node_id: NodeId) -> Result<VoterProfile, AvoError> {
        // Calculate initial voting power factors
        let factors = self.calculate_voting_power_factors(&node_id).await?;
        
        let profile = VoterProfile {
            node_id: node_id.clone(),
            total_voting_power: factors.base_stake + factors.validator_bonus,
            available_voting_power: factors.base_stake + factors.validator_bonus,
            delegated_voting_power: 0,
            received_delegations: 0,
            participation_rate: 0.0,
            voting_history: VotingHistory {
                total_votes_cast: 0,
                proposals_participated: Vec::new(),
                voting_streak: 0,
                last_vote_time: None,
                average_response_time: None,
                vote_distribution: VoteDistribution {
                    votes_for: 0,
                    votes_against: 0,
                    votes_abstain: 0,
                },
            },
            reputation_score: 100, // Start with neutral reputation
            is_validator: factors.validator_bonus > 0,
            stake_lock_end: None,
        };

        // Store the profile
        {
            let mut profiles = self.voter_profiles.write().await;
            profiles.insert(node_id, profile.clone());
        }

        Ok(profile)
    }

    async fn calculate_voting_power_factors(&self, _node_id: &NodeId) -> Result<VotingPowerFactors, AvoError> {
        // This would integrate with staking and validator systems
        // Placeholder implementation
        Ok(VotingPowerFactors {
            base_stake: 1000,
            validator_bonus: 500, // If node is a validator
            delegation_received: 0,
            delegation_given: 0,
            lock_time_multiplier: 1.0,
            participation_bonus: 0,
        })
    }

    async fn update_voter_profile_delegation(
        &self,
        delegator: &NodeId,
        delegate: &NodeId,
        voting_power: VotingPower,
        is_delegation: bool,
    ) -> Result<(), AvoError> {
        let mut profiles = self.voter_profiles.write().await;

        // Update delegator profile
        if let Some(delegator_profile) = profiles.get_mut(delegator) {
            if is_delegation {
                delegator_profile.delegated_voting_power += voting_power;
                delegator_profile.available_voting_power -= voting_power;
            } else {
                delegator_profile.delegated_voting_power -= voting_power;
                delegator_profile.available_voting_power += voting_power;
            }
        }

        // Update delegate profile
        if let Some(delegate_profile) = profiles.get_mut(delegate) {
            if is_delegation {
                delegate_profile.received_delegations += voting_power;
            } else {
                delegate_profile.received_delegations -= voting_power;
            }
        }

        Ok(())
    }

    async fn update_voter_participation(&self, voter: &NodeId, proposal_id: ProposalId) -> Result<(), AvoError> {
        let mut profiles = self.voter_profiles.write().await;
        
        if let Some(profile) = profiles.get_mut(voter) {
            profile.voting_history.total_votes_cast += 1;
            profile.voting_history.proposals_participated.push(proposal_id);
            profile.voting_history.last_vote_time = Some(current_timestamp());
            
            // Update voting streak
            profile.voting_history.voting_streak += 1;
            
            // Recalculate participation rate
            let total_proposals = 100; // This would come from proposal manager
            profile.participation_rate = (profile.voting_history.total_votes_cast as f64 / total_proposals as f64) * 100.0;
        }

        Ok(())
    }

    async fn calculate_recent_participation(&self) -> Result<f64, AvoError> {
        // Calculate average participation rate across all voters
        let profiles = self.voter_profiles.read().await;
        let total_participation: f64 = profiles.values()
            .map(|p| p.participation_rate)
            .sum();
        
        let average = if profiles.is_empty() {
            0.0
        } else {
            total_participation / profiles.len() as f64
        };

        Ok(average)
    }

    async fn calculate_total_eligible_power(&self) -> Result<VotingPower, AvoError> {
        let profiles = self.voter_profiles.read().await;
        let total = profiles.values()
            .map(|p| p.total_voting_power)
            .sum();
        Ok(total)
    }

    async fn clear_voting_power_cache(&self) {
        let mut cache = self.voting_power_cache.write().await;
        cache.clear();
    }
}

/// Voting statistics for analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VotingStatistics {
    pub total_votes: u32,
    pub total_voting_power: VotingPower,
    pub votes_for: u32,
    pub votes_against: u32,
    pub votes_abstain: u32,
    pub power_for: VotingPower,
    pub power_against: VotingPower,
    pub power_abstain: VotingPower,
    pub validator_participation: u32,
    pub average_response_time: u64,
    pub participation_rate: f64,
}

/// Get current timestamp in seconds since Unix epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
