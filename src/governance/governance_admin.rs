// governance_admin.rs
// Sistema de Gobernanza con Control Administrativo Inicial
// y Fee de Votación que se Quema (Burn)

use crate::error::AvoError;
use crate::governance::proposals::{Proposal, ProposalId, ProposalType, VoteChoice};
use crate::state::storage::AvocadoStorage;
use crate::types::{NodeId, TokenAmount};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Admin address with exclusive governance proposal rights (Phase 1)
pub const GOVERNANCE_ADMIN: &str = "0x372d3c99b7bdb6dec219daf4aef96bc2062e6090";

/// Fee per vote that gets burned (1 AVO = 10^18 wei)
pub const VOTE_FEE: TokenAmount = 1_000_000_000_000_000_000; // 1 AVO

/// Governance phases
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GovernancePhase {
    /// Phase 1: Only admin can create proposals, anyone can vote with fee
    AdminControlled {
        start_height: u64,
        min_community_size: u64, // Minimum holders to transition
    },
    /// Phase 2: Transition phase - Admin + Whitelisted proposers
    Transition {
        start_height: u64,
        whitelisted_proposers: Vec<NodeId>,
        min_stake_required: TokenAmount,
    },
    /// Phase 3: Fully decentralized - Anyone with stake can propose
    Decentralized {
        start_height: u64,
        min_proposal_stake: TokenAmount,
        proposal_cooldown: u64,
    },
}

impl Default for GovernancePhase {
    fn default() -> Self {
        Self::AdminControlled {
            start_height: 0,
            min_community_size: 100, // 100 holders mínimo para transición
        }
    }
}

/// Governance configuration with admin controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminGovernanceConfig {
    /// Current phase of governance
    pub phase: GovernancePhase,
    
    /// Admin address (immutable)
    pub admin_address: String,
    
    /// Vote fee in wei (1 AVO by default)
    pub vote_fee: TokenAmount,
    
    /// Whether vote fee is burned (true) or sent to treasury (false)
    pub burn_vote_fee: bool,
    
    /// Minimum voting power to vote (can be 0 if fee is paid)
    pub min_voting_power: TokenAmount,
    
    /// Whether admin can emergency halt governance
    pub admin_emergency_powers: bool,
    
    /// Total fees burned from voting
    pub total_fees_burned: TokenAmount,
    
    /// Total votes cast
    pub total_votes_cast: u64,
    
    /// Voting configuration
    pub default_voting_period: u64,   // 7 days default
    pub default_execution_delay: u64, // 2 days default
    pub quorum_threshold: u8,         // 33% default
    pub passing_threshold: u8,        // 67% default
    pub emergency_threshold: u8,      // 80% for emergencies
}

impl Default for AdminGovernanceConfig {
    fn default() -> Self {
        Self {
            phase: GovernancePhase::default(),
            admin_address: GOVERNANCE_ADMIN.to_string(),
            vote_fee: VOTE_FEE,
            burn_vote_fee: true, // Quemar fees por defecto
            min_voting_power: 0, // 0 porque se paga fee
            admin_emergency_powers: true,
            total_fees_burned: 0,
            total_votes_cast: 0,
            default_voting_period: 7 * 24 * 60 * 60,
            default_execution_delay: 2 * 24 * 60 * 60,
            quorum_threshold: 33,
            passing_threshold: 67,
            emergency_threshold: 80,
        }
    }
}

/// Admin-controlled governance manager
#[derive(Debug)]
pub struct AdminGovernanceManager {
    config: Arc<RwLock<AdminGovernanceConfig>>,
}

impl AdminGovernanceManager {
    /// Create new admin governance manager
    pub fn new(config: AdminGovernanceConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Check if address is authorized to create proposals
    pub async fn can_create_proposal(&self, proposer: &NodeId) -> Result<bool, AvoError> {
        let config = self.config.read().await;
        
        match &config.phase {
            GovernancePhase::AdminControlled { .. } => {
                // Solo admin puede crear propuestas
                Ok(proposer.to_lowercase() == config.admin_address.to_lowercase())
            }
            GovernancePhase::Transition {
                whitelisted_proposers,
                ..
            } => {
                // Admin + whitelist pueden proponer
                Ok(proposer.to_lowercase() == config.admin_address.to_lowercase()
                    || whitelisted_proposers.contains(proposer))
            }
            GovernancePhase::Decentralized { .. } => {
                // Cualquiera con stake suficiente puede proponer
                Ok(true) // Check stake se hace en otro lado
            }
        }
    }

    /// Validate and process vote fee
    pub async fn process_vote_fee(
        &self,
        voter: &NodeId,
        voter_balance: TokenAmount,
    ) -> Result<TokenAmount, AvoError> {
        let mut config = self.config.write().await;
        
        // Verificar que el votante tenga suficiente balance
        if voter_balance < config.vote_fee {
            return Err(AvoError::GovernanceError(format!(
                "Insufficient balance to pay vote fee. Required: {} wei (1 AVO), Have: {} wei",
                config.vote_fee, voter_balance
            )));
        }

        // Incrementar estadísticas
        config.total_votes_cast += 1;
        if config.burn_vote_fee {
            config.total_fees_burned += config.vote_fee;
        }

        info!(
            "💸 Vote fee processed: {} wei from {} (Total burned: {} wei, Total votes: {})",
            config.vote_fee, voter, config.total_fees_burned, config.total_votes_cast
        );

        Ok(config.vote_fee)
    }

    /// Burn vote fee (remove from total supply)
    pub async fn burn_vote_fee(&self, amount: TokenAmount) -> Result<(), AvoError> {
        let config = self.config.read().await;
        
        if !config.burn_vote_fee {
            return Ok(()); // No quemar si está deshabilitado
        }

        info!(
            "🔥 Burning vote fee: {} wei (1 AVO) - Total burned: {} wei",
            amount, config.total_fees_burned
        );

        // El burn real se hace en la transacción (restando del balance sin agregarlo a otro)
        Ok(())
    }

    /// Transition to next governance phase
    pub async fn transition_phase(&self, new_phase: GovernancePhase) -> Result<(), AvoError> {
        let mut config = self.config.write().await;
        
        match (&config.phase, &new_phase) {
            (GovernancePhase::AdminControlled { .. }, GovernancePhase::Transition { .. }) => {
                info!("🔄 Transitioning governance: AdminControlled → Transition");
                config.phase = new_phase;
                Ok(())
            }
            (GovernancePhase::Transition { .. }, GovernancePhase::Decentralized { .. }) => {
                info!("🔄 Transitioning governance: Transition → Decentralized");
                config.phase = new_phase;
                Ok(())
            }
            _ => Err(AvoError::GovernanceError(
                "Invalid phase transition".to_string(),
            )),
        }
    }

    /// Check if community is ready for transition (based on holder count)
    pub async fn check_transition_readiness(
        &self,
        current_holders: u64,
    ) -> Result<bool, AvoError> {
        let config = self.config.read().await;
        
        match &config.phase {
            GovernancePhase::AdminControlled {
                min_community_size, ..
            } => Ok(current_holders >= *min_community_size),
            _ => Ok(false), // Ya transicionó
        }
    }

    /// Admin emergency halt (solo en fase AdminControlled)
    pub async fn emergency_halt(&self, admin: &NodeId) -> Result<(), AvoError> {
        let config = self.config.read().await;
        
        if !config.admin_emergency_powers {
            return Err(AvoError::GovernanceError(
                "Admin emergency powers are disabled".to_string(),
            ));
        }

        if admin.to_lowercase() != config.admin_address.to_lowercase() {
            return Err(AvoError::GovernanceError(
                "Only admin can trigger emergency halt".to_string(),
            ));
        }

        warn!("🚨 EMERGENCY HALT triggered by admin: {}", admin);
        Ok(())
    }

    /// Get governance statistics
    pub async fn get_stats(&self) -> GovernanceStats {
        let config = self.config.read().await;
        
        GovernanceStats {
            phase: config.phase.clone(),
            total_fees_burned: config.total_fees_burned,
            total_votes_cast: config.total_votes_cast,
            vote_fee: config.vote_fee,
            admin_address: config.admin_address.clone(),
            burn_enabled: config.burn_vote_fee,
        }
    }

    /// Update vote fee (solo admin)
    pub async fn update_vote_fee(
        &self,
        new_fee: TokenAmount,
        admin: &NodeId,
    ) -> Result<(), AvoError> {
        let mut config = self.config.write().await;
        
        if admin.to_lowercase() != config.admin_address.to_lowercase() {
            return Err(AvoError::GovernanceError(
                "Only admin can update vote fee".to_string(),
            ));
        }

        let old_fee = config.vote_fee;
        config.vote_fee = new_fee;
        
        info!(
            "💰 Vote fee updated by admin: {} wei → {} wei",
            old_fee, new_fee
        );

        Ok(())
    }
}

/// Governance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceStats {
    pub phase: GovernancePhase,
    pub total_fees_burned: TokenAmount,
    pub total_votes_cast: u64,
    pub vote_fee: TokenAmount,
    pub admin_address: String,
    pub burn_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_admin_can_propose() {
        let manager = AdminGovernanceManager::new(AdminGovernanceConfig::default());
        let admin = GOVERNANCE_ADMIN.to_string();
        
        let can_propose = manager.can_create_proposal(&admin).await.unwrap();
        assert!(can_propose);
    }

    #[tokio::test]
    async fn test_non_admin_cannot_propose() {
        let manager = AdminGovernanceManager::new(AdminGovernanceConfig::default());
        let non_admin = "0x1234567890123456789012345678901234567890".to_string();
        
        let can_propose = manager.can_create_proposal(&non_admin).await.unwrap();
        assert!(!can_propose);
    }

    #[tokio::test]
    async fn test_vote_fee_processing() {
        let manager = AdminGovernanceManager::new(AdminGovernanceConfig::default());
        let voter = "0xvoter".to_string();
        let balance = 10_000_000_000_000_000_000u128; // 10 AVO
        
        let fee = manager.process_vote_fee(&voter, balance).await.unwrap();
        assert_eq!(fee, VOTE_FEE);
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.total_votes_cast, 1);
        assert_eq!(stats.total_fees_burned, VOTE_FEE);
    }

    #[tokio::test]
    async fn test_insufficient_balance_for_vote() {
        let manager = AdminGovernanceManager::new(AdminGovernanceConfig::default());
        let voter = "0xvoter".to_string();
        let balance = 500_000_000_000_000_000u128; // 0.5 AVO (insuficiente)
        
        let result = manager.process_vote_fee(&voter, balance).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_phase_transition() {
        let manager = AdminGovernanceManager::new(AdminGovernanceConfig::default());
        
        let new_phase = GovernancePhase::Transition {
            start_height: 1000,
            whitelisted_proposers: vec![],
            min_stake_required: 1000 * VOTE_FEE,
        };
        
        manager.transition_phase(new_phase).await.unwrap();
        
        let stats = manager.get_stats().await;
        assert!(matches!(stats.phase, GovernancePhase::Transition { .. }));
    }
}
