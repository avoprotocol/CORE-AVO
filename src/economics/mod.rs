//! # Economics Module
//!
//! Complete on-chain economics system for the AVO Protocol including:
//! - EIP-1559 dynamic fee mechanism per shard
//! - Real slashing detection and penalties
//! - MEV capture and redistribution
//! - Validator rewards and staking economics
//! - Persistent economic state in RocksDB

pub mod fee_market;
pub mod mev_distribution;
pub mod rewards;
pub mod slashing;
pub mod slashing_manager; // FASE 10.3: Real slashing implementation
pub mod storage;

pub use fee_market::{FeeMarket, ShardFeeState};
pub use mev_distribution::{MevCapture, MevDistribution, MevDistributor};
pub use rewards::{RewardCalculator, RewardDistribution};
pub use slashing::{SlashingEvent, SlashingManager as OldSlashingManager, SlashingReason};
pub use slashing_manager::{
    SlashingConfig, SlashingEvidence, SlashingManager, SlashingOffense, SlashingReward,
    SlashingSeverity, SlashingStatistics, SlashingStatus,
};
pub use storage::{EconomicStorage, EconomicStorageConfig};

use crate::error::AvoError;
use crate::types::{ShardId, TokenAmount, ValidatorId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;

/// Economic parameters for the protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicParams {
    /// Target gas per block per shard
    pub target_gas_per_block: u64,
    /// Maximum gas per block per shard
    pub max_gas_per_block: u64,
    /// Base fee change denominator (EIP-1559)
    pub base_fee_change_denominator: u64,
    /// Elasticity multiplier for gas limit
    pub elasticity_multiplier: u64,
    /// Minimum base fee (in wei)
    pub min_base_fee: u128,
    /// Maximum base fee (in wei)
    pub max_base_fee: u128,
    /// Initial base fee per shard (in wei)
    pub initial_base_fee: u128,
    /// Percentage of base fee to burn (0-100)
    pub burn_percentage: u8,
    /// Block reward for validators (in tokens)
    pub block_reward: TokenAmount,
    /// Validator commission rate (0.0-1.0)
    pub validator_commission: f64,
    /// Delegator reward share (0.0-1.0)
    pub delegator_share: f64,
    /// Treasury MEV share (0.0-1.0)
    pub treasury_mev_share: f64,
    /// Annual inflation rate (0.0-1.0)
    pub annual_inflation_rate: f64,
    /// Slashing percentage for double signing (0.0-1.0)
    pub double_sign_slash_percentage: f64,
    /// Slashing percentage for downtime (0.0-1.0)
    pub downtime_slash_percentage: f64,
    /// Downtime threshold in blocks
    pub downtime_threshold_blocks: u64,
    /// Jail duration for slashed validators (in epochs)
    pub jail_duration_epochs: u64,
    /// Minimum stake to be a validator
    pub min_validator_stake: TokenAmount,
}

impl Default for EconomicParams {
    fn default() -> Self {
        Self {
            target_gas_per_block: 15_000_000,
            max_gas_per_block: 30_000_000,
            base_fee_change_denominator: 8,
            elasticity_multiplier: 2,
            min_base_fee: 1_000_000_000,         // 1 gwei
            max_base_fee: 1_000_000_000_000_000, // 1000 gwei
            initial_base_fee: 10_000_000_000,    // 10 gwei
            burn_percentage: 70,
            block_reward: 2_000_000_000_000_000_000, // 2 tokens
            validator_commission: 0.10,
            delegator_share: 0.85,
            treasury_mev_share: 0.15,
            annual_inflation_rate: 0.05,
            double_sign_slash_percentage: 0.05,
            downtime_slash_percentage: 0.01,
            downtime_threshold_blocks: 100,
            jail_duration_epochs: 10,
            min_validator_stake: 32_000_000_000_000_000_000_000, // 32k tokens
        }
    }
}

/// Current economic state of the protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicState {
    /// Current base fee per shard
    pub shard_base_fees: HashMap<ShardId, u128>,
    /// Total supply
    pub total_supply: TokenAmount,
    /// Total staked
    pub total_staked: TokenAmount,
    /// Total burned
    pub total_burned: TokenAmount,
    /// Total MEV captured
    pub total_mev_captured: TokenAmount,
    /// Total slashed
    pub total_slashed: TokenAmount,
    /// Current epoch
    pub current_epoch: u64,
    /// Block height
    pub block_height: u64,
}

impl Default for EconomicState {
    fn default() -> Self {
        Self {
            shard_base_fees: HashMap::new(),
            total_supply: 0,
            total_staked: 0,
            total_burned: 0,
            total_mev_captured: 0,
            total_slashed: 0,
            current_epoch: 0,
            block_height: 0,
        }
    }
}

/// Main economics coordinator
#[derive(Debug)]
pub struct EconomicsManager {
    params: EconomicParams,
    fee_market: FeeMarket,
    slashing_manager: SlashingManager,
    reward_calculator: RewardCalculator,
    mev_distributor: MevDistributor,
    storage: EconomicStorage,
    state: EconomicState,
}

impl EconomicsManager {
    /// Create new economics manager
    pub async fn new(
        params: EconomicParams,
        storage_config: EconomicStorageConfig,
    ) -> Result<Self, AvoError> {
        let storage = EconomicStorage::new(storage_config).await?;
        let state = storage.load_state().await?.unwrap_or_default();

        let fee_market = FeeMarket::new(params.clone());
        let slashing_manager = SlashingManager::new(SlashingConfig::default(), None);
        let reward_calculator = RewardCalculator::new(params.clone());
        let mev_distributor = MevDistributor::new(params.clone());

        Ok(Self {
            params,
            fee_market,
            slashing_manager,
            reward_calculator,
            mev_distributor,
            storage,
            state,
        })
    }

    /// Get current base fee for a shard
    pub fn get_base_fee(&self, shard_id: ShardId) -> u128 {
        self.state
            .shard_base_fees
            .get(&shard_id)
            .copied()
            .unwrap_or(self.params.initial_base_fee)
    }

    /// Update base fee for a shard after block
    pub async fn update_base_fee(
        &mut self,
        shard_id: ShardId,
        gas_used: u64,
    ) -> Result<u128, AvoError> {
        let current_base_fee = self.get_base_fee(shard_id);
        let new_base_fee = self.fee_market.calculate_next_base_fee(
            current_base_fee,
            gas_used,
            self.params.target_gas_per_block,
        );

        self.state.shard_base_fees.insert(shard_id, new_base_fee);
        self.storage
            .save_base_fee(shard_id, new_base_fee, self.state.block_height)
            .await?;

        Ok(new_base_fee)
    }

    /// Process transaction fees
    pub async fn process_transaction_fees(
        &mut self,
        shard_id: ShardId,
        base_fee: u128,
        priority_fee: u128,
        gas_used: u64,
    ) -> Result<(TokenAmount, TokenAmount), AvoError> {
        let total_base_fee = base_fee * gas_used as u128;
        let total_priority_fee = priority_fee * gas_used as u128;

        // 🔥 BURN 100% of all fees (completely deflationary)
        let burn_amount = total_base_fee + total_priority_fee;
        let validator_base_fee = 0; // Validators get 0% (100% burned)

        self.state.total_burned += burn_amount;
        self.storage
            .record_burn(burn_amount, self.state.block_height)
            .await?;

        Ok((validator_base_fee, burn_amount))
    }

    /// Detect and process slashing events
    pub async fn process_slashing_detection(
        &mut self,
        validator_id: u64,
        evidence: Vec<u8>,
    ) -> Result<Option<TokenAmount>, AvoError> {
        tracing::warn!(
            "Slashing evidence processing not yet integrated with new manager: validator {}",
            validator_id
        );
        let _ = evidence;
        Ok(None)
    }

    /// Calculate and distribute block rewards
    pub async fn distribute_block_reward(
        &mut self,
        validator_id: u64,
        delegator_stakes: Vec<(u64, TokenAmount)>,
    ) -> Result<RewardDistribution, AvoError> {
        let distribution = self.reward_calculator.calculate_reward_distribution(
            self.params.block_reward,
            validator_id,
            delegator_stakes,
        )?;

        self.storage
            .record_reward_distribution(&distribution, self.state.block_height)
            .await?;

        Ok(distribution)
    }

    /// Capture and distribute MEV
    pub async fn process_mev_capture(
        &mut self,
        mev_amount: TokenAmount,
        validator_id: u64,
    ) -> Result<(), AvoError> {
        self.state.total_mev_captured += mev_amount;

        let distribution = self
            .mev_distributor
            .distribute_mev(mev_amount, validator_id)?;

        self.storage
            .record_mev_distribution(&distribution, self.state.block_height)
            .await?;

        Ok(())
    }

    /// Get current economic state
    pub fn get_state(&self) -> &EconomicState {
        &self.state
    }

    /// Advance to next block
    pub async fn advance_block(&mut self) -> Result<(), AvoError> {
        self.state.block_height += 1;
        self.storage.save_state(&self.state).await?;
        Ok(())
    }

    /// Advance to next epoch
    pub async fn advance_epoch(&mut self) -> Result<(), AvoError> {
        self.state.current_epoch += 1;
        self.storage.save_state(&self.state).await?;
        Ok(())
    }

    /// Record validator participation for slashing tracking
    pub async fn record_block_participation(
        &mut self,
        validator_id: u64,
        _block_height: u64,
        participated: bool,
    ) -> Result<Option<crate::economics::slashing_manager::SlashingEvent>, AvoError> {
        let validator_id: ValidatorId = validator_id
            .try_into()
            .map_err(|_| AvoError::consensus("Validator ID overflow for slashing tracking"))?;

        self.slashing_manager
            .record_validator_activity(validator_id, self.state.current_epoch, participated)
            .await
    }

    /// Get economic parameters
    pub fn params(&self) -> &EconomicParams {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_economics_manager_initialization() {
        let temp_dir = tempdir().unwrap();
        let config = EconomicStorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            chain_state_path: temp_dir.path().join("chain_state.json"),
        };

        let params = EconomicParams::default();
        let manager = EconomicsManager::new(params, config).await.unwrap();

        assert_eq!(manager.state.block_height, 0);
        assert_eq!(manager.state.current_epoch, 0);
    }

    #[tokio::test]
    async fn test_base_fee_update() {
        let temp_dir = tempdir().unwrap();
        let config = EconomicStorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            chain_state_path: temp_dir.path().join("chain_state.json"),
        };

        let params = EconomicParams::default();
        let mut manager = EconomicsManager::new(params.clone(), config).await.unwrap();

        let shard_id = 0;
        let initial_fee = manager.get_base_fee(shard_id);
        assert_eq!(initial_fee, params.initial_base_fee);

        // Simulate block with high gas usage
        let new_fee = manager
            .update_base_fee(shard_id, params.target_gas_per_block * 2)
            .await
            .unwrap();

        assert!(new_fee > initial_fee);
    }

    #[tokio::test]
    async fn test_fee_burning() {
        let temp_dir = tempdir().unwrap();
        let config = EconomicStorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            chain_state_path: temp_dir.path().join("chain_state.json"),
        };

        let params = EconomicParams::default();
        let mut manager = EconomicsManager::new(params.clone(), config).await.unwrap();

        let (validator_fee, burned) = manager
            .process_transaction_fees(0, 10_000_000_000, 1_000_000_000, 21000)
            .await
            .unwrap();

        assert!(burned > 0);
        assert!(validator_fee > 0);
        assert_eq!(manager.state.total_burned, burned);
    }
}
