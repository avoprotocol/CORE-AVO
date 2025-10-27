//! # Rewards Module
//!
//! Real reward calculation and distribution for validators and delegators.
//! Handles block rewards, epoch rewards, and compounding.

use crate::economics::EconomicParams;
use crate::error::AvoError;
use crate::types::TokenAmount;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Reward distribution breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    pub validator_id: u64,
    pub block_height: u64,
    pub epoch: u64,
    pub total_reward: TokenAmount,
    pub validator_reward: TokenAmount,
    pub validator_commission: TokenAmount,
    pub delegator_rewards: HashMap<u64, TokenAmount>,
    pub timestamp: u64,
}

/// Reward calculator
#[derive(Debug, Clone)]
pub struct RewardCalculator {
    params: EconomicParams,
}

impl RewardCalculator {
    pub fn new(params: EconomicParams) -> Self {
        Self { params }
    }

    /// Calculate reward distribution for a block
    pub fn calculate_reward_distribution(
        &self,
        block_reward: TokenAmount,
        validator_id: u64,
        delegator_stakes: Vec<(u64, TokenAmount)>,
    ) -> Result<RewardDistribution, AvoError> {
        let total_delegated_stake: TokenAmount =
            delegator_stakes.iter().map(|(_, stake)| stake).sum();

        // Calculate validator commission
        let validator_commission =
            ((block_reward as f64) * self.params.validator_commission) as TokenAmount;

        // Remaining reward for distribution
        let distributable_reward = block_reward - validator_commission;

        // Calculate delegator rewards proportionally
        let mut delegator_rewards = HashMap::new();

        if total_delegated_stake > 0 {
            for (delegator_id, stake) in delegator_stakes {
                let delegator_share = (distributable_reward as f64
                    * (stake as f64 / total_delegated_stake as f64))
                    as TokenAmount;
                delegator_rewards.insert(delegator_id, delegator_share);
            }
        }

        // Validator gets commission + their own stake share
        let validator_reward = validator_commission
            + delegator_rewards
                .get(&validator_id)
                .copied()
                .unwrap_or(distributable_reward);

        Ok(RewardDistribution {
            validator_id,
            block_height: 0,
            epoch: 0,
            total_reward: block_reward,
            validator_reward,
            validator_commission,
            delegator_rewards,
            timestamp: current_timestamp(),
        })
    }

    /// Calculate epoch rewards with inflation adjustment
    pub fn calculate_epoch_reward(
        &self,
        total_staked: TokenAmount,
        total_supply: TokenAmount,
        blocks_per_epoch: u64,
    ) -> TokenAmount {
        // Annual inflation target
        let annual_inflation = (total_supply as f64) * self.params.annual_inflation_rate;

        // Epochs per year (assuming 6 second blocks)
        let blocks_per_year = 365 * 24 * 60 * 10; // ~5.25M blocks
        let epochs_per_year = blocks_per_year / blocks_per_epoch;

        // Epoch inflation
        let epoch_inflation = annual_inflation / (epochs_per_year as f64);

        // Adjust based on staking ratio
        let staking_ratio = (total_staked as f64) / (total_supply as f64);
        let adjusted_inflation = if staking_ratio < 0.5 {
            // Boost rewards if staking is low
            epoch_inflation * (1.0 + (0.5 - staking_ratio))
        } else if staking_ratio > 0.8 {
            // Reduce rewards if staking is too high
            epoch_inflation * (1.0 - (staking_ratio - 0.8) * 0.5)
        } else {
            epoch_inflation
        };

        adjusted_inflation as TokenAmount
    }

    /// Calculate APY for a validator based on performance
    pub fn calculate_validator_apy(
        &self,
        validator_stake: TokenAmount,
        delegated_stake: TokenAmount,
        blocks_produced: u64,
        total_blocks_possible: u64,
        total_supply: TokenAmount,
    ) -> f64 {
        if total_blocks_possible == 0 {
            return 0.0;
        }

        let total_validator_stake = validator_stake + delegated_stake;
        let uptime_ratio = (blocks_produced as f64) / (total_blocks_possible as f64);

        // Base APY from inflation
        let base_apy = self.params.annual_inflation_rate;

        // Adjust for validator commission
        let effective_apy = base_apy * (1.0 - self.params.validator_commission);

        // Adjust for uptime
        let performance_adjusted_apy = effective_apy * uptime_ratio;

        // Adjust for staking ratio
        let staking_ratio = (total_validator_stake as f64) / (total_supply as f64);
        let final_apy = if staking_ratio < 0.01 {
            performance_adjusted_apy * 1.5 // Boost for early stakers
        } else {
            performance_adjusted_apy
        };

        final_apy
    }

    /// Calculate compounded rewards over time
    pub fn calculate_compounded_rewards(
        &self,
        initial_stake: TokenAmount,
        apy: f64,
        epochs: u64,
    ) -> TokenAmount {
        let rate_per_epoch = apy / 365.0; // Assuming ~daily epochs
        let compound_factor = (1.0 + rate_per_epoch).powi(epochs as i32);
        let final_amount = (initial_stake as f64) * compound_factor;
        let rewards = final_amount - (initial_stake as f64);
        rewards as TokenAmount
    }

    /// Calculate penalty-adjusted rewards
    pub fn apply_performance_penalty(
        &self,
        base_reward: TokenAmount,
        blocks_produced: u64,
        blocks_expected: u64,
    ) -> TokenAmount {
        if blocks_expected == 0 {
            return base_reward;
        }

        let performance_ratio = (blocks_produced as f64) / (blocks_expected as f64);

        // Apply linear penalty for poor performance
        if performance_ratio < 0.5 {
            // Below 50% performance, reduce rewards significantly
            ((base_reward as f64) * performance_ratio * 0.5) as TokenAmount
        } else if performance_ratio < 0.9 {
            // Between 50-90%, linear reduction
            ((base_reward as f64) * performance_ratio) as TokenAmount
        } else {
            // Above 90%, full rewards
            base_reward
        }
    }
}

/// Reward accumulator for tracking pending distributions
#[derive(Debug, Default)]
pub struct RewardAccumulator {
    pending_validator_rewards: HashMap<u64, TokenAmount>,
    pending_delegator_rewards: HashMap<u64, TokenAmount>,
    total_pending: TokenAmount,
}

impl RewardAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_validator_reward(&mut self, validator_id: u64, amount: TokenAmount) {
        *self
            .pending_validator_rewards
            .entry(validator_id)
            .or_insert(0) += amount;
        self.total_pending += amount;
    }

    pub fn add_delegator_reward(&mut self, delegator_id: u64, amount: TokenAmount) {
        *self
            .pending_delegator_rewards
            .entry(delegator_id)
            .or_insert(0) += amount;
        self.total_pending += amount;
    }

    pub fn get_validator_pending(&self, validator_id: u64) -> TokenAmount {
        self.pending_validator_rewards
            .get(&validator_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn get_delegator_pending(&self, delegator_id: u64) -> TokenAmount {
        self.pending_delegator_rewards
            .get(&delegator_id)
            .copied()
            .unwrap_or(0)
    }

    pub fn claim_validator_reward(&mut self, validator_id: u64) -> TokenAmount {
        let amount = self
            .pending_validator_rewards
            .remove(&validator_id)
            .unwrap_or(0);
        self.total_pending -= amount;
        amount
    }

    pub fn claim_delegator_reward(&mut self, delegator_id: u64) -> TokenAmount {
        let amount = self
            .pending_delegator_rewards
            .remove(&delegator_id)
            .unwrap_or(0);
        self.total_pending -= amount;
        amount
    }

    pub fn total_pending(&self) -> TokenAmount {
        self.total_pending
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_params() -> EconomicParams {
        EconomicParams::default()
    }

    #[test]
    fn test_reward_distribution_with_delegators() {
        let params = default_params();
        let calculator = RewardCalculator::new(params.clone());

        let block_reward = 2_000_000_000_000_000_000u128; // 2 tokens
        let validator_id = 1;
        let delegator_stakes = vec![
            (validator_id, 50_000_000_000_000_000_000_000u128), // Validator: 50k
            (2, 30_000_000_000_000_000_000_000u128),            // Delegator 1: 30k
            (3, 20_000_000_000_000_000_000_000u128),            // Delegator 2: 20k
        ];

        let distribution = calculator
            .calculate_reward_distribution(block_reward, validator_id, delegator_stakes)
            .unwrap();

        assert_eq!(distribution.total_reward, block_reward);
        assert!(distribution.validator_commission > 0);
        assert!(distribution.validator_reward > distribution.validator_commission);
        assert_eq!(distribution.delegator_rewards.len(), 3);
    }

    #[test]
    fn test_reward_distribution_no_delegators() {
        let params = default_params();
        let calculator = RewardCalculator::new(params);

        let block_reward = 2_000_000_000_000_000_000u128;
        let validator_id = 1;

        let distribution = calculator
            .calculate_reward_distribution(block_reward, validator_id, vec![])
            .unwrap();

        assert_eq!(distribution.validator_reward, block_reward);
        assert!(distribution.delegator_rewards.is_empty());
    }

    #[test]
    fn test_epoch_reward_calculation() {
        let params = default_params();
        let calculator = RewardCalculator::new(params);

        let total_staked = 500_000_000_000_000_000_000_000u128; // 500k tokens
        let total_supply = 1_000_000_000_000_000_000_000_000u128; // 1M tokens
        let blocks_per_epoch = 14400; // ~1 day

        let epoch_reward =
            calculator.calculate_epoch_reward(total_staked, total_supply, blocks_per_epoch);

        assert!(epoch_reward > 0);
    }

    #[test]
    fn test_apy_calculation() {
        let params = default_params();
        let calculator = RewardCalculator::new(params);

        let validator_stake = 100_000_000_000_000_000_000_000u128;
        let delegated_stake = 400_000_000_000_000_000_000_000u128;
        let blocks_produced = 9000;
        let total_blocks = 10000;
        let total_supply = 1_000_000_000_000_000_000_000_000u128;

        let apy = calculator.calculate_validator_apy(
            validator_stake,
            delegated_stake,
            blocks_produced,
            total_blocks,
            total_supply,
        );

        assert!(apy > 0.0);
        assert!(apy < 1.0); // Should be reasonable percentage
    }

    #[test]
    fn test_compounded_rewards() {
        let params = default_params();
        let calculator = RewardCalculator::new(params);

        let initial_stake = 100_000_000_000_000_000_000_000u128;
        let apy = 0.05; // 5%
        let epochs = 365; // 1 year of daily epochs

        let rewards = calculator.calculate_compounded_rewards(initial_stake, apy, epochs);

        assert!(rewards > 0);
        assert!(rewards < initial_stake); // Rewards should be less than principal
    }

    #[test]
    fn test_performance_penalty() {
        let params = default_params();
        let calculator = RewardCalculator::new(params);

        let base_reward = 2_000_000_000_000_000_000u128;

        // 100% performance
        let full = calculator.apply_performance_penalty(base_reward, 100, 100);
        assert_eq!(full, base_reward);

        // 90% performance
        let ninety = calculator.apply_performance_penalty(base_reward, 90, 100);
        assert_eq!(ninety, base_reward);

        // 75% performance
        let seventy_five = calculator.apply_performance_penalty(base_reward, 75, 100);
        assert!(seventy_five < base_reward);

        // 40% performance (severe penalty)
        let forty = calculator.apply_performance_penalty(base_reward, 40, 100);
        assert!(forty < base_reward / 2);
    }

    #[test]
    fn test_reward_accumulator() {
        let mut accumulator = RewardAccumulator::new();

        accumulator.add_validator_reward(1, 1_000_000_000_000_000_000);
        accumulator.add_delegator_reward(2, 500_000_000_000_000_000);
        accumulator.add_delegator_reward(3, 300_000_000_000_000_000);

        assert_eq!(accumulator.total_pending(), 1_800_000_000_000_000_000);

        let claimed = accumulator.claim_validator_reward(1);
        assert_eq!(claimed, 1_000_000_000_000_000_000);
        assert_eq!(accumulator.total_pending(), 800_000_000_000_000_000);
    }

    #[test]
    fn test_proportional_delegator_distribution() {
        let params = default_params();
        let calculator = RewardCalculator::new(params);

        let block_reward = 1_000_000_000_000_000_000u128;
        let validator_id = 1;
        let delegator_stakes = vec![
            (2, 60_000_000_000_000_000_000_000u128), // 60% stake
            (3, 40_000_000_000_000_000_000_000u128), // 40% stake
        ];

        let distribution = calculator
            .calculate_reward_distribution(block_reward, validator_id, delegator_stakes)
            .unwrap();

        let d2_reward = *distribution.delegator_rewards.get(&2).unwrap();
        let d3_reward = *distribution.delegator_rewards.get(&3).unwrap();

        // Check proportionality (allowing for rounding)
        let ratio = (d2_reward as f64) / (d3_reward as f64);
        assert!((ratio - 1.5).abs() < 0.1); // Should be ~1.5 (60/40)
    }
}
