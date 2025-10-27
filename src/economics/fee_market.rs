//! # Fee Market Module
//!
//! EIP-1559 inspired dynamic fee mechanism adapted for sharded architecture.
//! Each shard maintains its own base fee that adjusts based on block utilization.

use crate::economics::EconomicParams;
use crate::types::ShardId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fee market manager
#[derive(Debug, Clone)]
pub struct FeeMarket {
    params: EconomicParams,
}

impl FeeMarket {
    /// Create new fee market
    pub fn new(params: EconomicParams) -> Self {
        Self { params }
    }

    /// Calculate next base fee using EIP-1559 formula
    pub fn calculate_next_base_fee(
        &self,
        current_base_fee: u128,
        gas_used: u64,
        target_gas: u64,
    ) -> u128 {
        if gas_used == target_gas {
            return current_base_fee;
        }

        let gas_used_delta = if gas_used > target_gas {
            gas_used - target_gas
        } else {
            target_gas - gas_used
        };

        let base_fee_delta = (current_base_fee * gas_used_delta as u128)
            / (target_gas as u128 * self.params.base_fee_change_denominator as u128);

        let new_base_fee = if gas_used > target_gas {
            current_base_fee + base_fee_delta.max(1)
        } else {
            current_base_fee.saturating_sub(base_fee_delta)
        };

        // Clamp to min/max
        new_base_fee
            .max(self.params.min_base_fee)
            .min(self.params.max_base_fee)
    }

    /// Calculate effective priority fee
    pub fn calculate_effective_priority_fee(
        &self,
        max_priority_fee: u128,
        max_fee_per_gas: u128,
        base_fee: u128,
    ) -> u128 {
        let max_priority = max_priority_fee;
        let max_from_total = max_fee_per_gas.saturating_sub(base_fee);
        max_priority.min(max_from_total)
    }

    /// Validate transaction can pay fees
    pub fn validate_transaction_fees(
        &self,
        base_fee: u128,
        max_fee_per_gas: u128,
        max_priority_fee: u128,
        gas_limit: u64,
        sender_balance: u128,
    ) -> Result<(), String> {
        if max_fee_per_gas < base_fee {
            return Err(format!(
                "Max fee {} below base fee {}",
                max_fee_per_gas, base_fee
            ));
        }

        if max_priority_fee > max_fee_per_gas {
            return Err("Priority fee exceeds max fee".to_string());
        }

        let max_cost = max_fee_per_gas * gas_limit as u128;
        if sender_balance < max_cost {
            return Err(format!(
                "Insufficient balance: need {}, have {}",
                max_cost, sender_balance
            ));
        }

        Ok(())
    }
}

/// Per-shard fee state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardFeeState {
    pub shard_id: ShardId,
    pub current_base_fee: u128,
    pub block_number: u64,
    pub gas_used_history: Vec<u64>,
    pub base_fee_history: Vec<u128>,
}

impl ShardFeeState {
    pub fn new(shard_id: ShardId, initial_base_fee: u128) -> Self {
        Self {
            shard_id,
            current_base_fee: initial_base_fee,
            block_number: 0,
            gas_used_history: Vec::new(),
            base_fee_history: Vec::new(),
        }
    }

    pub fn update(&mut self, new_base_fee: u128, gas_used: u64) {
        self.current_base_fee = new_base_fee;
        self.block_number += 1;

        self.gas_used_history.push(gas_used);
        self.base_fee_history.push(new_base_fee);

        // Keep only last 100 blocks
        if self.gas_used_history.len() > 100 {
            self.gas_used_history.remove(0);
            self.base_fee_history.remove(0);
        }
    }

    pub fn average_gas_used(&self) -> u64 {
        if self.gas_used_history.is_empty() {
            return 0;
        }
        let sum: u64 = self.gas_used_history.iter().sum();
        sum / self.gas_used_history.len() as u64
    }

    pub fn average_base_fee(&self) -> u128 {
        if self.base_fee_history.is_empty() {
            return self.current_base_fee;
        }
        let sum: u128 = self.base_fee_history.iter().sum();
        sum / self.base_fee_history.len() as u128
    }
}

/// Multi-shard fee coordinator
#[derive(Debug)]
pub struct MultiShardFeeCoordinator {
    shard_states: HashMap<ShardId, ShardFeeState>,
    fee_market: FeeMarket,
}

impl MultiShardFeeCoordinator {
    pub fn new(params: EconomicParams, shard_ids: Vec<ShardId>) -> Self {
        let mut shard_states = HashMap::new();
        for shard_id in shard_ids {
            shard_states.insert(
                shard_id,
                ShardFeeState::new(shard_id, params.initial_base_fee),
            );
        }

        Self {
            shard_states,
            fee_market: FeeMarket::new(params),
        }
    }

    pub fn get_base_fee(&self, shard_id: ShardId) -> Option<u128> {
        self.shard_states
            .get(&shard_id)
            .map(|state| state.current_base_fee)
    }

    pub fn update_shard_fee(
        &mut self,
        shard_id: ShardId,
        gas_used: u64,
        target_gas: u64,
    ) -> Result<u128, String> {
        let state = self
            .shard_states
            .get_mut(&shard_id)
            .ok_or_else(|| format!("Shard {} not found", shard_id))?;

        let new_base_fee =
            self.fee_market
                .calculate_next_base_fee(state.current_base_fee, gas_used, target_gas);

        state.update(new_base_fee, gas_used);
        Ok(new_base_fee)
    }

    pub fn get_shard_state(&self, shard_id: ShardId) -> Option<&ShardFeeState> {
        self.shard_states.get(&shard_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_params() -> EconomicParams {
        EconomicParams::default()
    }

    #[test]
    fn test_base_fee_increase_on_high_usage() {
        let params = default_params();
        let fee_market = FeeMarket::new(params.clone());

        let current_fee = params.initial_base_fee;
        let gas_used = params.target_gas_per_block * 2; // Double target
        let new_fee =
            fee_market.calculate_next_base_fee(current_fee, gas_used, params.target_gas_per_block);

        assert!(new_fee > current_fee);
    }

    #[test]
    fn test_base_fee_decrease_on_low_usage() {
        let params = default_params();
        let fee_market = FeeMarket::new(params.clone());

        let current_fee = params.initial_base_fee;
        let gas_used = params.target_gas_per_block / 2; // Half target
        let new_fee =
            fee_market.calculate_next_base_fee(current_fee, gas_used, params.target_gas_per_block);

        assert!(new_fee < current_fee);
    }

    #[test]
    fn test_base_fee_stable_at_target() {
        let params = default_params();
        let fee_market = FeeMarket::new(params.clone());

        let current_fee = params.initial_base_fee;
        let gas_used = params.target_gas_per_block;
        let new_fee =
            fee_market.calculate_next_base_fee(current_fee, gas_used, params.target_gas_per_block);

        assert_eq!(new_fee, current_fee);
    }

    #[test]
    fn test_base_fee_clamping() {
        let params = default_params();
        let fee_market = FeeMarket::new(params.clone());

        // Test min clamping
        let very_low_fee = params.min_base_fee / 2;
        let new_fee =
            fee_market.calculate_next_base_fee(very_low_fee, 0, params.target_gas_per_block);
        assert_eq!(new_fee, params.min_base_fee);

        // Test max clamping (simulate extreme congestion)
        let mut high_fee = params.max_base_fee - 1000;
        for _ in 0..100 {
            high_fee = fee_market.calculate_next_base_fee(
                high_fee,
                params.max_gas_per_block,
                params.target_gas_per_block,
            );
        }
        assert!(high_fee <= params.max_base_fee);
    }

    #[test]
    fn test_priority_fee_calculation() {
        let params = default_params();
        let fee_market = FeeMarket::new(params);

        let base_fee = 10_000_000_000u128;
        let max_fee = 15_000_000_000u128;
        let max_priority = 3_000_000_000u128;

        let effective_priority =
            fee_market.calculate_effective_priority_fee(max_priority, max_fee, base_fee);

        assert_eq!(effective_priority, 3_000_000_000);
    }

    #[test]
    fn test_fee_validation_insufficient_balance() {
        let params = default_params();
        let fee_market = FeeMarket::new(params);

        let result = fee_market.validate_transaction_fees(
            10_000_000_000,
            15_000_000_000,
            2_000_000_000,
            21000,
            100_000_000_000_000, // Not enough for gas_limit * max_fee
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_multi_shard_coordinator() {
        let params = default_params();
        let shard_ids = vec![0, 1, 2];
        let mut coordinator = MultiShardFeeCoordinator::new(params.clone(), shard_ids);

        // Update shard 0 with high usage
        let new_fee = coordinator
            .update_shard_fee(
                0,
                params.target_gas_per_block * 2,
                params.target_gas_per_block,
            )
            .unwrap();

        assert!(new_fee > params.initial_base_fee);

        // Check shard 1 remains at initial
        let shard_1_fee = coordinator.get_base_fee(1).unwrap();
        assert_eq!(shard_1_fee, params.initial_base_fee);
    }

    #[test]
    fn test_shard_state_history() {
        let mut state = ShardFeeState::new(0, 10_000_000_000);

        for i in 0..10 {
            state.update(
                10_000_000_000u128 + (i as u128) * 1_000_000_000u128,
                15_000_000u64 + (i as u64) * 100_000u64,
            );
        }

        assert_eq!(state.gas_used_history.len(), 10);
        assert_eq!(state.base_fee_history.len(), 10);
        assert!(state.average_gas_used() > 15_000_000);
        assert!(state.average_base_fee() > 10_000_000_000);
    }
}
