//! # Economic Storage Module
//!
//! Persistent storage for all economic state using RocksDB.
//! Handles base fees, rewards, slashing events, MEV distributions, and economic snapshots.

use crate::economics::{
    EconomicState, MevDistribution, RewardDistribution, SlashingEvent, SlashingReason,
};
use crate::error::AvoError;
use crate::types::{ShardId, TokenAmount};
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

/// Storage configuration
#[derive(Debug, Clone)]
pub struct EconomicStorageConfig {
    pub base_path: PathBuf,
    pub chain_state_path: PathBuf,
}

/// Column families for economic data
const CF_ECONOMIC_STATE: &str = "economic_state";
const CF_BASE_FEES: &str = "base_fees";
const CF_REWARDS: &str = "rewards";
const CF_SLASHING: &str = "slashing";
const CF_MEV: &str = "mev";
const CF_BURNS: &str = "burns";
const CF_SNAPSHOTS: &str = "snapshots";

/// Economic storage manager
#[derive(Debug, Clone)]
pub struct EconomicStorage {
    db: Arc<DB>,
}

impl EconomicStorage {
    /// Create new economic storage
    pub async fn new(config: EconomicStorageConfig) -> Result<Self, AvoError> {
        let db_path = config.base_path.join("economics");
        std::fs::create_dir_all(&db_path)
            .map_err(|e| AvoError::storage(&format!("Failed to create economics DB dir: {}", e)))?;

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_ECONOMIC_STATE, Options::default()),
            ColumnFamilyDescriptor::new(CF_BASE_FEES, Options::default()),
            ColumnFamilyDescriptor::new(CF_REWARDS, Options::default()),
            ColumnFamilyDescriptor::new(CF_SLASHING, Options::default()),
            ColumnFamilyDescriptor::new(CF_MEV, Options::default()),
            ColumnFamilyDescriptor::new(CF_BURNS, Options::default()),
            ColumnFamilyDescriptor::new(CF_SNAPSHOTS, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&db_opts, &db_path, cfs)
            .map_err(|e| AvoError::storage(&format!("Failed to open economics DB: {}", e)))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Save current economic state
    pub async fn save_state(&self, state: &EconomicState) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle(CF_ECONOMIC_STATE)
            .ok_or_else(|| AvoError::storage("Economic state CF not found"))?;

        let key = b"current_state";
        let value = bincode::serialize(state)
            .map_err(|e| AvoError::storage(&format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(&cf, key, value)
            .map_err(|e| AvoError::storage(&format!("Failed to save state: {}", e)))?;

        Ok(())
    }

    /// Load economic state
    pub async fn load_state(&self) -> Result<Option<EconomicState>, AvoError> {
        let cf = self
            .db
            .cf_handle(CF_ECONOMIC_STATE)
            .ok_or_else(|| AvoError::storage("Economic state CF not found"))?;

        let key = b"current_state";

        match self.db.get_cf(&cf, key) {
            Ok(Some(value)) => {
                let state = bincode::deserialize(&value)
                    .map_err(|e| AvoError::storage(&format!("Deserialization error: {}", e)))?;
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::storage(&format!("Failed to load state: {}", e))),
        }
    }

    /// Save base fee for shard
    pub async fn save_base_fee(
        &self,
        shard_id: ShardId,
        base_fee: u128,
        block_height: u64,
    ) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle(CF_BASE_FEES)
            .ok_or_else(|| AvoError::storage("Base fees CF not found"))?;

        let key = format!("{}:{}", shard_id, block_height);
        let record = BaseFeeRecord {
            shard_id,
            base_fee,
            block_height,
            timestamp: current_timestamp(),
        };

        let value = bincode::serialize(&record)
            .map_err(|e| AvoError::storage(&format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(&cf, key.as_bytes(), value)
            .map_err(|e| AvoError::storage(&format!("Failed to save base fee: {}", e)))?;

        // Also save latest for quick lookup
        let latest_key = format!("latest:{}", shard_id);
        self.db
            .put_cf(&cf, latest_key.as_bytes(), &base_fee.to_le_bytes())
            .map_err(|e| AvoError::storage(&format!("Failed to save latest base fee: {}", e)))?;

        Ok(())
    }

    /// Load latest base fee for shard
    pub async fn load_latest_base_fee(&self, shard_id: ShardId) -> Result<Option<u128>, AvoError> {
        let cf = self
            .db
            .cf_handle(CF_BASE_FEES)
            .ok_or_else(|| AvoError::storage("Base fees CF not found"))?;

        let key = format!("latest:{}", shard_id);

        match self.db.get_cf(&cf, key.as_bytes()) {
            Ok(Some(value)) => {
                if value.len() == 16 {
                    let bytes: [u8; 16] = value.try_into().unwrap();
                    Ok(Some(u128::from_le_bytes(bytes)))
                } else {
                    Ok(None)
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::storage(&format!(
                "Failed to load base fee: {}",
                e
            ))),
        }
    }

    /// Record reward distribution
    pub async fn record_reward_distribution(
        &self,
        distribution: &RewardDistribution,
        block_height: u64,
    ) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle(CF_REWARDS)
            .ok_or_else(|| AvoError::storage("Rewards CF not found"))?;

        let key = format!("{}:{}", block_height, distribution.validator_id);
        let value = bincode::serialize(distribution)
            .map_err(|e| AvoError::storage(&format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(&cf, key.as_bytes(), value)
            .map_err(|e| AvoError::storage(&format!("Failed to save reward: {}", e)))?;

        Ok(())
    }

    /// Load reward distributions for block
    pub async fn load_rewards_for_block(
        &self,
        block_height: u64,
    ) -> Result<Vec<RewardDistribution>, AvoError> {
        let cf = self
            .db
            .cf_handle(CF_REWARDS)
            .ok_or_else(|| AvoError::storage("Rewards CF not found"))?;

        let prefix = format!("{}:", block_height);
        let mut distributions = Vec::new();

        let iter = self.db.prefix_iterator_cf(&cf, prefix.as_bytes());
        for item in iter {
            match item {
                Ok((key, value)) => {
                    if key.starts_with(prefix.as_bytes()) {
                        if let Ok(dist) = bincode::deserialize::<RewardDistribution>(&value) {
                            distributions.push(dist);
                        }
                    } else {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        Ok(distributions)
    }

    /// Record slashing event
    pub async fn record_slashing(
        &self,
        validator_id: u64,
        slash_amount: TokenAmount,
        reason: SlashingReason,
        block_height: u64,
    ) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle(CF_SLASHING)
            .ok_or_else(|| AvoError::storage("Slashing CF not found"))?;

        let key = format!("{}:{}", block_height, validator_id);
        let record = SlashingRecord {
            validator_id,
            slash_amount,
            reason,
            block_height,
            timestamp: current_timestamp(),
        };

        let value = bincode::serialize(&record)
            .map_err(|e| AvoError::storage(&format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(&cf, key.as_bytes(), value)
            .map_err(|e| AvoError::storage(&format!("Failed to save slashing: {}", e)))?;

        Ok(())
    }

    /// Load slashing history for validator
    pub(crate) async fn load_slashing_history(
        &self,
        validator_id: u64,
        limit: usize,
    ) -> Result<Vec<SlashingRecord>, AvoError> {
        let cf = self
            .db
            .cf_handle(CF_SLASHING)
            .ok_or_else(|| AvoError::storage("Slashing CF not found"))?;

        let mut records = Vec::new();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::End);

        for item in iter {
            if records.len() >= limit {
                break;
            }

            match item {
                Ok((_key, value)) => {
                    if let Ok(record) = bincode::deserialize::<SlashingRecord>(&value) {
                        if record.validator_id == validator_id {
                            records.push(record);
                        }
                    }
                }
                Err(_) => break,
            }
        }

        Ok(records)
    }

    /// Record MEV distribution
    pub async fn record_mev_distribution(
        &self,
        distribution: &MevDistribution,
        block_height: u64,
    ) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle(CF_MEV)
            .ok_or_else(|| AvoError::storage("MEV CF not found"))?;

        let key = format!("{}:{}", block_height, distribution.validator_id);
        let value = bincode::serialize(distribution)
            .map_err(|e| AvoError::storage(&format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(&cf, key.as_bytes(), value)
            .map_err(|e| AvoError::storage(&format!("Failed to save MEV: {}", e)))?;

        Ok(())
    }

    /// Load MEV distributions for epoch
    pub async fn load_mev_for_epoch(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<MevDistribution>, AvoError> {
        let cf = self
            .db
            .cf_handle(CF_MEV)
            .ok_or_else(|| AvoError::storage("MEV CF not found"))?;

        let mut distributions = Vec::new();

        for block in start_block..=end_block {
            let prefix = format!("{}:", block);
            let iter = self.db.prefix_iterator_cf(&cf, prefix.as_bytes());

            for item in iter {
                match item {
                    Ok((key, value)) => {
                        if key.starts_with(prefix.as_bytes()) {
                            if let Ok(dist) = bincode::deserialize::<MevDistribution>(&value) {
                                distributions.push(dist);
                            }
                        } else {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        Ok(distributions)
    }

    /// Record token burn
    pub async fn record_burn(
        &self,
        burn_amount: TokenAmount,
        block_height: u64,
    ) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle(CF_BURNS)
            .ok_or_else(|| AvoError::storage("Burns CF not found"))?;

        let key = block_height.to_le_bytes();
        let record = BurnRecord {
            burn_amount,
            block_height,
            timestamp: current_timestamp(),
        };

        let value = bincode::serialize(&record)
            .map_err(|e| AvoError::storage(&format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(&cf, &key, value)
            .map_err(|e| AvoError::storage(&format!("Failed to save burn: {}", e)))?;

        Ok(())
    }

    /// Get total burned tokens
    pub async fn get_total_burned(&self) -> Result<TokenAmount, AvoError> {
        let cf = self
            .db
            .cf_handle(CF_BURNS)
            .ok_or_else(|| AvoError::storage("Burns CF not found"))?;

        let mut total = 0u128;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);

        for item in iter {
            match item {
                Ok((_key, value)) => {
                    if let Ok(record) = bincode::deserialize::<BurnRecord>(&value) {
                        total += record.burn_amount;
                    }
                }
                Err(_) => break,
            }
        }

        Ok(total)
    }

    /// Create economic snapshot
    pub async fn create_snapshot(&self, epoch: u64, state: &EconomicState) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle(CF_SNAPSHOTS)
            .ok_or_else(|| AvoError::storage("Snapshots CF not found"))?;

        let key = epoch.to_le_bytes();
        let value = bincode::serialize(state)
            .map_err(|e| AvoError::storage(&format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(&cf, &key, value)
            .map_err(|e| AvoError::storage(&format!("Failed to save snapshot: {}", e)))?;

        Ok(())
    }

    /// Load economic snapshot
    pub async fn load_snapshot(&self, epoch: u64) -> Result<Option<EconomicState>, AvoError> {
        let cf = self
            .db
            .cf_handle(CF_SNAPSHOTS)
            .ok_or_else(|| AvoError::storage("Snapshots CF not found"))?;

        let key = epoch.to_le_bytes();

        match self.db.get_cf(&cf, &key) {
            Ok(Some(value)) => {
                let state = bincode::deserialize(&value)
                    .map_err(|e| AvoError::storage(&format!("Deserialization error: {}", e)))?;
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::storage(&format!(
                "Failed to load snapshot: {}",
                e
            ))),
        }
    }
}

/// Base fee record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaseFeeRecord {
    shard_id: ShardId,
    base_fee: u128,
    block_height: u64,
    timestamp: u64,
}

/// Slashing record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SlashingRecord {
    validator_id: u64,
    slash_amount: TokenAmount,
    reason: SlashingReason,
    block_height: u64,
    timestamp: u64,
}

/// Burn record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BurnRecord {
    burn_amount: TokenAmount,
    block_height: u64,
    timestamp: u64,
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
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_storage_initialization() {
        let temp_dir = tempdir().unwrap();
        let config = EconomicStorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            chain_state_path: temp_dir.path().join("chain_state.json"),
        };

        let storage = EconomicStorage::new(config).await.unwrap();
        assert!(storage.db.cf_handle(CF_ECONOMIC_STATE).is_some());
    }

    #[tokio::test]
    async fn test_save_and_load_state() {
        let temp_dir = tempdir().unwrap();
        let config = EconomicStorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            chain_state_path: temp_dir.path().join("chain_state.json"),
        };

        let storage = EconomicStorage::new(config).await.unwrap();

        let mut state = EconomicState::default();
        state.total_supply = 1_000_000;
        state.total_staked = 500_000;

        storage.save_state(&state).await.unwrap();

        let loaded = storage.load_state().await.unwrap().unwrap();
        assert_eq!(loaded.total_supply, 1_000_000);
        assert_eq!(loaded.total_staked, 500_000);
    }

    #[tokio::test]
    async fn test_base_fee_persistence() {
        let temp_dir = tempdir().unwrap();
        let config = EconomicStorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            chain_state_path: temp_dir.path().join("chain_state.json"),
        };

        let storage = EconomicStorage::new(config).await.unwrap();

        storage.save_base_fee(0, 10_000_000_000, 100).await.unwrap();

        let loaded = storage.load_latest_base_fee(0).await.unwrap().unwrap();
        assert_eq!(loaded, 10_000_000_000);
    }

    #[tokio::test]
    async fn test_burn_tracking() {
        let temp_dir = tempdir().unwrap();
        let config = EconomicStorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            chain_state_path: temp_dir.path().join("chain_state.json"),
        };

        let storage = EconomicStorage::new(config).await.unwrap();

        storage.record_burn(1000, 100).await.unwrap();
        storage.record_burn(2000, 101).await.unwrap();
        storage.record_burn(3000, 102).await.unwrap();

        let total = storage.get_total_burned().await.unwrap();
        assert_eq!(total, 6000);
    }

    #[tokio::test]
    async fn test_snapshot_creation() {
        let temp_dir = tempdir().unwrap();
        let config = EconomicStorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            chain_state_path: temp_dir.path().join("chain_state.json"),
        };

        let storage = EconomicStorage::new(config).await.unwrap();

        let mut state = EconomicState::default();
        state.current_epoch = 42;
        state.total_supply = 999_999;

        storage.create_snapshot(42, &state).await.unwrap();

        let loaded = storage.load_snapshot(42).await.unwrap().unwrap();
        assert_eq!(loaded.current_epoch, 42);
        assert_eq!(loaded.total_supply, 999_999);
    }
}
