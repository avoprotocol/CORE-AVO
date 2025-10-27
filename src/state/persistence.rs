use crate::error::{AvoError, AvoResult};
use crate::staking::{StakePosition, ValidatorRecord};
use crate::state::storage::AvocadoStorage;
use crate::types::Epoch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Default)]
pub struct ChainState {
    pub current_epoch: Epoch,
    pub last_block_height: u64,
    pub timestamp: u64,
    #[serde(default)]
    pub stake_positions: HashMap<String, StakePosition>,
    #[serde(default)]
    pub validators: HashMap<u32, ValidatorRecord>,
}

impl ChainState {
    /// Load chain state from disk, or create default if file doesn't exist
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> AvoResult<Self> {
        let path = path.as_ref();

        if path.exists() {
            let content = fs::read_to_string(path)
                .map_err(|e| crate::error::AvoError::IoError { source: e })?;

            let state: ChainState = serde_json::from_str(&content)
                .map_err(|e| crate::error::AvoError::JsonError { source: e })?;

            // Chain state loaded from storage
            Ok(state)
        } else {
            // Only print this message once during initial startup
            static PRINTED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !PRINTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                println!("📂 Creating new chain state (no existing state found)");
            }
            Ok(ChainState::default())
        }
    }

    /// Save current state to disk
    pub fn save<P: AsRef<Path>>(&self, path: P) -> AvoResult<()> {
        let path = path.as_ref();

        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| crate::error::AvoError::IoError { source: e })?;
        }

        let content = serde_json::to_string_pretty(self)
            .map_err(|e| crate::error::AvoError::JsonError { source: e })?;

        fs::write(path, content).map_err(|e| crate::error::AvoError::IoError { source: e })?;

        // Chain state saved
        Ok(())
    }

    /// Update and save the current epoch (static method for convenience)
    pub fn update_epoch<P: AsRef<Path>>(path: P, new_epoch: Epoch) -> AvoResult<()> {
        let mut chain_state = Self::load_or_create(&path)?;
        chain_state.current_epoch = new_epoch;
        chain_state.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        chain_state.save(path)
    }

    /// Add or update a validator record in the chain state
    pub fn upsert_validator<P: AsRef<Path>>(path: P, record: ValidatorRecord) -> AvoResult<()> {
        let mut chain_state = Self::load_or_create(&path)?;
        chain_state.validators.insert(record.id, record);
        chain_state.save(path)
    }

    /// Remove validator information from the chain state
    pub fn remove_validator<P: AsRef<Path>>(path: P, validator_id: u32) -> AvoResult<()> {
        let mut chain_state = Self::load_or_create(&path)?;
        chain_state.validators.remove(&validator_id);
        chain_state.save(path)
    }

    /// Fetch validator information from chain state
    pub fn get_validator<P: AsRef<Path>>(
        path: P,
        validator_id: u32,
    ) -> AvoResult<Option<ValidatorRecord>> {
        let chain_state = Self::load_or_create(&path)?;
        Ok(chain_state.validators.get(&validator_id).cloned())
    }

    /// Update and save the current block height
    pub fn update_height<P: AsRef<Path>>(path: P, new_height: u64) -> AvoResult<()> {
        let mut chain_state = Self::load_or_create(&path)?;
        chain_state.last_block_height = new_height;
        chain_state.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        chain_state.save(path)
    }

    /// Add or update a stake position in the chain state
    pub fn add_stake_position<P: AsRef<Path>>(path: P, position: StakePosition) -> AvoResult<()> {
        let mut chain_state = Self::load_or_create(&path)?;
        chain_state
            .stake_positions
            .insert(position.id.clone(), position);
        chain_state.save(path)
    }

    /// Remove a stake position from the chain state
    pub fn remove_stake_position<P: AsRef<Path>>(path: P, position_id: &str) -> AvoResult<()> {
        let mut chain_state = Self::load_or_create(&path)?;
        chain_state.stake_positions.remove(position_id);
        chain_state.save(path)
    }

    /// Get all stake positions for a specific owner
    pub fn get_user_stakes<P: AsRef<Path>>(path: P, owner: &str) -> AvoResult<Vec<StakePosition>> {
        let chain_state = Self::load_or_create(&path)?;
        let user_stakes: Vec<StakePosition> = chain_state
            .stake_positions
            .values()
            .filter(|pos| pos.owner == owner && pos.is_active)
            .cloned()
            .collect();
        Ok(user_stakes)
    }

    /// Get a specific stake position by ID
    pub fn get_stake_position<P: AsRef<Path>>(
        path: P,
        position_id: &str,
    ) -> AvoResult<Option<StakePosition>> {
        let chain_state = Self::load_or_create(&path)?;
        Ok(chain_state.stake_positions.get(position_id).cloned())
    }

    /// Load chain state from RocksDB, or create default if not exists
    pub async fn load_or_create_from_db(storage: Arc<AvocadoStorage>) -> AvoResult<Self> {
        match storage.get_state("chain_state").await {
            Ok(Some(data)) => {
                let chain_state: ChainState =
                    serde_json::from_slice(&data).map_err(|e| AvoError::JsonError { source: e })?;
                Ok(chain_state)
            }
            Ok(None) => {
                // Create default and save to RocksDB
                let default_state = ChainState::default();
                default_state.save_to_db(storage).await?;
                Ok(default_state)
            }
            Err(e) => Err(e),
        }
    }

    /// Save current state to RocksDB
    pub async fn save_to_db(&self, storage: Arc<AvocadoStorage>) -> AvoResult<()> {
        let serialized = serde_json::to_vec(self).map_err(|e| AvoError::JsonError { source: e })?;

        storage
            .store_state("chain_state", &serialized)
            .await
            .map_err(|e| AvoError::StorageError {
                reason: e.to_string(),
            })?;

        Ok(())
    }

    /// Update and save epoch to RocksDB
    pub async fn update_epoch_db(storage: Arc<AvocadoStorage>, new_epoch: Epoch) -> AvoResult<()> {
        let mut chain_state = Self::load_or_create_from_db(storage.clone()).await?;
        chain_state.current_epoch = new_epoch;
        chain_state.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        chain_state.save_to_db(storage).await
    }

    /// Update and save block height to RocksDB
    pub async fn update_height_db(storage: Arc<AvocadoStorage>, new_height: u64) -> AvoResult<()> {
        let mut chain_state = Self::load_or_create_from_db(storage.clone()).await?;
        chain_state.last_block_height = new_height;
        chain_state.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        chain_state.save_to_db(storage).await
    }

    /// Update and save both epoch and block height to RocksDB (for block creation)
    pub async fn update_block_height_db(
        storage: Arc<AvocadoStorage>,
        new_epoch: Epoch,
        new_height: u64,
    ) -> AvoResult<()> {
        let mut chain_state = Self::load_or_create_from_db(storage.clone()).await?;
        chain_state.current_epoch = new_epoch;
        chain_state.last_block_height = new_height;
        chain_state.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        chain_state.save_to_db(storage).await
    }
}
