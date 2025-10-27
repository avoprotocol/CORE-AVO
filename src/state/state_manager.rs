use crate::error::AvoError;
use crate::state::{
    merkle_tree::{MerkleProof, OptimizedMerkleTree},
    storage::{AvocadoStorage, StorageConfig, StorageKey},
};
use crate::types::{AccountId, BlockId, Hash, ShardId, TransactionId};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, RwLock};

/// Account state information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
    pub code_hash: Option<Hash>,
    pub storage_root: Hash,
    pub last_modified: u64,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            balance: 0,
            nonce: 0,
            code_hash: None,
            storage_root: [0u8; 32],
            last_modified: 0,
        }
    }
}

/// Transaction execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    pub transaction_id: TransactionId,
    pub status: TransactionStatus,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub logs: Vec<EventLog>,
    pub state_changes: Vec<StateChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    Success,
    Failed { reason: String },
    Reverted { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLog {
    pub address: AccountId,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub account: AccountId,
    pub field: StateField,
    pub old_value: Vec<u8>,
    pub new_value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateField {
    Balance,
    Nonce,
    Code,
    Storage(String),
}

/// State transition information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from_root: Hash,
    pub to_root: Hash,
    pub block_id: BlockId,
    pub shard_id: ShardId,
    pub transactions: Vec<TransactionId>,
    pub timestamp: u64,
}

/// State snapshot for rollbacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub root_hash: Hash,
    pub block_id: BlockId,
    pub shard_id: ShardId,
    pub account_states: HashMap<AccountId, AccountState>,
    pub timestamp: u64,
}

/// Configuration for state manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateManagerConfig {
    /// Maximum number of snapshots to keep
    pub max_snapshots: usize,
    /// Enable state pruning
    pub enable_pruning: bool,
    /// Pruning interval
    pub pruning_interval: Duration,
    /// Cache size for account states
    pub account_cache_size: usize,
    /// Enable cross-shard state verification
    pub enable_cross_shard_verification: bool,
}

impl Default for StateManagerConfig {
    fn default() -> Self {
        Self {
            max_snapshots: 100,
            enable_pruning: true,
            pruning_interval: Duration::from_secs(3600), // 1 hour
            account_cache_size: 10000,
            enable_cross_shard_verification: true,
        }
    }
}

/// Advanced state manager for AVO blockchain
pub struct StateManager {
    /// Configuration
    config: StateManagerConfig,
    /// Storage backend
    storage: Arc<AvocadoStorage>,
    /// Merkle tree for state root
    merkle_tree: Arc<RwLock<OptimizedMerkleTree>>,
    /// Account state cache
    account_cache: Arc<RwLock<HashMap<AccountId, AccountState>>>,
    /// Pending state changes
    pending_changes: Arc<RwLock<HashMap<AccountId, AccountState>>>,
    /// State snapshots for rollbacks
    snapshots: Arc<RwLock<BTreeMap<u64, StateSnapshot>>>,
    /// Transaction results cache
    tx_results: Arc<RwLock<HashMap<TransactionId, TransactionResult>>>,
    /// State transition history
    transitions: Arc<RwLock<Vec<StateTransition>>>,
    /// Current shard ID
    shard_id: ShardId,
    /// Cross-shard state synchronization
    cross_shard_states: Arc<RwLock<HashMap<ShardId, Hash>>>,
    /// Background task handles
    background_tasks: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
}

impl StateManager {
    /// Create new state manager
    pub fn new(
        shard_id: ShardId,
        config: StateManagerConfig,
        storage_config: StorageConfig,
    ) -> Self {
        let storage =
            Arc::new(AvocadoStorage::new(storage_config).expect("Failed to create storage"));
        let merkle_tree = Arc::new(RwLock::new(OptimizedMerkleTree::new()));

        Self {
            config,
            storage,
            merkle_tree,
            shard_id,
            account_cache: Arc::new(RwLock::new(HashMap::new())),
            pending_changes: Arc::new(RwLock::new(HashMap::new())),
            snapshots: Arc::new(RwLock::new(BTreeMap::new())),
            tx_results: Arc::new(RwLock::new(HashMap::new())),
            transitions: Arc::new(RwLock::new(Vec::new())),
            cross_shard_states: Arc::new(RwLock::new(HashMap::new())),
            background_tasks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Store account state in RocksDB
    async fn store_account_state(
        &self,
        account_id: &AccountId,
        state: &AccountState,
    ) -> Result<(), AvoError> {
        let key = format!("account_{}", hex::encode(account_id));
        let value = serde_json::to_string(state).map_err(|e| AvoError::StateError {
            reason: format!("Failed to serialize account state: {}", e),
        })?;

        self.storage.put_cf("accounts", &key, &value).await
    }

    /// Load account state from RocksDB
    async fn load_account_state(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<AccountState>, AvoError> {
        let key = format!("account_{}", hex::encode(account_id));

        match self.storage.get_cf("accounts", &key).await? {
            Some(value) => {
                let state: AccountState =
                    serde_json::from_str(&value).map_err(|e| AvoError::StateError {
                        reason: format!("Failed to deserialize account state: {}", e),
                    })?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Store pending change in RocksDB
    async fn store_pending_change(
        &self,
        account_id: &AccountId,
        state: &AccountState,
    ) -> Result<(), AvoError> {
        let key = format!("pending_{}", hex::encode(account_id));
        let value = serde_json::to_string(state).map_err(|e| AvoError::StateError {
            reason: format!("Failed to serialize pending change: {}", e),
        })?;

        self.storage.put_cf("pending_changes", &key, &value).await
    }

    /// Load pending change from RocksDB
    async fn load_pending_change(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<AccountState>, AvoError> {
        let key = format!("pending_{}", hex::encode(account_id));

        match self.storage.get_cf("pending_changes", &key).await? {
            Some(value) => {
                let state: AccountState =
                    serde_json::from_str(&value).map_err(|e| AvoError::StateError {
                        reason: format!("Failed to deserialize pending change: {}", e),
                    })?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Remove pending change from RocksDB
    async fn remove_pending_change(&self, account_id: &AccountId) -> Result<(), AvoError> {
        let key = format!("pending_{}", hex::encode(account_id));
        self.storage.delete_cf("pending_changes", &key).await
    }

    /// Store transaction result in RocksDB
    async fn store_transaction_result_internal(
        &self,
        result: &TransactionResult,
    ) -> Result<(), AvoError> {
        let key = format!("tx_{}", hex::encode(&result.transaction_id.0));
        let value = serde_json::to_string(result).map_err(|e| AvoError::StateError {
            reason: format!("Failed to serialize transaction result: {}", e),
        })?;

        self.storage.put_cf("transactions", &key, &value).await
    }

    /// Load transaction result from RocksDB
    async fn load_transaction_result(
        &self,
        tx_id: &TransactionId,
    ) -> Result<Option<TransactionResult>, AvoError> {
        let key = format!("tx_{}", hex::encode(&tx_id.0));

        match self.storage.get_cf("transactions", &key).await? {
            Some(value) => {
                let result: TransactionResult =
                    serde_json::from_str(&value).map_err(|e| AvoError::StateError {
                        reason: format!("Failed to deserialize transaction result: {}", e),
                    })?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Store cross-shard state in RocksDB
    async fn store_cross_shard_state(
        &self,
        shard_id: &ShardId,
        state_hash: &Hash,
    ) -> Result<(), AvoError> {
        let key = format!("cross_shard_{}", shard_id);
        let value = hex::encode(state_hash);

        self.storage.put_cf("cross_shard_state", &key, &value).await
    }

    /// Load cross-shard state from RocksDB
    async fn load_cross_shard_state(&self, shard_id: &ShardId) -> Result<Option<Hash>, AvoError> {
        let key = format!("cross_shard_{}", shard_id);

        match self.storage.get_cf("cross_shard_state", &key).await? {
            Some(value) => {
                let hash_bytes = hex::decode(&value).map_err(|e| AvoError::StateError {
                    reason: format!("Failed to decode cross-shard state hash: {}", e),
                })?;

                if hash_bytes.len() != 32 {
                    return Err(AvoError::StateError {
                        reason: "Invalid hash length".to_string(),
                    });
                }

                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_bytes);
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Get all pending changes from RocksDB (simplified version)
    async fn get_all_pending_changes(&self) -> Result<HashMap<AccountId, AccountState>, AvoError> {
        let mut aggregated = {
            let pending = self.pending_changes.read().await;
            pending.clone()
        };

        let entries = self
            .storage
            .get_cf_range_bytes("pending_changes", "pending_")
            .await?;

        for (key_bytes, value_bytes) in entries {
            let key_str = String::from_utf8(key_bytes).map_err(|e| AvoError::StateError {
                reason: format!("Failed to decode pending change key: {}", e),
            })?;

            if !key_str.starts_with("pending_") {
                continue;
            }

            let encoded_id = &key_str["pending_".len()..];
            let account_bytes = hex::decode(encoded_id).map_err(|e| AvoError::StateError {
                reason: format!("Failed to decode pending account id: {}", e),
            })?;
            let account_id =
                String::from_utf8(account_bytes).map_err(|e| AvoError::StateError {
                    reason: format!("Invalid UTF-8 in account id: {}", e),
                })?;

            let state: AccountState =
                serde_json::from_slice(&value_bytes).map_err(|e| AvoError::StateError {
                    reason: format!("Failed to deserialize pending change: {}", e),
                })?;

            aggregated.insert(account_id, state);
        }

        Ok(aggregated)
    }

    /// Clear all pending changes from RocksDB (simplified version)
    async fn clear_all_pending_changes(&self) -> Result<(), AvoError> {
        {
            let mut pending = self.pending_changes.write().await;
            pending.clear();
        }

        let entries = self
            .storage
            .get_cf_range_bytes("pending_changes", "pending_")
            .await?;
        for (key_bytes, _) in entries {
            let key_str = String::from_utf8(key_bytes).map_err(|e| AvoError::StateError {
                reason: format!("Failed to decode pending change key: {}", e),
            })?;
            self.storage.delete_cf("pending_changes", &key_str).await?;
        }

        Ok(())
    }

    /// Initialize state manager
    pub async fn initialize(&self) -> Result<(), AvoError> {
        // Initializing State Manager

        // Initialize storage
        self.storage.initialize().await?;

        // Load existing state root if any
        self.load_existing_state().await?;

        // Start background tasks
        self.start_background_tasks().await;

        // State Manager initialized
        Ok(())
    }

    /// Get current state root hash
    pub async fn get_state_root(&self) -> Hash {
        let merkle_tree = self.merkle_tree.read().await;
        merkle_tree.get_root_hash().await.unwrap_or([0u8; 32])
    }

    /// Get account state
    pub async fn get_account_state(
        &self,
        account_id: &AccountId,
    ) -> Result<AccountState, AvoError> {
        // Check cache first (still use in-memory cache for performance)
        {
            let cache = self.account_cache.read().await;
            if let Some(state) = cache.get(account_id) {
                return Ok(state.clone());
            }
        }

        // Check pending changes in RocksDB
        if let Some(state) = self.load_pending_change(account_id).await? {
            // Update cache for future access
            {
                let mut cache = self.account_cache.write().await;
                cache.insert(account_id.clone(), state.clone());
            }
            return Ok(state);
        }

        // Load from RocksDB storage
        if let Some(state) = self.load_account_state(account_id).await? {
            // Update cache
            {
                let mut cache = self.account_cache.write().await;
                cache.insert(account_id.clone(), state.clone());

                // Limit cache size
                if cache.len() > self.config.account_cache_size {
                    // Remove oldest entries (simple FIFO for demo)
                    let keys_to_remove: Vec<_> =
                        cache.keys().take(cache.len() / 10).cloned().collect();
                    for key in keys_to_remove {
                        cache.remove(&key);
                    }
                }
            }

            Ok(state)
        } else {
            // Return default state for new accounts
            Ok(AccountState::default())
        }
    }

    /// Update account state
    pub async fn update_account_state(
        &self,
        account_id: AccountId,
        state: AccountState,
    ) -> Result<(), AvoError> {
        // Store pending change in RocksDB
        self.store_pending_change(&account_id, &state).await?;

        {
            let mut pending = self.pending_changes.write().await;
            pending.insert(account_id.clone(), state.clone());
        }

        // Update cache for performance
        {
            let mut cache = self.account_cache.write().await;
            cache.insert(account_id, state);
        }

        Ok(())
    }

    /// Begin new transaction batch
    pub async fn begin_batch(&self) -> Result<(), AvoError> {
        // Clear pending changes from RocksDB for new batch
        self.clear_all_pending_changes().await?;

        Ok(())
    }

    /// Commit pending changes to storage and update state root
    pub async fn commit_batch(
        &self,
        block_id: BlockId,
        transactions: Vec<TransactionId>,
    ) -> Result<Hash, AvoError> {
        // Committing transaction batch

        let current_root = self.get_state_root().await;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Get pending changes from RocksDB
        let pending_changes = self.get_all_pending_changes().await?;

        if pending_changes.is_empty() {
            return Ok(current_root);
        }

        // Update storage with pending changes - store in accounts CF
        for (account_id, state) in &pending_changes {
            self.store_account_state(account_id, state).await?;
        }

        // Update Merkle tree with new account hashes
        {
            let merkle_tree = self.merkle_tree.clone();
            for (account_id, state) in &pending_changes {
                let account_hash = self.compute_account_hash(state);
                let change = crate::state::merkle_tree::StateChange {
                    account_id: account_id.clone(),
                    field: "account_state".to_string(),
                    old_value: None,
                    new_value: account_hash.to_vec(),
                    timestamp: timestamp,
                    transaction_id: crate::types::TransactionId([0u8; 32]), // Default for demo
                };
                merkle_tree.write().await.add_state_change(change).await?;
            }
            merkle_tree.write().await.apply_pending_changes().await?;
        }

        let new_root = self.get_state_root().await;

        // Create state transition record
        let transition = StateTransition {
            from_root: current_root,
            to_root: new_root,
            block_id,
            shard_id: self.shard_id,
            transactions,
            timestamp,
        };

        // Store transition
        {
            let mut transitions = self.transitions.write().await;
            transitions.push(transition);

            // Limit transition history
            if transitions.len() > 1000 {
                transitions.remove(0);
            }
        }

        // Clear pending changes after commit from RocksDB
        self.clear_all_pending_changes().await?;

        // Batch committed successfully
        Ok(new_root)
    }

    /// Rollback to previous state
    pub async fn rollback(&self, target_block: BlockId) -> Result<(), AvoError> {
        println!("⏪ Rolling back to block: {}", hex::encode(&target_block.0));

        // Find snapshot for target block
        let snapshot = {
            let snapshots = self.snapshots.read().await;
            snapshots
                .values()
                .find(|s| s.block_id == target_block)
                .cloned()
        };

        if let Some(snapshot) = snapshot {
            // Restore state from snapshot
            {
                let mut cache = self.account_cache.write().await;
                cache.clear();
                cache.extend(
                    snapshot
                        .account_states
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                );
            }

            // Update Merkle tree
            {
                let merkle_tree = self.merkle_tree.clone();
                *merkle_tree.write().await = OptimizedMerkleTree::new();

                for (account_id, state) in &snapshot.account_states {
                    let account_hash = self.compute_account_hash(state);
                    let change = crate::state::merkle_tree::StateChange {
                        account_id: account_id.clone(),
                        field: "account_state".to_string(),
                        old_value: None,
                        new_value: account_hash.to_vec(),
                        timestamp: snapshot.timestamp,
                        transaction_id: crate::types::TransactionId([0u8; 32]),
                    };
                    merkle_tree.write().await.add_state_change(change).await?;
                }
                merkle_tree.write().await.apply_pending_changes().await?;
            }

            // Clear pending changes
            {
                let mut pending = self.pending_changes.write().await;
                pending.clear();
            }

            println!(
                "✅ Successfully rolled back to block: {}",
                hex::encode(&target_block.0)
            );
            Ok(())
        } else {
            Err(AvoError::InvalidInput(format!(
                "No snapshot found for block: {}",
                hex::encode(&target_block.0)
            )))
        }
    }

    /// Create snapshot of current state
    pub async fn create_snapshot(&self, block_id: BlockId) -> Result<(), AvoError> {
        println!(
            "📸 Creating state snapshot for block: {}",
            hex::encode(&block_id.0)
        );

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Get current account states
        let account_states = {
            let cache = self.account_cache.read().await;
            cache.clone()
        };

        let snapshot = StateSnapshot {
            root_hash: self.get_state_root().await,
            block_id,
            shard_id: self.shard_id,
            account_states,
            timestamp,
        };

        // Store snapshot
        {
            let mut snapshots = self.snapshots.write().await;
            snapshots.insert(timestamp, snapshot);

            // Limit number of snapshots
            while snapshots.len() > self.config.max_snapshots {
                if let Some(oldest_key) = snapshots.keys().next().copied() {
                    snapshots.remove(&oldest_key);
                }
            }
        }

        println!(
            "✅ Snapshot created for block: {}",
            hex::encode(&block_id.0)
        );
        Ok(())
    }

    /// Get state proof for account
    pub async fn get_state_proof(&self, account_id: &AccountId) -> Result<MerkleProof, AvoError> {
        let merkle_tree = self.merkle_tree.read().await;
        // For demo purposes, generate proof for index 0
        // In production, you'd map account_id to actual leaf index
        merkle_tree.generate_proof(0).await
    }

    /// Verify state proof
    pub async fn verify_state_proof(
        &self,
        _account_id: &AccountId,
        proof: &MerkleProof,
        _root: &Hash,
    ) -> Result<bool, AvoError> {
        let merkle_tree = self.merkle_tree.read().await;
        merkle_tree.verify_proof(proof).await
    }

    /// Update cross-shard state information
    pub async fn update_cross_shard_state(
        &self,
        shard_id: ShardId,
        state_root: Hash,
    ) -> Result<(), AvoError> {
        // Store in RocksDB
        self.store_cross_shard_state(&shard_id, &state_root).await?;

        // Update cache for performance
        let mut cross_shard = self.cross_shard_states.write().await;
        cross_shard.insert(shard_id, state_root);
        Ok(())
    }

    /// Get cross-shard state roots
    pub async fn get_cross_shard_states(&self) -> HashMap<ShardId, Hash> {
        let cross_shard = self.cross_shard_states.read().await;
        cross_shard.clone()
    }

    /// Store transaction result
    pub async fn store_transaction_result(
        &self,
        result: TransactionResult,
    ) -> Result<(), AvoError> {
        // Store in RocksDB using internal method
        self.store_transaction_result_internal(&result).await?;

        // Update cache for performance
        let mut tx_results = self.tx_results.write().await;
        tx_results.insert(result.transaction_id, result);

        // Limit cache size
        if tx_results.len() > 10000 {
            // Remove oldest entries
            let keys_to_remove: Vec<_> = tx_results
                .keys()
                .take(tx_results.len() / 10)
                .cloned()
                .collect();
            for key in keys_to_remove {
                tx_results.remove(&key);
            }
        }

        Ok(())
    }

    /// Get transaction result
    pub async fn get_transaction_result(&self, tx_id: &TransactionId) -> Option<TransactionResult> {
        // Check cache first
        {
            let tx_results = self.tx_results.read().await;
            if let Some(result) = tx_results.get(tx_id) {
                return Some(result.clone());
            }
        }

        // Load from RocksDB
        if let Ok(Some(result)) = self.load_transaction_result(tx_id).await {
            // Update cache
            {
                let mut tx_results = self.tx_results.write().await;
                tx_results.insert(*tx_id, result.clone());
            }
            Some(result)
        } else {
            None
        }
    }

    /// Get state statistics
    pub async fn get_state_stats(&self) -> StateStats {
        let cache = self.account_cache.read().await;
        let pending = self.pending_changes.read().await;
        let snapshots = self.snapshots.read().await;
        let transitions = self.transitions.read().await;
        let cross_shard = self.cross_shard_states.read().await;

        StateStats {
            shard_id: self.shard_id,
            state_root: self.get_state_root().await,
            cached_accounts: cache.len(),
            pending_changes: pending.len(),
            snapshots_count: snapshots.len(),
            transitions_count: transitions.len(),
            cross_shard_count: cross_shard.len(),
        }
    }

    /// Compute hash of account state
    fn compute_account_hash(&self, state: &AccountState) -> Hash {
        let serialized = serde_json::to_vec(state).unwrap_or_default();
        let mut hasher = Sha3_256::new();
        hasher.update(&serialized);
        hasher.finalize().into()
    }

    /// Load existing state from storage
    async fn load_existing_state(&self) -> Result<(), AvoError> {
        // Load state root and rebuild Merkle tree if needed
        let state_key = StorageKey::Metadata("state_root".to_string());
        if let Some(root_data) = self.storage.get(&state_key).await? {
            if root_data.len() == 32 {
                let mut root = [0u8; 32];
                root.copy_from_slice(&root_data);
                println!("📂 Loaded existing state root: {}", hex::encode(&root));
            }
        }

        Ok(())
    }

    /// Start background maintenance tasks
    async fn start_background_tasks(&self) {
        if self.config.enable_pruning {
            let snapshots = Arc::clone(&self.snapshots);
            let config = self.config.clone();

            let pruning_task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(config.pruning_interval);
                loop {
                    interval.tick().await;

                    // Prune old snapshots
                    let mut snapshots_lock = snapshots.write().await;
                    while snapshots_lock.len() > config.max_snapshots {
                        if let Some(oldest_key) = snapshots_lock.keys().next().copied() {
                            snapshots_lock.remove(&oldest_key);
                        }
                    }
                }
            });

            let mut tasks = self.background_tasks.write().await;
            tasks.push(pruning_task);
        }
    }

    /// Shutdown state manager
    pub async fn shutdown(&self) -> Result<(), AvoError> {
        println!("🛑 Shutting down State Manager");

        // Stop background tasks
        let tasks = {
            let mut background_tasks = self.background_tasks.write().await;
            std::mem::take(&mut *background_tasks)
        };

        for task in tasks {
            task.abort();
        }

        // Shutdown storage
        self.storage.shutdown().await?;

        println!("✅ State Manager shut down cleanly");
        Ok(())
    }
}

/// State manager statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateStats {
    pub shard_id: ShardId,
    pub state_root: Hash,
    pub cached_accounts: usize,
    pub pending_changes: usize,
    pub snapshots_count: usize,
    pub transitions_count: usize,
    pub cross_shard_count: usize,
}
