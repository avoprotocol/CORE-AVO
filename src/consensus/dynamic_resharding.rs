//! # Dynamic Resharding
//!
//! FASE 12.3: Dynamic shard split/merge with MMR-based state commitment
//! and seamless state migration protocol.

use crate::error::{AvoError, AvoResult};
use crate::types::{Address, BlockId, Epoch, Hash, ShardId, ValidatorId};
use crate::utils::hash;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for dynamic resharding
#[derive(Debug, Clone)]
pub struct ReshardingConfig {
    /// Minimum load factor to trigger split (0.0-1.0)
    pub split_threshold: f64,
    /// Maximum load factor to trigger merge (0.0-1.0)
    pub merge_threshold: f64,
    /// Evaluation period in epochs
    pub evaluation_period: u64,
    /// Minimum number of shards
    pub min_shards: usize,
    /// Maximum number of shards
    pub max_shards: usize,
    /// State migration batch size
    pub migration_batch_size: usize,
}

impl Default for ReshardingConfig {
    fn default() -> Self {
        Self {
            split_threshold: 0.8,  // Split when 80% full
            merge_threshold: 0.3,  // Merge when below 30%
            evaluation_period: 50, // Every 50 epochs
            min_shards: 2,
            max_shards: 64,
            migration_batch_size: 1000, // Migrate 1000 accounts per batch
        }
    }
}

/// Shard load metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardLoadMetrics {
    pub shard_id: ShardId,
    pub account_count: usize,
    pub transaction_rate: f64, // Transactions per second
    pub storage_bytes: usize,
    pub load_factor: f64, // 0.0-1.0
}

/// Merkle Mountain Range for efficient state commitments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Peaks of the mountain range
    peaks: Vec<Hash>,
    /// Total number of leaves
    leaf_count: usize,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            peaks: vec![],
            leaf_count: 0,
        }
    }

    /// Add a new leaf to the MMR
    pub fn append(&mut self, leaf: Hash) {
        self.leaf_count += 1;
        let mut peaks = self.peaks.clone();
        peaks.push(leaf);

        // Merge peaks where possible
        let mut i = peaks.len() - 1;
        while i > 0 {
            if self.should_merge(i - 1, peaks.len() - 1) {
                let right = peaks.pop().unwrap();
                let left = peaks.pop().unwrap();
                peaks.push(Self::hash_pair(&left, &right));
                i -= 1;
            } else {
                break;
            }
        }

        self.peaks = peaks;
    }

    /// Get the root hash of the MMR
    pub fn get_root(&self) -> Hash {
        if self.peaks.is_empty() {
            return [0u8; 32];
        }

        if self.peaks.len() == 1 {
            return self.peaks[0];
        }

        // Bag the peaks
        let mut hash = self.peaks[0];
        for peak in &self.peaks[1..] {
            hash = Self::hash_pair(&hash, peak);
        }
        hash
    }

    fn should_merge(&self, left_idx: usize, right_idx: usize) -> bool {
        // Check if both peaks represent complete subtrees of the same height
        let left_height = self.peak_height(left_idx);
        let right_height = self.peak_height(right_idx);
        left_height == right_height
    }

    fn peak_height(&self, idx: usize) -> usize {
        // Calculate height based on position in leaf_count
        let pos = self.leaf_count - (self.peaks.len() - idx);
        pos.trailing_zeros() as usize
    }

    fn hash_pair(left: &Hash, right: &Hash) -> Hash {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

/// Resharding operation type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReshardingOperation {
    /// Split one shard into two
    Split {
        source_shard: ShardId,
        new_shard_1: ShardId,
        new_shard_2: ShardId,
    },
    /// Merge two shards into one
    Merge {
        shard_1: ShardId,
        shard_2: ShardId,
        target_shard: ShardId,
    },
}

/// State migration plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub operation: ReshardingOperation,
    pub total_accounts: usize,
    pub batches: usize,
    pub accounts_per_batch: Vec<Vec<Address>>,
    pub state_root_before: Hash,
}

/// Migration progress tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationProgress {
    pub plan: MigrationPlan,
    pub batches_completed: usize,
    pub accounts_migrated: usize,
    pub started_at: Epoch,
    pub estimated_completion: Epoch,
}

/// State of a resharding operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReshardingState {
    /// Evaluating shard loads
    Evaluating,
    /// Planning resharding operation
    Planning,
    /// Migrating state
    Migrating { progress: usize },
    /// Finalizing new shard configuration
    Finalizing,
    /// Completed
    Completed,
}

/// Manager for dynamic resharding
pub struct DynamicReshardingManager {
    config: ReshardingConfig,
    /// Current shard topology
    active_shards: Arc<RwLock<HashSet<ShardId>>>,
    /// Shard load metrics
    shard_metrics: Arc<RwLock<HashMap<ShardId, ShardLoadMetrics>>>,
    /// Active migrations
    active_migrations: Arc<RwLock<HashMap<ShardId, MigrationProgress>>>,
    /// State MMR for each shard
    shard_mmr: Arc<RwLock<HashMap<ShardId, MerkleTree>>>,
    /// Shard account mappings (simplified - in production would be in state DB)
    account_mappings: Arc<RwLock<HashMap<Address, ShardId>>>,
}

impl DynamicReshardingManager {
    /// Create a new dynamic resharding manager
    pub fn new(config: ReshardingConfig, initial_shards: usize) -> Self {
        let mut active_shards = HashSet::new();
        for i in 0..initial_shards {
            active_shards.insert(i as ShardId);
        }

        Self {
            config,
            active_shards: Arc::new(RwLock::new(active_shards)),
            shard_metrics: Arc::new(RwLock::new(HashMap::new())),
            active_migrations: Arc::new(RwLock::new(HashMap::new())),
            shard_mmr: Arc::new(RwLock::new(HashMap::new())),
            account_mappings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update metrics for a shard
    pub async fn update_shard_metrics(&self, metrics: ShardLoadMetrics) {
        let mut shard_metrics = self.shard_metrics.write().await;
        shard_metrics.insert(metrics.shard_id, metrics);
    }

    /// Evaluate if resharding is needed
    pub async fn evaluate_resharding(&self) -> AvoResult<Option<ReshardingOperation>> {
        let shard_metrics = self.shard_metrics.read().await;
        let active_shards = self.active_shards.read().await;

        // Find overloaded shards (candidates for split)
        for (shard_id, metrics) in shard_metrics.iter() {
            if metrics.load_factor > self.config.split_threshold {
                if active_shards.len() < self.config.max_shards {
                    let new_shard_1 = self.get_next_shard_id(&active_shards).await;
                    let new_shard_2 = new_shard_1 + 1;

                    tracing::info!(
                        "📊 Shard {} overloaded ({:.2}%), planning split",
                        shard_id,
                        metrics.load_factor * 100.0
                    );

                    return Ok(Some(ReshardingOperation::Split {
                        source_shard: *shard_id,
                        new_shard_1,
                        new_shard_2,
                    }));
                }
            }
        }

        // Find underloaded shard pairs (candidates for merge)
        let underloaded: Vec<(ShardId, &ShardLoadMetrics)> = shard_metrics
            .iter()
            .filter(|(_, m)| m.load_factor < self.config.merge_threshold)
            .map(|(id, m)| (*id, m))
            .collect();

        if underloaded.len() >= 2 && active_shards.len() > self.config.min_shards {
            let shard_1 = underloaded[0].0;
            let shard_2 = underloaded[1].0;
            let target_shard = shard_1.min(shard_2);

            tracing::info!(
                "📊 Shards {} and {} underloaded, planning merge",
                shard_1,
                shard_2
            );

            return Ok(Some(ReshardingOperation::Merge {
                shard_1,
                shard_2,
                target_shard,
            }));
        }

        Ok(None)
    }

    /// Create migration plan for a resharding operation
    pub async fn create_migration_plan(
        &self,
        operation: ReshardingOperation,
    ) -> AvoResult<MigrationPlan> {
        let account_mappings = self.account_mappings.read().await;

        let (affected_shards, accounts): (Vec<ShardId>, Vec<Address>) = match &operation {
            ReshardingOperation::Split { source_shard, .. } => {
                let accounts: Vec<Address> = account_mappings
                    .iter()
                    .filter(|(_, shard)| *shard == source_shard)
                    .map(|(addr, _)| *addr)
                    .collect();
                (vec![*source_shard], accounts)
            }
            ReshardingOperation::Merge {
                shard_1, shard_2, ..
            } => {
                let accounts: Vec<Address> = account_mappings
                    .iter()
                    .filter(|(_, shard)| *shard == shard_1 || *shard == shard_2)
                    .map(|(addr, _)| *addr)
                    .collect();
                (vec![*shard_1, *shard_2], accounts)
            }
        };

        let total_accounts = accounts.len();
        let batch_size = self.config.migration_batch_size;
        let batches = (total_accounts + batch_size - 1) / batch_size;

        let mut accounts_per_batch = Vec::new();
        for chunk in accounts.chunks(batch_size) {
            accounts_per_batch.push(chunk.to_vec());
        }

        // Calculate state root before migration
        let state_root_before = self.calculate_state_root(&affected_shards).await?;

        let plan = MigrationPlan {
            operation,
            total_accounts,
            batches,
            accounts_per_batch,
            state_root_before,
        };

        tracing::info!(
            "📋 Created migration plan: {} accounts in {} batches",
            total_accounts,
            batches
        );

        Ok(plan)
    }

    /// Execute a migration batch
    pub async fn execute_migration_batch(
        &self,
        plan: &MigrationPlan,
        batch_index: usize,
    ) -> AvoResult<usize> {
        if batch_index >= plan.batches {
            return Err(AvoError::consensus(format!(
                "Batch index {} exceeds total batches {}",
                batch_index, plan.batches
            )));
        }

        let accounts = &plan.accounts_per_batch[batch_index];
        let mut account_mappings = self.account_mappings.write().await;
        let mut shard_mmr = self.shard_mmr.write().await;

        let target_shards = match &plan.operation {
            ReshardingOperation::Split {
                new_shard_1,
                new_shard_2,
                ..
            } => vec![*new_shard_1, *new_shard_2],
            ReshardingOperation::Merge { target_shard, .. } => vec![*target_shard],
        };

        // Migrate accounts
        for (idx, account) in accounts.iter().enumerate() {
            // Determine target shard (for split, use hash-based distribution)
            let target_shard = if target_shards.len() == 1 {
                target_shards[0]
            } else {
                // Hash-based distribution for split
                if self.hash_account(account) % 2 == 0 {
                    target_shards[0]
                } else {
                    target_shards[1]
                }
            };

            // Update mapping
            account_mappings.insert(*account, target_shard);

            // Update MMR
            let mmr = shard_mmr
                .entry(target_shard)
                .or_insert_with(MerkleTree::new);
            let account_hash = hash::hash_bytes(&account.0);
            mmr.append(account_hash);
        }

        tracing::debug!(
            "Migrated batch {}/{}: {} accounts",
            batch_index + 1,
            plan.batches,
            accounts.len()
        );

        Ok(accounts.len())
    }

    /// Finalize resharding operation
    pub async fn finalize_resharding(&self, operation: ReshardingOperation) -> AvoResult<()> {
        let mut active_shards = self.active_shards.write().await;

        match operation {
            ReshardingOperation::Split {
                source_shard,
                new_shard_1,
                new_shard_2,
            } => {
                active_shards.remove(&source_shard);
                active_shards.insert(new_shard_1);
                active_shards.insert(new_shard_2);

                tracing::info!(
                    "✅ Finalized split: shard {} → shards {} and {}",
                    source_shard,
                    new_shard_1,
                    new_shard_2
                );
            }
            ReshardingOperation::Merge {
                shard_1,
                shard_2,
                target_shard,
            } => {
                active_shards.remove(&shard_1);
                active_shards.remove(&shard_2);
                active_shards.insert(target_shard);

                tracing::info!(
                    "✅ Finalized merge: shards {} and {} → shard {}",
                    shard_1,
                    shard_2,
                    target_shard
                );
            }
        }

        Ok(())
    }

    /// Get current shard count
    pub async fn get_shard_count(&self) -> usize {
        self.active_shards.read().await.len()
    }

    /// Get shard for an account
    pub async fn get_account_shard(&self, account: &Address) -> Option<ShardId> {
        self.account_mappings.read().await.get(account).copied()
    }

    /// Assign account to shard (for testing/initialization)
    pub async fn assign_account(&self, account: Address, shard_id: ShardId) {
        let mut mappings = self.account_mappings.write().await;
        mappings.insert(account, shard_id);
    }

    /// Calculate aggregate state root across shards
    async fn calculate_state_root(&self, shard_ids: &[ShardId]) -> AvoResult<Hash> {
        let shard_mmr = self.shard_mmr.read().await;

        let mut combined = MerkleTree::new();
        for shard_id in shard_ids {
            if let Some(mmr) = shard_mmr.get(shard_id) {
                combined.append(mmr.get_root());
            }
        }

        Ok(combined.get_root())
    }

    fn hash_account(&self, account: &Address) -> u64 {
        let hash = blake3::hash(&account.0);
        u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap())
    }

    async fn get_next_shard_id(&self, active: &HashSet<ShardId>) -> ShardId {
        active.iter().max().map(|m| m + 1).unwrap_or(0)
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> ReshardingStatistics {
        let active_shards = self.active_shards.read().await.len();
        let total_accounts = self.account_mappings.read().await.len();
        let active_migrations = self.active_migrations.read().await.len();

        ReshardingStatistics {
            active_shards,
            total_accounts,
            active_migrations,
            min_shards: self.config.min_shards,
            max_shards: self.config.max_shards,
        }
    }
}

/// Statistics for dynamic resharding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshardingStatistics {
    pub active_shards: usize,
    pub total_accounts: usize,
    pub active_migrations: usize,
    pub min_shards: usize,
    pub max_shards: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmr_basic() {
        let mut mmr = MerkleTree::new();

        mmr.append([1u8; 32]);
        assert_eq!(mmr.leaf_count, 1);

        mmr.append([2u8; 32]);
        assert_eq!(mmr.leaf_count, 2);

        let root = mmr.get_root();
        assert_ne!(root, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_resharding_manager_creation() {
        let config = ReshardingConfig::default();
        let manager = DynamicReshardingManager::new(config, 4);

        assert_eq!(manager.get_shard_count().await, 4);
    }

    #[tokio::test]
    async fn test_split_evaluation() {
        let config = ReshardingConfig {
            split_threshold: 0.7,
            max_shards: 10,
            ..Default::default()
        };
        let manager = DynamicReshardingManager::new(config, 2);

        // Add overloaded shard metrics
        manager
            .update_shard_metrics(ShardLoadMetrics {
                shard_id: 0,
                account_count: 10000,
                transaction_rate: 1000.0,
                storage_bytes: 1_000_000,
                load_factor: 0.85,
            })
            .await;

        let operation = manager.evaluate_resharding().await.unwrap();
        assert!(matches!(operation, Some(ReshardingOperation::Split { .. })));
    }

    #[tokio::test]
    async fn test_merge_evaluation() {
        let config = ReshardingConfig {
            merge_threshold: 0.4,
            min_shards: 2,
            ..Default::default()
        };
        let manager = DynamicReshardingManager::new(config, 4);

        // Add underloaded shard metrics
        for i in 0..2 {
            manager
                .update_shard_metrics(ShardLoadMetrics {
                    shard_id: i,
                    account_count: 100,
                    transaction_rate: 10.0,
                    storage_bytes: 10_000,
                    load_factor: 0.2,
                })
                .await;
        }

        let operation = manager.evaluate_resharding().await.unwrap();
        assert!(matches!(operation, Some(ReshardingOperation::Merge { .. })));
    }

    #[tokio::test]
    async fn test_migration_plan() {
        let config = ReshardingConfig {
            migration_batch_size: 10,
            ..Default::default()
        };
        let manager = DynamicReshardingManager::new(config, 2);

        // Assign some accounts
        for i in 0..25 {
            let addr = Address([i as u8; 20]);
            manager.assign_account(addr, 0).await;
        }

        let operation = ReshardingOperation::Split {
            source_shard: 0,
            new_shard_1: 2,
            new_shard_2: 3,
        };

        let plan = manager.create_migration_plan(operation).await.unwrap();

        assert_eq!(plan.total_accounts, 25);
        assert_eq!(plan.batches, 3); // 25 accounts / 10 per batch = 3 batches
        assert_eq!(plan.accounts_per_batch.len(), 3);
    }

    #[tokio::test]
    async fn test_complete_split_workflow() {
        let config = ReshardingConfig {
            migration_batch_size: 5,
            ..Default::default()
        };
        let manager = DynamicReshardingManager::new(config, 2);

        // Assign accounts to shard 0
        for i in 0..10 {
            manager.assign_account(Address([i; 20]), 0).await;
        }

        // Create split operation
        let operation = ReshardingOperation::Split {
            source_shard: 0,
            new_shard_1: 2,
            new_shard_2: 3,
        };

        // Create and execute migration plan
        let plan = manager
            .create_migration_plan(operation.clone())
            .await
            .unwrap();

        for batch_idx in 0..plan.batches {
            manager
                .execute_migration_batch(&plan, batch_idx)
                .await
                .unwrap();
        }

        // Finalize
        manager.finalize_resharding(operation).await.unwrap();

        // Verify new shard count
        assert_eq!(manager.get_shard_count().await, 3); // Removed 0, added 2 and 3
    }
}
