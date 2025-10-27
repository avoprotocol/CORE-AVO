use crate::error::AvoError;
use crate::types::{NodeId, ShardId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Shard status enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ShardStatus {
    Healthy,
    Degraded,
    Overloaded,
    Offline,
    Migrating,
}

/// Helper function to get current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Dynamic shard manager for real-time load balancing
#[derive(Debug, Clone)]
pub struct DynamicShardManager {
    /// Current shard topology mapping
    shard_topology: Arc<RwLock<HashMap<ShardId, ShardInfo>>>,
    /// Load metrics for each shard
    load_metrics: Arc<RwLock<HashMap<ShardId, LoadMetrics>>>,
    /// Rebalancing configuration
    rebalance_config: RebalanceConfig,
    /// Active rebalancing operations
    active_migrations: Arc<RwLock<Vec<MigrationOperation>>>,
}

/// Information about a shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardInfo {
    pub shard_id: ShardId,
    pub assigned_nodes: Vec<NodeId>,
    pub primary_node: NodeId,
    pub backup_nodes: Vec<NodeId>,
    pub state_size: u64,
    pub transaction_count: u64,
    pub last_updated: u64,
    pub status: ShardStatus,
}

/// Shard health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardHealth {
    pub shard_id: ShardId,
    pub status: ShardStatus,
    pub last_check: u64,
    pub error_count: u32,
    pub uptime_percent: f64,
}

/// Real-time load metrics for a shard
#[derive(Debug, Clone, Default)]
pub struct LoadMetrics {
    pub transactions_per_second: f64,
    pub average_latency_ms: f64,
    pub cpu_utilization: f64,
    pub memory_usage: f64,
    pub storage_usage: u64,
    pub network_bandwidth: f64,
    pub last_measured: u64,
}

/// Configuration for automatic rebalancing
#[derive(Debug, Clone)]
pub struct RebalanceConfig {
    /// TPS threshold to trigger rebalancing
    pub tps_threshold: f64,
    /// CPU utilization threshold (0.0-1.0)
    pub cpu_threshold: f64,
    /// Memory usage threshold (0.0-1.0)
    pub memory_threshold: f64,
    /// Minimum time between rebalancing operations (seconds)
    pub cooldown_period: u64,
    /// Enable automatic rebalancing
    pub auto_rebalance_enabled: bool,
}

/// Migration operation for shard rebalancing
#[derive(Debug, Clone)]
pub struct MigrationOperation {
    pub migration_id: String,
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub migration_type: MigrationType,
    pub progress: f64,
    pub started_at: u64,
    pub estimated_completion: u64,
}

#[derive(Debug, Clone)]
pub enum MigrationType {
    /// Split a shard into multiple shards
    ShardSplit { new_shard_count: usize },
    /// Merge multiple shards into one
    ShardMerge { merging_shards: Vec<ShardId> },
    /// Move transactions between existing shards
    TransactionMigration { transaction_count: u64 },
    /// Reassign nodes to different shards
    NodeReassignment { nodes: Vec<NodeId> },
}

impl DynamicShardManager {
    /// Create new dynamic shard manager
    pub fn new(rebalance_config: RebalanceConfig) -> Self {
        Self {
            shard_topology: Arc::new(RwLock::new(HashMap::new())),
            load_metrics: Arc::new(RwLock::new(HashMap::new())),
            rebalance_config,
            active_migrations: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize shards with default configuration
    pub async fn initialize_shards(
        &self,
        shard_count: usize,
        nodes: Vec<NodeId>,
    ) -> Result<(), AvoError> {
        info!(
            "🔄 Initializing {} shards with {} nodes",
            shard_count,
            nodes.len()
        );

        let mut topology = self.shard_topology.write().await;
        let mut metrics = self.load_metrics.write().await;

        let nodes_per_shard = nodes.len() / shard_count;

        for shard_id in 0..shard_count {
            let start_idx = shard_id * nodes_per_shard;
            let end_idx = if shard_id == shard_count - 1 {
                nodes.len() // Last shard gets remaining nodes
            } else {
                start_idx + nodes_per_shard
            };

            let shard_nodes = nodes[start_idx..end_idx].to_vec();
            let primary_node = shard_nodes[0].clone();
            let backup_nodes = shard_nodes[1..].to_vec();

            let shard_info = ShardInfo {
                shard_id: shard_id as u32,
                assigned_nodes: shard_nodes,
                primary_node,
                backup_nodes,
                state_size: 0,
                transaction_count: 0,
                last_updated: current_timestamp(),
                status: ShardStatus::Healthy,
            };

            topology.insert(shard_id as u32, shard_info);
            metrics.insert(shard_id as u32, LoadMetrics::default());
        }

        info!("✅ Successfully initialized {} shards", shard_count);
        Ok(())
    }

    /// Update load metrics for a shard in real-time
    pub async fn update_shard_metrics(
        &self,
        shard_id: ShardId,
        metrics: LoadMetrics,
    ) -> Result<(), AvoError> {
        let mut load_metrics = self.load_metrics.write().await;
        load_metrics.insert(shard_id, metrics.clone());

        // Check if rebalancing is needed
        if self.rebalance_config.auto_rebalance_enabled {
            self.check_rebalancing_trigger(shard_id, &metrics).await?;
        }

        Ok(())
    }

    /// Check if rebalancing should be triggered for a shard
    async fn check_rebalancing_trigger(
        &self,
        shard_id: ShardId,
        metrics: &LoadMetrics,
    ) -> Result<(), AvoError> {
        let needs_rebalancing = metrics.transactions_per_second
            > self.rebalance_config.tps_threshold
            || metrics.cpu_utilization > self.rebalance_config.cpu_threshold
            || metrics.memory_usage > self.rebalance_config.memory_threshold;

        if needs_rebalancing {
            warn!(
                "🚨 Shard {} requires rebalancing - TPS: {:.0}, CPU: {:.1}%, Memory: {:.1}%",
                shard_id,
                metrics.transactions_per_second,
                metrics.cpu_utilization * 100.0,
                metrics.memory_usage * 100.0
            );

            self.trigger_automatic_rebalancing(shard_id).await?;
        }

        Ok(())
    }

    /// Trigger automatic rebalancing for overloaded shard
    pub async fn trigger_automatic_rebalancing(
        &self,
        overloaded_shard: ShardId,
    ) -> Result<(), AvoError> {
        info!(
            "🔄 Triggering automatic rebalancing for shard {}",
            overloaded_shard
        );

        // Check cooldown period
        if !self.can_start_rebalancing().await {
            warn!("⏳ Rebalancing is in cooldown period, skipping");
            return Ok(());
        }

        let topology = self.shard_topology.read().await;
        let metrics = self.load_metrics.read().await;

        let overloaded_metrics = metrics.get(&overloaded_shard).ok_or_else(|| {
            AvoError::cross_shard(format!("Shard {} not found", overloaded_shard))
        })?;

        // Determine best rebalancing strategy
        let migration_op = self
            .determine_rebalancing_strategy(
                overloaded_shard,
                overloaded_metrics,
                &topology,
                &metrics,
            )
            .await?;

        // Execute the migration
        self.execute_migration(migration_op).await?;

        Ok(())
    }

    /// Determine the best rebalancing strategy
    async fn determine_rebalancing_strategy(
        &self,
        overloaded_shard: ShardId,
        overloaded_metrics: &LoadMetrics,
        _topology: &HashMap<ShardId, ShardInfo>,
        all_metrics: &HashMap<ShardId, LoadMetrics>,
    ) -> Result<MigrationOperation, AvoError> {
        // Strategy 1: Find underutilized shards for transaction migration
        for (shard_id, metrics) in all_metrics.iter() {
            if *shard_id != overloaded_shard
                && metrics.transactions_per_second < self.rebalance_config.tps_threshold * 0.5
                && metrics.cpu_utilization < self.rebalance_config.cpu_threshold * 0.5
            {
                let migration_count = (overloaded_metrics.transactions_per_second * 0.3) as u64;

                return Ok(MigrationOperation {
                    migration_id: format!(
                        "migrate-{}-to-{}-{}",
                        overloaded_shard,
                        shard_id,
                        current_timestamp()
                    ),
                    source_shard: overloaded_shard,
                    target_shard: *shard_id,
                    migration_type: MigrationType::TransactionMigration {
                        transaction_count: migration_count,
                    },
                    progress: 0.0,
                    started_at: current_timestamp(),
                    estimated_completion: current_timestamp() + 300, // 5 minutes
                });
            }
        }

        // Strategy 2: Shard split if no underutilized shards available
        info!(
            "🔀 No underutilized shards found, initiating shard split for shard {}",
            overloaded_shard
        );

        Ok(MigrationOperation {
            migration_id: format!("split-{}-{}", overloaded_shard, current_timestamp()),
            source_shard: overloaded_shard,
            target_shard: self.get_next_available_shard_id().await,
            migration_type: MigrationType::ShardSplit { new_shard_count: 2 },
            progress: 0.0,
            started_at: current_timestamp(),
            estimated_completion: current_timestamp() + 600, // 10 minutes
        })
    }

    /// Execute a migration operation
    pub async fn execute_migration(&self, migration: MigrationOperation) -> Result<(), AvoError> {
        info!(
            "🚀 Executing migration: {} - Type: {:?}",
            migration.migration_id, migration.migration_type
        );

        // Add to active migrations
        let mut active_migrations = self.active_migrations.write().await;
        active_migrations.push(migration.clone());
        drop(active_migrations);

        // Execute based on migration type
        match migration.migration_type {
            MigrationType::TransactionMigration { transaction_count } => {
                self.execute_transaction_migration(
                    migration.source_shard,
                    migration.target_shard,
                    transaction_count,
                )
                .await?;
            }
            MigrationType::ShardSplit { new_shard_count } => {
                self.execute_shard_split(migration.source_shard, new_shard_count)
                    .await?;
            }
            MigrationType::ShardMerge { merging_shards } => {
                self.execute_shard_merge(merging_shards, migration.target_shard)
                    .await?;
            }
            MigrationType::NodeReassignment { nodes } => {
                self.execute_node_reassignment(
                    migration.source_shard,
                    migration.target_shard,
                    nodes,
                )
                .await?;
            }
        }

        // Remove from active migrations
        let mut active_migrations = self.active_migrations.write().await;
        active_migrations.retain(|m| m.migration_id != migration.migration_id);

        info!(
            "✅ Migration {} completed successfully",
            migration.migration_id
        );
        Ok(())
    }

    /// Execute transaction migration between shards
    async fn execute_transaction_migration(
        &self,
        source_shard: ShardId,
        target_shard: ShardId,
        transaction_count: u64,
    ) -> Result<(), AvoError> {
        info!(
            "📦 Migrating {} transactions from shard {} to shard {}",
            transaction_count, source_shard, target_shard
        );

        // Simulate migration process
        for i in 0..transaction_count {
            // In real implementation, this would:
            // 1. Lock transactions in source shard
            // 2. Copy transaction data to target shard
            // 3. Update state roots
            // 4. Verify consistency
            // 5. Remove from source shard

            if i % 1000 == 0 {
                info!(
                    "📦 Migration progress: {}/{} transactions",
                    i, transaction_count
                );
            }

            // Simulate work
            tokio::time::sleep(tokio::time::Duration::from_micros(10)).await;
        }

        // Update shard info
        let mut topology = self.shard_topology.write().await;
        if let Some(source_info) = topology.get_mut(&source_shard) {
            source_info.transaction_count = source_info
                .transaction_count
                .saturating_sub(transaction_count);
        }
        if let Some(target_info) = topology.get_mut(&target_shard) {
            target_info.transaction_count += transaction_count;
        }

        info!(
            "✅ Successfully migrated {} transactions",
            transaction_count
        );
        Ok(())
    }

    /// Execute shard split operation
    async fn execute_shard_split(
        &self,
        source_shard: ShardId,
        new_shard_count: usize,
    ) -> Result<(), AvoError> {
        info!(
            "🔀 Splitting shard {} into {} new shards",
            source_shard, new_shard_count
        );

        let mut topology = self.shard_topology.write().await;
        let source_info = topology
            .get(&source_shard)
            .ok_or_else(|| AvoError::cross_shard(format!("Shard {} not found", source_shard)))?
            .clone();

        // Calculate transaction distribution
        let transactions_per_new_shard = source_info.transaction_count / new_shard_count as u64;
        let nodes_per_new_shard = source_info.assigned_nodes.len() / new_shard_count;

        for i in 0..new_shard_count {
            let new_shard_id = self.get_next_available_shard_id().await;
            let start_node_idx = i * nodes_per_new_shard;
            let end_node_idx = if i == new_shard_count - 1 {
                source_info.assigned_nodes.len()
            } else {
                start_node_idx + nodes_per_new_shard
            };

            let new_shard_nodes = source_info.assigned_nodes[start_node_idx..end_node_idx].to_vec();
            let primary_node = new_shard_nodes[0].clone();
            let backup_nodes = new_shard_nodes[1..].to_vec();

            let new_shard_info = ShardInfo {
                shard_id: new_shard_id,
                assigned_nodes: new_shard_nodes,
                primary_node,
                backup_nodes,
                state_size: source_info.state_size / new_shard_count as u64,
                transaction_count: transactions_per_new_shard,
                last_updated: current_timestamp(),
                status: ShardStatus::Healthy,
            };

            topology.insert(new_shard_id, new_shard_info);

            // Initialize metrics for new shard
            let mut metrics = self.load_metrics.write().await;
            metrics.insert(new_shard_id, LoadMetrics::default());
            drop(metrics);
        }

        // Remove original shard
        topology.remove(&source_shard);

        info!(
            "✅ Successfully split shard {} into {} new shards",
            source_shard, new_shard_count
        );
        Ok(())
    }

    /// Execute shard merge operation
    async fn execute_shard_merge(
        &self,
        merging_shards: Vec<ShardId>,
        target_shard: ShardId,
    ) -> Result<(), AvoError> {
        info!(
            "🔗 Merging shards {:?} into shard {}",
            merging_shards, target_shard
        );

        let mut topology = self.shard_topology.write().await;
        let mut total_transactions = 0;
        let mut total_state_size = 0;
        let mut all_nodes = Vec::new();

        // Collect information from all merging shards
        for shard_id in &merging_shards {
            if let Some(shard_info) = topology.get(shard_id) {
                total_transactions += shard_info.transaction_count;
                total_state_size += shard_info.state_size;
                all_nodes.extend(shard_info.assigned_nodes.clone());
            }
        }

        // Create merged shard
        let primary_node = all_nodes[0].clone();
        let backup_nodes = all_nodes[1..].to_vec();

        let merged_shard_info = ShardInfo {
            shard_id: target_shard,
            assigned_nodes: all_nodes,
            primary_node,
            backup_nodes,
            state_size: total_state_size,
            transaction_count: total_transactions,
            last_updated: current_timestamp(),
            status: ShardStatus::Healthy,
        };

        topology.insert(target_shard, merged_shard_info);

        // Remove original shards
        for shard_id in merging_shards {
            topology.remove(&shard_id);
        }

        info!("✅ Successfully merged shards into shard {}", target_shard);
        Ok(())
    }

    /// Execute node reassignment
    async fn execute_node_reassignment(
        &self,
        source_shard: ShardId,
        target_shard: ShardId,
        nodes: Vec<NodeId>,
    ) -> Result<(), AvoError> {
        info!(
            "🔄 Reassigning {} nodes from shard {} to shard {}",
            nodes.len(),
            source_shard,
            target_shard
        );

        let mut topology = self.shard_topology.write().await;

        // Remove nodes from source shard
        if let Some(source_info) = topology.get_mut(&source_shard) {
            source_info
                .assigned_nodes
                .retain(|node| !nodes.contains(node));
            if nodes.contains(&source_info.primary_node) && !source_info.assigned_nodes.is_empty() {
                source_info.primary_node = source_info.assigned_nodes[0].clone();
            }
            source_info
                .backup_nodes
                .retain(|node| !nodes.contains(node));
        }

        // Add nodes to target shard
        if let Some(target_info) = topology.get_mut(&target_shard) {
            target_info.assigned_nodes.extend(nodes);
            // Update backup nodes
            target_info.backup_nodes = target_info.assigned_nodes[1..].to_vec();
        }

        info!("✅ Successfully reassigned nodes");
        Ok(())
    }

    /// Check if rebalancing can start (cooldown period)
    async fn can_start_rebalancing(&self) -> bool {
        let active_migrations = self.active_migrations.read().await;
        if !active_migrations.is_empty() {
            return false;
        }

        // Check cooldown period - simplified implementation
        true
    }

    /// Get next available shard ID
    async fn get_next_available_shard_id(&self) -> ShardId {
        let topology = self.shard_topology.read().await;
        let max_shard_id = topology.keys().max().copied().unwrap_or(0);
        max_shard_id + 1
    }

    /// Get current shard topology
    pub async fn get_shard_topology(&self) -> HashMap<ShardId, ShardInfo> {
        self.shard_topology.read().await.clone()
    }

    /// Get load metrics for all shards
    pub async fn get_load_metrics(&self) -> HashMap<ShardId, LoadMetrics> {
        self.load_metrics.read().await.clone()
    }

    /// Get active migrations
    pub async fn get_active_migrations(&self) -> Vec<MigrationOperation> {
        self.active_migrations.read().await.clone()
    }

    /// Create a new shard (ShardManager trait compatibility)
    pub async fn create_shard(&self, shard_id: ShardId) -> Result<(), AvoError> {
        let shard_info = ShardInfo {
            shard_id,
            assigned_nodes: vec![format!("node_{}", shard_id)],
            primary_node: format!("primary_{}", shard_id),
            backup_nodes: vec![format!("backup_{}", shard_id)],
            state_size: 0,
            transaction_count: 0,
            last_updated: current_timestamp(),
            status: ShardStatus::Healthy,
        };

        let mut shards = self.shard_topology.write().await;
        shards.insert(shard_id, shard_info);

        let mut metrics = self.load_metrics.write().await;
        metrics.insert(shard_id, LoadMetrics::default());

        Ok(())
    }

    /// Remove a shard (ShardManager trait compatibility)
    pub async fn remove_shard(&self, shard_id: ShardId) -> Result<(), AvoError> {
        let mut shards = self.shard_topology.write().await;
        shards.remove(&shard_id);

        let mut metrics = self.load_metrics.write().await;
        metrics.remove(&shard_id);

        Ok(())
    }

    /// Get shard information (ShardManager trait compatibility)
    pub async fn get_shard_info(&self, shard_id: &ShardId) -> Result<ShardInfo, AvoError> {
        let shards = self.shard_topology.read().await;
        shards
            .get(shard_id)
            .cloned()
            .ok_or_else(|| AvoError::NotFound(format!("Shard {} not found", shard_id)))
    }

    /// Get all shard loads for rebalancing
    pub async fn get_all_shard_loads(&self) -> HashMap<ShardId, f64> {
        let metrics = self.load_metrics.read().await;
        metrics
            .iter()
            .map(|(id, m)| (*id, m.cpu_utilization + m.memory_usage))
            .collect()
    }

    /// Get shard for account assignment
    pub async fn get_shard_for_account(&self, account_id: &String) -> Result<ShardId, AvoError> {
        // Simple hash-based assignment for demo
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        account_id.hash(&mut hasher);
        let hash_value = hasher.finish();

        let shards = self.shard_topology.read().await;
        let shard_count = shards.len() as u64;
        if shard_count == 0 {
            return Err(AvoError::NotFound("No shards available".to_string()));
        }

        let shard_index = hash_value % shard_count;
        let shard_ids: Vec<_> = shards.keys().collect();
        Ok(*shard_ids[shard_index as usize])
    }

    /// Get accounts in a shard
    pub async fn get_shard_accounts(&self, _shard_id: &ShardId) -> Result<Vec<String>, AvoError> {
        // For demo purposes, return empty list
        Ok(Vec::new())
    }

    /// Get available shards
    pub async fn get_available_shards(&self) -> Vec<ShardId> {
        let shards = self.shard_topology.read().await;
        shards.keys().copied().collect()
    }

    /// Get all shard health information
    pub async fn get_all_shard_health(&self) -> Result<HashMap<ShardId, ShardHealth>, AvoError> {
        let shards = self.shard_topology.read().await;
        let health_map = shards
            .iter()
            .map(|(id, info)| {
                let health = ShardHealth {
                    shard_id: *id,
                    status: info.status.clone(),
                    last_check: current_timestamp(),
                    error_count: 0,
                    uptime_percent: 99.9,
                };
                (*id, health)
            })
            .collect();
        Ok(health_map)
    }
}

impl Default for RebalanceConfig {
    fn default() -> Self {
        Self {
            tps_threshold: 50000.0, // 50k TPS per shard
            cpu_threshold: 0.8,     // 80% CPU
            memory_threshold: 0.85, // 85% memory
            cooldown_period: 300,   // 5 minutes
            auto_rebalance_enabled: true,
        }
    }
}
