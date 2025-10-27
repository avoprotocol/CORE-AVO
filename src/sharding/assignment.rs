use crate::error::AvoError;
use crate::sharding::dynamic_shard_manager::{LoadMetrics, ShardInfo};
use crate::types::{Hash, ShardId, TransactionId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Transaction assignment strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssignmentStrategy {
    /// Hash-based consistent assignment
    ConsistentHash,
    /// Load-aware assignment
    LoadBased,
    /// Locality-aware assignment
    LocalityBased,
    /// Hybrid strategy combining multiple factors
    Hybrid,
}

/// Transaction assignment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentConfig {
    /// Number of shards in the system
    pub shard_count: u32,
    /// Assignment strategy to use
    pub strategy: AssignmentStrategy,
    /// Load balancing threshold
    pub load_threshold: f64,
    /// Affinity weight for locality
    pub locality_weight: f64,
    /// Maximum imbalance before rebalancing
    pub max_imbalance: f64,
}

impl Default for AssignmentConfig {
    fn default() -> Self {
        Self {
            shard_count: 64,
            strategy: AssignmentStrategy::Hybrid,
            load_threshold: 0.8,
            locality_weight: 0.3,
            max_imbalance: 0.2,
        }
    }
}

/// Transaction assignment statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AssignmentStats {
    pub total_assignments: u64,
    pub successful_assignments: u64,
    pub failed_assignments: u64,
    pub cross_shard_transactions: u64,
    pub load_redistributions: u64,
    pub average_assignment_time_ms: f64,
    pub assignment_efficiency: f64,
}

/// Transaction assignment metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentMetadata {
    pub transaction_id: TransactionId,
    pub assigned_shard: ShardId,
    pub assignment_time: SystemTime,
    pub assignment_reason: String,
    pub cross_shard_dependencies: Vec<ShardId>,
    pub estimated_gas: u64,
    pub priority: u32,
}

/// Intelligent transaction assigner for AVO shards
#[derive(Debug)]
pub struct TransactionAssigner {
    config: AssignmentConfig,
    shard_info: Arc<RwLock<HashMap<ShardId, ShardInfo>>>,
    assignment_history: Arc<RwLock<HashMap<TransactionId, AssignmentMetadata>>>,
    stats: Arc<RwLock<AssignmentStats>>,
    load_metrics: Arc<RwLock<HashMap<ShardId, LoadMetrics>>>,
}

impl TransactionAssigner {
    /// Create new transaction assigner
    pub fn new(config: AssignmentConfig) -> Self {
        Self {
            config,
            shard_info: Arc::new(RwLock::new(HashMap::new())),
            assignment_history: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(AssignmentStats::default())),
            load_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(AssignmentConfig::default())
    }

    /// Assign transaction to optimal shard (simplified interface)
    pub async fn assign_transaction_obj(
        &self,
        transaction: &crate::types::Transaction,
        _dynamic_manager: &crate::sharding::dynamic_shard_manager::DynamicShardManager,
    ) -> Result<AssignmentMetadata, AvoError> {
        self.assign_transaction(
            transaction.id,
            transaction.data.as_deref().unwrap_or(&[]),
            transaction.gas_limit,
            1, // Default priority
        )
        .await
    }

    /// Assign transaction to optimal shard
    pub async fn assign_transaction(
        &self,
        transaction_id: TransactionId,
        transaction_data: &[u8],
        gas_estimate: u64,
        priority: u32,
    ) -> Result<AssignmentMetadata, AvoError> {
        let start_time = SystemTime::now();

        // Determine best shard using strategy
        let assigned_shard = match self.config.strategy {
            AssignmentStrategy::ConsistentHash => self.assign_by_hash(&transaction_id).await?,
            AssignmentStrategy::LoadBased => self.assign_by_load(gas_estimate, priority).await?,
            AssignmentStrategy::LocalityBased => {
                self.assign_by_locality(&transaction_id, transaction_data)
                    .await?
            }
            AssignmentStrategy::Hybrid => {
                self.assign_hybrid(&transaction_id, transaction_data, gas_estimate, priority)
                    .await?
            }
        };

        // Check for cross-shard dependencies
        let cross_shard_deps = self
            .analyze_cross_shard_dependencies(&transaction_id, transaction_data, assigned_shard)
            .await?;

        // Create assignment metadata
        let assignment_metadata = AssignmentMetadata {
            transaction_id: transaction_id.clone(),
            assigned_shard,
            assignment_time: SystemTime::now(),
            assignment_reason: format!("Strategy: {:?}", self.config.strategy),
            cross_shard_dependencies: cross_shard_deps,
            estimated_gas: gas_estimate,
            priority,
        };

        // Store assignment
        {
            let mut history = self.assignment_history.write().await;
            history.insert(transaction_id.clone(), assignment_metadata.clone());
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_assignments += 1;
            stats.successful_assignments += 1;

            let assignment_time = start_time.elapsed().unwrap_or(Duration::ZERO).as_millis() as f64;
            stats.average_assignment_time_ms =
                (stats.average_assignment_time_ms + assignment_time) / 2.0;

            if !assignment_metadata.cross_shard_dependencies.is_empty() {
                stats.cross_shard_transactions += 1;
            }
        }

        println!(
            "📍 Assigned transaction {} to shard {}",
            transaction_id, assigned_shard
        );

        Ok(assignment_metadata)
    }

    /// Assign using consistent hash
    async fn assign_by_hash(&self, transaction_id: &TransactionId) -> Result<ShardId, AvoError> {
        // Use transaction ID hash for consistent assignment
        let hash_value = self.calculate_hash(transaction_id.as_bytes());
        let shard_id = hash_value % self.config.shard_count;
        Ok(shard_id)
    }

    /// Assign based on current load
    async fn assign_by_load(&self, gas_estimate: u64, priority: u32) -> Result<ShardId, AvoError> {
        let load_metrics = self.load_metrics.read().await;

        // Find shard with lowest load
        let mut best_shard = 0;
        let mut lowest_load = f64::MAX;

        for shard_id in 0..self.config.shard_count {
            if let Some(metrics) = load_metrics.get(&shard_id) {
                let load_score = self.calculate_load_score(metrics, gas_estimate, priority);
                if load_score < lowest_load {
                    lowest_load = load_score;
                    best_shard = shard_id;
                }
            }
        }

        Ok(best_shard)
    }

    /// Assign based on data locality
    async fn assign_by_locality(
        &self,
        transaction_id: &TransactionId,
        transaction_data: &[u8],
    ) -> Result<ShardId, AvoError> {
        // Analyze transaction data for locality hints
        let locality_hints = self.extract_locality_hints(transaction_data).await?;

        if let Some(preferred_shard) = locality_hints.first() {
            Ok(*preferred_shard)
        } else {
            // Fallback to hash-based assignment
            self.assign_by_hash(transaction_id).await
        }
    }

    /// Hybrid assignment strategy
    async fn assign_hybrid(
        &self,
        transaction_id: &TransactionId,
        transaction_data: &[u8],
        gas_estimate: u64,
        priority: u32,
    ) -> Result<ShardId, AvoError> {
        // Get hash-based assignment as baseline
        let hash_shard = self.assign_by_hash(transaction_id).await?;

        // Get load-based assignment
        let load_shard = self.assign_by_load(gas_estimate, priority).await?;

        // Get locality preferences
        let locality_hints = self.extract_locality_hints(transaction_data).await?;

        // Score each candidate shard
        let mut best_shard = hash_shard;
        let mut best_score = f64::MIN;

        let candidates = vec![hash_shard, load_shard]
            .into_iter()
            .chain(locality_hints.into_iter())
            .collect::<HashSet<_>>();

        for candidate in candidates {
            let score = self
                .calculate_hybrid_score(candidate, hash_shard, gas_estimate, priority)
                .await?;

            if score > best_score {
                best_score = score;
                best_shard = candidate;
            }
        }

        Ok(best_shard)
    }

    /// Calculate load score for a shard
    fn calculate_load_score(&self, metrics: &LoadMetrics, gas_estimate: u64, priority: u32) -> f64 {
        let base_load =
            metrics.cpu_utilization + metrics.memory_usage + metrics.storage_usage as f64;
        let transaction_impact = (gas_estimate as f64) / 1_000_000.0; // Normalize gas
        let priority_factor = (priority as f64) / 10.0; // Priority boost

        base_load + transaction_impact - priority_factor
    }

    /// Calculate hybrid score for shard assignment
    async fn calculate_hybrid_score(
        &self,
        candidate_shard: ShardId,
        hash_shard: ShardId,
        gas_estimate: u64,
        priority: u32,
    ) -> Result<f64, AvoError> {
        let load_metrics = self.load_metrics.read().await;

        let mut score = 0.0;

        // Hash consistency bonus
        if candidate_shard == hash_shard {
            score += 50.0;
        }

        // Load penalty
        if let Some(metrics) = load_metrics.get(&candidate_shard) {
            let load_penalty = (metrics.cpu_utilization + metrics.memory_usage) * 10.0;
            score -= load_penalty;
        }

        // Priority bonus
        score += (priority as f64) * 5.0;

        // Gas efficiency
        score += 100.0 / (1.0 + (gas_estimate as f64) / 1_000_000.0);

        Ok(score)
    }

    /// Analyze cross-shard dependencies
    async fn analyze_cross_shard_dependencies(
        &self,
        transaction_id: &TransactionId,
        transaction_data: &[u8],
        assigned_shard: ShardId,
    ) -> Result<Vec<ShardId>, AvoError> {
        let mut dependencies = Vec::new();

        // Simple dependency analysis (can be enhanced)
        // Look for account references that might be in other shards
        if transaction_data.len() > 64 {
            // Parse potential account addresses
            for chunk in transaction_data.chunks(32) {
                if chunk.len() == 32 {
                    let potential_address = TransactionId::from(chunk.to_vec());
                    let potential_shard = self.assign_by_hash(&potential_address).await?;

                    if potential_shard != assigned_shard && !dependencies.contains(&potential_shard)
                    {
                        dependencies.push(potential_shard);
                    }
                }
            }
        }

        Ok(dependencies)
    }

    /// Extract locality hints from transaction data
    async fn extract_locality_hints(
        &self,
        transaction_data: &[u8],
    ) -> Result<Vec<ShardId>, AvoError> {
        let mut hints = Vec::new();

        // Simple locality extraction (can be enhanced)
        if transaction_data.len() >= 4 {
            let locality_hint = u32::from_be_bytes([
                transaction_data[0],
                transaction_data[1],
                transaction_data[2],
                transaction_data[3],
            ]) % self.config.shard_count;
            hints.push(locality_hint);
        }

        Ok(hints)
    }

    /// Update shard information
    pub async fn update_shard_info(&self, shard_id: ShardId, info: ShardInfo) {
        let mut shard_info = self.shard_info.write().await;
        shard_info.insert(shard_id, info);
    }

    /// Update load metrics
    pub async fn update_load_metrics(&self, shard_id: ShardId, metrics: LoadMetrics) {
        let mut load_metrics = self.load_metrics.write().await;
        load_metrics.insert(shard_id, metrics);
    }

    /// Get assignment statistics
    pub async fn get_stats(&self) -> AssignmentStats {
        self.stats.read().await.clone()
    }

    /// Get assignment history for transaction
    pub async fn get_assignment(
        &self,
        transaction_id: &TransactionId,
    ) -> Option<AssignmentMetadata> {
        let history = self.assignment_history.read().await;
        history.get(transaction_id).cloned()
    }

    /// Simple hash calculation
    fn calculate_hash(&self, data: &[u8]) -> u32 {
        data.iter()
            .fold(0u32, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u32))
    }

    /// Check if rebalancing is needed
    pub async fn needs_rebalancing(&self) -> bool {
        let load_metrics = self.load_metrics.read().await;

        if load_metrics.len() < 2 {
            return false;
        }

        let loads: Vec<f64> = load_metrics
            .values()
            .map(|m| m.cpu_utilization + m.memory_usage)
            .collect();

        let max_load = loads.iter().fold(0.0f64, |a, &b| a.max(b));
        let min_load = loads.iter().fold(f64::MAX, |a, &b| a.min(b));

        if max_load == 0.0 {
            return false;
        }

        let imbalance = (max_load - min_load) / max_load;
        imbalance > self.config.max_imbalance
    }

    /// Recommend rebalancing actions
    pub async fn recommend_rebalancing(&self) -> Vec<(ShardId, ShardId, f64)> {
        let mut recommendations = Vec::new();
        let load_metrics = self.load_metrics.read().await;

        // Find overloaded and underloaded shards
        let mut overloaded = Vec::new();
        let mut underloaded = Vec::new();

        for (&shard_id, metrics) in load_metrics.iter() {
            let total_load = metrics.cpu_utilization + metrics.memory_usage;

            if total_load > self.config.load_threshold {
                overloaded.push((shard_id, total_load));
            } else if total_load < self.config.load_threshold * 0.5 {
                underloaded.push((shard_id, total_load));
            }
        }

        // Generate move recommendations
        for (from_shard, from_load) in overloaded {
            for (to_shard, to_load) in &underloaded {
                let transfer_amount = (from_load - to_load) * 0.1; // Transfer 10% of difference
                recommendations.push((from_shard, *to_shard, transfer_amount));
            }
        }

        recommendations
    }
}
