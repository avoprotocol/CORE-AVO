use crate::error::AvoError;
use crate::sharding::dynamic_shard_manager::{LoadMetrics, ShardInfo};
use crate::types::{ShardId, TransactionId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

/// Load balancing strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingStrategy {
    /// Round-robin distribution
    RoundRobin,
    /// Least connections first
    LeastConnections,
    /// Weighted round-robin
    WeightedRoundRobin,
    /// Resource-aware balancing
    ResourceAware,
    /// Predictive load balancing
    Predictive,
}

/// Load balancing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    /// Balancing strategy
    pub strategy: LoadBalancingStrategy,
    /// Target load threshold
    pub target_load_threshold: f64,
    /// Maximum load before rejecting
    pub max_load_threshold: f64,
    /// Rebalancing check interval
    pub rebalance_interval: Duration,
    /// Circuit breaker threshold
    pub circuit_breaker_threshold: f64,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Prediction window for predictive balancing
    pub prediction_window: Duration,
}

impl Default for LoadBalancerConfig {
    fn default() -> Self {
        Self {
            strategy: LoadBalancingStrategy::ResourceAware,
            target_load_threshold: 0.7,
            max_load_threshold: 0.95,
            rebalance_interval: Duration::from_secs(30),
            circuit_breaker_threshold: 0.9,
            health_check_interval: Duration::from_secs(10),
            prediction_window: Duration::from_secs(300),
        }
    }
}

/// Shard health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ShardHealth {
    Healthy,
    Degraded,
    Overloaded,
    Unavailable,
    CircuitBroken,
}

/// Load balancing statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoadBalancerStats {
    pub total_requests: u64,
    pub successful_routes: u64,
    pub failed_routes: u64,
    pub load_redistributions: u64,
    pub circuit_breaker_trips: u64,
    pub average_response_time_ms: f64,
    pub throughput_per_second: f64,
    pub efficiency_ratio: f64,
}

/// Real-time shard status
#[derive(Debug, Clone)]
pub struct ShardStatus {
    pub shard_id: ShardId,
    pub health: ShardHealth,
    pub current_load: f64,
    pub connection_count: u32,
    pub average_response_time: Duration,
    pub last_health_check: SystemTime,
    pub weight: f64,
    pub circuit_breaker_open: bool,
}

/// Load prediction data
#[derive(Debug, Clone)]
pub struct LoadPrediction {
    pub shard_id: ShardId,
    pub predicted_load: f64,
    pub confidence: f64,
    pub prediction_time: SystemTime,
    pub trend: LoadTrend,
}

/// Load trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadTrend {
    Increasing,
    Decreasing,
    Stable,
    Volatile,
}

/// Advanced load balancer for AVO shards
#[derive(Debug)]
pub struct LoadBalancer {
    config: LoadBalancerConfig,
    shard_status: Arc<RwLock<HashMap<ShardId, ShardStatus>>>,
    round_robin_counter: Arc<RwLock<u32>>,
    load_history: Arc<RwLock<HashMap<ShardId, VecDeque<(SystemTime, f64)>>>>,
    predictions: Arc<RwLock<HashMap<ShardId, LoadPrediction>>>,
    stats: Arc<RwLock<LoadBalancerStats>>,
    last_rebalance: Arc<RwLock<SystemTime>>,
}

impl LoadBalancer {
    /// Create new load balancer
    pub fn new(config: LoadBalancerConfig) -> Self {
        Self {
            config,
            shard_status: Arc::new(RwLock::new(HashMap::new())),
            round_robin_counter: Arc::new(RwLock::new(0)),
            load_history: Arc::new(RwLock::new(HashMap::new())),
            predictions: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(LoadBalancerStats::default())),
            last_rebalance: Arc::new(RwLock::new(SystemTime::now())),
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(LoadBalancerConfig::default())
    }

    /// Select optimal shard for new request
    pub async fn select_shard(
        &self,
        transaction_id: Option<TransactionId>,
        request_weight: f64,
    ) -> Result<ShardId, AvoError> {
        let start_time = Instant::now();

        let selected_shard = match self.config.strategy {
            LoadBalancingStrategy::RoundRobin => self.select_round_robin().await?,
            LoadBalancingStrategy::LeastConnections => self.select_least_connections().await?,
            LoadBalancingStrategy::WeightedRoundRobin => self.select_weighted_round_robin().await?,
            LoadBalancingStrategy::ResourceAware => {
                self.select_resource_aware(request_weight).await?
            }
            LoadBalancingStrategy::Predictive => self.select_predictive(request_weight).await?,
        };

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
            stats.successful_routes += 1;

            let response_time = start_time.elapsed().as_millis() as f64;
            stats.average_response_time_ms = (stats.average_response_time_ms + response_time) / 2.0;
        }

        // Update shard connection count
        self.increment_connections(selected_shard).await;

        println!(
            "⚖️ Load balancer selected shard {} for request",
            selected_shard
        );
        Ok(selected_shard)
    }

    /// Round-robin selection
    async fn select_round_robin(&self) -> Result<ShardId, AvoError> {
        let healthy_shards = self.get_healthy_shards().await;

        if healthy_shards.is_empty() {
            return Err(AvoError::NetworkError {
                reason: "No healthy shards available".to_string(),
            });
        }

        let mut counter = self.round_robin_counter.write().await;
        let index = (*counter as usize) % healthy_shards.len();
        *counter = counter.wrapping_add(1);

        Ok(healthy_shards[index])
    }

    /// Least connections selection
    async fn select_least_connections(&self) -> Result<ShardId, AvoError> {
        let shard_status = self.shard_status.read().await;

        let mut best_shard = None;
        let mut min_connections = u32::MAX;

        for (&shard_id, status) in shard_status.iter() {
            if status.health == ShardHealth::Healthy && !status.circuit_breaker_open {
                if status.connection_count < min_connections {
                    min_connections = status.connection_count;
                    best_shard = Some(shard_id);
                }
            }
        }

        best_shard.ok_or_else(|| AvoError::NetworkError {
            reason: "No available shards for least connections".to_string(),
        })
    }

    /// Weighted round-robin selection
    async fn select_weighted_round_robin(&self) -> Result<ShardId, AvoError> {
        let shard_status = self.shard_status.read().await;

        // Build weighted list
        let mut weighted_shards = Vec::new();
        for (&shard_id, status) in shard_status.iter() {
            if status.health == ShardHealth::Healthy && !status.circuit_breaker_open {
                let weight = (status.weight * 10.0) as usize;
                for _ in 0..weight.max(1) {
                    weighted_shards.push(shard_id);
                }
            }
        }

        if weighted_shards.is_empty() {
            return Err(AvoError::NetworkError {
                reason: "No weighted shards available".to_string(),
            });
        }

        let mut counter = self.round_robin_counter.write().await;
        let index = (*counter as usize) % weighted_shards.len();
        *counter = counter.wrapping_add(1);

        Ok(weighted_shards[index])
    }

    /// Resource-aware selection
    async fn select_resource_aware(&self, request_weight: f64) -> Result<ShardId, AvoError> {
        let shard_status = self.shard_status.read().await;

        let mut best_shard = None;
        let mut best_score = f64::MIN;

        for (&shard_id, status) in shard_status.iter() {
            if status.health != ShardHealth::Healthy || status.circuit_breaker_open {
                continue;
            }

            let score = self.calculate_resource_score(status, request_weight);
            if score > best_score {
                best_score = score;
                best_shard = Some(shard_id);
            }
        }

        best_shard.ok_or_else(|| AvoError::NetworkError {
            reason: "No suitable shard found for resource-aware selection".to_string(),
        })
    }

    /// Predictive selection using load forecasting
    async fn select_predictive(&self, request_weight: f64) -> Result<ShardId, AvoError> {
        let predictions = self.predictions.read().await;
        let shard_status = self.shard_status.read().await;

        let mut best_shard = None;
        let mut best_score = f64::MIN;

        for (&shard_id, status) in shard_status.iter() {
            if status.health != ShardHealth::Healthy || status.circuit_breaker_open {
                continue;
            }

            let predicted_load = predictions
                .get(&shard_id)
                .map(|p| p.predicted_load)
                .unwrap_or(status.current_load);

            let future_load = predicted_load + request_weight;

            // Score based on predicted future state
            let score = 1.0 / (1.0 + future_load);

            if score > best_score && future_load < self.config.max_load_threshold {
                best_score = score;
                best_shard = Some(shard_id);
            }
        }

        best_shard.ok_or_else(|| AvoError::NetworkError {
            reason: "No suitable shard found for predictive selection".to_string(),
        })
    }

    /// Calculate resource score for shard
    fn calculate_resource_score(&self, status: &ShardStatus, request_weight: f64) -> f64 {
        let load_penalty = status.current_load * 2.0;
        let connection_penalty = (status.connection_count as f64) / 100.0;
        let response_time_penalty = status.average_response_time.as_millis() as f64 / 1000.0;
        let weight_bonus = status.weight;

        // Higher score is better
        100.0 + weight_bonus - load_penalty - connection_penalty - response_time_penalty
    }

    /// Update shard health and metrics
    pub async fn update_shard_metrics(&self, shard_id: ShardId, metrics: LoadMetrics) {
        let current_time = SystemTime::now();
        let total_load =
            metrics.cpu_utilization + metrics.memory_usage + metrics.storage_usage as f64; // Update load history
        {
            let mut history = self.load_history.write().await;
            let shard_history = history.entry(shard_id).or_insert_with(VecDeque::new);
            shard_history.push_back((current_time, total_load));

            // Keep only recent history
            while shard_history.len() > 100 {
                shard_history.pop_front();
            }
        }

        // Update shard status
        {
            let mut status_map = self.shard_status.write().await;
            let status = status_map.entry(shard_id).or_insert_with(|| ShardStatus {
                shard_id,
                health: ShardHealth::Healthy,
                current_load: 0.0,
                connection_count: 0,
                average_response_time: Duration::ZERO,
                last_health_check: current_time,
                weight: 1.0,
                circuit_breaker_open: false,
            });

            status.current_load = total_load;
            status.last_health_check = current_time;

            // Update health based on load
            status.health = if total_load > self.config.max_load_threshold {
                ShardHealth::Overloaded
            } else if total_load > self.config.target_load_threshold {
                ShardHealth::Degraded
            } else {
                ShardHealth::Healthy
            };

            // Circuit breaker logic
            if total_load > self.config.circuit_breaker_threshold {
                status.circuit_breaker_open = true;
            } else if total_load < self.config.circuit_breaker_threshold * 0.8 {
                status.circuit_breaker_open = false;
            }
        }

        // Update predictions
        self.update_predictions(shard_id).await;
    }

    /// Update load predictions for shard
    async fn update_predictions(&self, shard_id: ShardId) {
        let history = self.load_history.read().await;

        if let Some(shard_history) = history.get(&shard_id) {
            if shard_history.len() >= 5 {
                let prediction = self.calculate_load_prediction(shard_history);
                let mut predictions = self.predictions.write().await;
                predictions.insert(shard_id, prediction);
            }
        }
    }

    /// Calculate load prediction using simple linear regression
    fn calculate_load_prediction(&self, history: &VecDeque<(SystemTime, f64)>) -> LoadPrediction {
        let data: Vec<(f64, f64)> = history
            .iter()
            .enumerate()
            .map(|(i, (_, load))| (i as f64, *load))
            .collect();

        let n = data.len() as f64;
        let sum_x: f64 = data.iter().map(|(x, _)| x).sum();
        let sum_y: f64 = data.iter().map(|(_, y)| y).sum();
        let sum_xy: f64 = data.iter().map(|(x, y)| x * y).sum();
        let sum_x2: f64 = data.iter().map(|(x, _)| x * x).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        let intercept = (sum_y - slope * sum_x) / n;

        let next_x = n;
        let predicted_load = slope * next_x + intercept;

        // Determine trend
        let trend = if slope > 0.1 {
            LoadTrend::Increasing
        } else if slope < -0.1 {
            LoadTrend::Decreasing
        } else {
            LoadTrend::Stable
        };

        LoadPrediction {
            shard_id: 0, // Will be set by caller
            predicted_load: predicted_load.max(0.0),
            confidence: 0.8, // Simple confidence measure
            prediction_time: SystemTime::now(),
            trend,
        }
    }

    /// Get list of healthy shards
    async fn get_healthy_shards(&self) -> Vec<ShardId> {
        let shard_status = self.shard_status.read().await;
        shard_status
            .iter()
            .filter(|(_, status)| {
                status.health == ShardHealth::Healthy && !status.circuit_breaker_open
            })
            .map(|(&shard_id, _)| shard_id)
            .collect()
    }

    /// Increment connection count for shard
    async fn increment_connections(&self, shard_id: ShardId) {
        let mut shard_status = self.shard_status.write().await;
        if let Some(status) = shard_status.get_mut(&shard_id) {
            status.connection_count += 1;
        }
    }

    /// Decrement connection count for shard
    pub async fn decrement_connections(&self, shard_id: ShardId) {
        let mut shard_status = self.shard_status.write().await;
        if let Some(status) = shard_status.get_mut(&shard_id) {
            status.connection_count = status.connection_count.saturating_sub(1);
        }
    }

    /// Check if rebalancing is needed
    pub async fn needs_rebalancing(&self) -> bool {
        let last_rebalance = *self.last_rebalance.read().await;
        let time_since_rebalance = SystemTime::now()
            .duration_since(last_rebalance)
            .unwrap_or(Duration::ZERO);

        if time_since_rebalance < self.config.rebalance_interval {
            return false;
        }

        let shard_status = self.shard_status.read().await;
        let loads: Vec<f64> = shard_status.values().map(|s| s.current_load).collect();

        if loads.len() < 2 {
            return false;
        }

        let max_load = loads.iter().fold(0.0f64, |a, &b| a.max(b));
        let min_load = loads.iter().fold(f64::MAX, |a, &b| a.min(b));

        max_load > self.config.target_load_threshold || (max_load - min_load) > 0.3
    }

    /// Get load balancer statistics
    pub async fn get_stats(&self) -> LoadBalancerStats {
        self.stats.read().await.clone()
    }

    /// Get current shard status
    pub async fn get_shard_status(&self, shard_id: ShardId) -> Option<ShardStatus> {
        let shard_status = self.shard_status.read().await;
        shard_status.get(&shard_id).cloned()
    }

    /// Get all shard statuses
    pub async fn get_all_shard_status(&self) -> HashMap<ShardId, ShardStatus> {
        self.shard_status.read().await.clone()
    }

    /// Perform health check on all shards
    pub async fn health_check(&self) -> Result<(), AvoError> {
        let mut shard_status = self.shard_status.write().await;
        let current_time = SystemTime::now();

        for (_, status) in shard_status.iter_mut() {
            let time_since_check = current_time
                .duration_since(status.last_health_check)
                .unwrap_or(Duration::MAX);

            if time_since_check > self.config.health_check_interval * 2 {
                status.health = ShardHealth::Unavailable;
            }
        }

        Ok(())
    }

    /// Update rebalance timestamp
    pub async fn mark_rebalanced(&self) {
        let mut last_rebalance = self.last_rebalance.write().await;
        *last_rebalance = SystemTime::now();

        let mut stats = self.stats.write().await;
        stats.load_redistributions += 1;
    }

    /// Calculate optimal assignment for rebalancing
    pub async fn calculate_optimal_assignment(
        &self,
        shard_loads: &HashMap<ShardId, f64>,
    ) -> Result<HashMap<String, ShardId>, AvoError> {
        // Simple strategy: return empty assignment for demo
        Ok(HashMap::new())
    }

    /// Calculate load variance across shards
    pub async fn calculate_load_variance(
        &self,
        shard_loads: &HashMap<ShardId, f64>,
    ) -> Result<f64, AvoError> {
        if shard_loads.is_empty() {
            return Ok(0.0);
        }

        let loads: Vec<f64> = shard_loads.values().copied().collect();
        let mean = loads.iter().sum::<f64>() / loads.len() as f64;
        let variance =
            loads.iter().map(|&load| (load - mean).powi(2)).sum::<f64>() / loads.len() as f64;

        Ok(variance.sqrt() / mean) // Coefficient of variation
    }
}
