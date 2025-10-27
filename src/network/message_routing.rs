use crate::error::AvoError;
use crate::network::tcp_pool::TcpConnectionPool;
use crate::network::NodeEndpoint;
use crate::types::Hash;
use crate::types::NetworkMessage;
use bincode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Message priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Routing strategy for messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingStrategy {
    /// Send to all connected peers
    Broadcast,
    /// Send to specific peer
    Direct(String),
    /// Send to closest peers based on some metric
    Closest(usize),
    /// Send to random subset of peers
    Random(usize),
    /// Send based on shard routing
    ShardBased(u32),
    /// Send to peers with specific capabilities
    CapabilityBased(Vec<String>),
}

/// Message routing metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingMetadata {
    pub message_id: String,
    pub source_node: String,
    pub target_strategy: RoutingStrategy,
    pub priority: MessagePriority,
    pub ttl: u32,
    pub timestamp: SystemTime,
    pub retry_count: u32,
    pub max_retries: u32,
}

/// Queued message for routing
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub metadata: RoutingMetadata,
    pub message: NetworkMessage,
    pub target_peers: Vec<String>,
}

/// Routing statistics
#[derive(Debug, Clone, Default)]
pub struct RoutingStats {
    pub messages_routed: u64,
    pub messages_failed: u64,
    pub messages_retried: u64,
    pub average_routing_time_ms: f64,
    pub queue_size: usize,
    pub active_routes: usize,
}

/// Peer routing information
#[derive(Debug, Clone)]
pub struct PeerRouteInfo {
    pub peer_id: String,
    pub endpoint: NodeEndpoint,
    pub latency: Option<Duration>,
    pub reliability_score: f64, // 0.0 to 1.0
    pub capabilities: Vec<String>,
    pub last_success: Option<SystemTime>,
    pub consecutive_failures: u32,
    pub message_count: u64,
    pub shard_assignments: Vec<u32>,
}

/// Message Router - Intelligent message routing and delivery with real TCP
pub struct MessageRouter {
    /// Message queue organized by priority
    message_queue: Arc<RwLock<HashMap<MessagePriority, VecDeque<QueuedMessage>>>>,
    /// Peer routing information
    peer_routes: Arc<RwLock<HashMap<String, PeerRouteInfo>>>,
    /// TCP connection pool for real network delivery
    tcp_pool: Arc<TcpConnectionPool>,
    /// Routing statistics
    stats: Arc<RwLock<RoutingStats>>,
    /// Configuration
    max_queue_size: usize,
    default_ttl: u32,
    max_retries: u32,
    /// Running status
    is_running: Arc<RwLock<bool>>,
}

impl MessageRouter {
    /// Create new message router with TCP pool
    pub fn new(max_queue_size: usize, tcp_pool: Arc<TcpConnectionPool>) -> Self {
        let mut queue = HashMap::new();
        queue.insert(MessagePriority::Critical, VecDeque::new());
        queue.insert(MessagePriority::High, VecDeque::new());
        queue.insert(MessagePriority::Normal, VecDeque::new());
        queue.insert(MessagePriority::Low, VecDeque::new());

        Self {
            message_queue: Arc::new(RwLock::new(queue)),
            peer_routes: Arc::new(RwLock::new(HashMap::new())),
            tcp_pool,
            stats: Arc::new(RwLock::new(RoutingStats::default())),
            max_queue_size,
            default_ttl: 30, // 30 hops default
            max_retries: 3,
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the message router
    pub async fn start(&self) -> Result<(), AvoError> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }
        *is_running = true;
        drop(is_running);

        println!("🚀 Starting Message Router");

        // Start message processing loop
        self.start_processing_loop().await;

        // Start cleanup task
        self.start_cleanup_task().await;

        println!("✅ Message Router started");
        Ok(())
    }

    /// Stop the message router
    pub async fn stop(&self) -> Result<(), AvoError> {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }
        *is_running = false;
        drop(is_running);

        println!("🛑 Stopping Message Router");

        // Clear message queue
        {
            let mut queue = self.message_queue.write().await;
            for priority_queue in queue.values_mut() {
                priority_queue.clear();
            }
        }

        println!("✅ Message Router stopped");
        Ok(())
    }

    /// Route a message with specified strategy
    pub async fn route_message(
        &self,
        message: NetworkMessage,
        strategy: RoutingStrategy,
        priority: MessagePriority,
    ) -> Result<String, AvoError> {
        let message_id = format!("msg-{}", uuid::Uuid::new_v4());

        let metadata = RoutingMetadata {
            message_id: message_id.clone(),
            source_node: "local".to_string(), // In real implementation, get from config
            target_strategy: strategy.clone(),
            priority: priority.clone(),
            ttl: self.default_ttl,
            timestamp: SystemTime::now(),
            retry_count: 0,
            max_retries: self.max_retries,
        };

        // Determine target peers based on strategy
        let target_peers = self.select_target_peers(&strategy).await?;

        let queued_message = QueuedMessage {
            metadata,
            message,
            target_peers,
        };

        // Add to appropriate priority queue
        {
            let mut queue = self.message_queue.write().await;
            if let Some(priority_queue) = queue.get_mut(&priority) {
                if priority_queue.len() >= self.max_queue_size {
                    return Err(AvoError::NetworkError {
                        reason: "Message queue full".to_string(),
                    });
                }
                priority_queue.push_back(queued_message);
            }
        }

        // Update queue size stat
        {
            let mut stats = self.stats.write().await;
            stats.queue_size += 1;
        }

        println!(
            "📮 Queued message {} with priority {:?}",
            message_id, priority
        );
        Ok(message_id)
    }

    /// Add or update peer route information
    pub async fn update_peer_route(&self, peer_route: PeerRouteInfo) {
        let mut routes = self.peer_routes.write().await;
        routes.insert(peer_route.peer_id.clone(), peer_route);
    }

    /// Remove peer route
    pub async fn remove_peer_route(&self, peer_id: &str) {
        let mut routes = self.peer_routes.write().await;
        routes.remove(peer_id);
    }

    /// Get routing statistics
    pub async fn get_stats(&self) -> RoutingStats {
        let mut stats = self.stats.read().await.clone();

        // Update queue size
        let queue = self.message_queue.read().await;
        stats.queue_size = queue.values().map(|q| q.len()).sum();

        // Update active routes
        let routes = self.peer_routes.read().await;
        stats.active_routes = routes.len();

        stats
    }

    /// Get best peers for routing based on strategy
    async fn select_target_peers(
        &self,
        strategy: &RoutingStrategy,
    ) -> Result<Vec<String>, AvoError> {
        let routes = self.peer_routes.read().await;

        match strategy {
            RoutingStrategy::Broadcast => Ok(routes.keys().cloned().collect()),
            RoutingStrategy::Direct(peer_id) => {
                if routes.contains_key(peer_id) {
                    Ok(vec![peer_id.clone()])
                } else {
                    Err(AvoError::NetworkError {
                        reason: format!("Peer {} not found", peer_id),
                    })
                }
            }
            RoutingStrategy::Closest(count) => {
                let mut peers: Vec<_> = routes.values().collect();

                // Sort by latency (lower is better)
                peers.sort_by(|a, b| match (a.latency, b.latency) {
                    (Some(lat_a), Some(lat_b)) => lat_a.cmp(&lat_b),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                });

                Ok(peers
                    .into_iter()
                    .take(*count)
                    .map(|p| p.peer_id.clone())
                    .collect())
            }
            RoutingStrategy::Random(count) => {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                let mut peer_ids: Vec<_> = routes.keys().cloned().collect();
                peer_ids.shuffle(&mut rng);
                Ok(peer_ids.into_iter().take(*count).collect())
            }
            RoutingStrategy::ShardBased(shard_id) => {
                let peers: Vec<String> = routes
                    .values()
                    .filter(|route| route.shard_assignments.contains(shard_id))
                    .map(|route| route.peer_id.clone())
                    .collect();

                if peers.is_empty() {
                    Err(AvoError::NetworkError {
                        reason: format!("No peers found for shard {}", shard_id),
                    })
                } else {
                    Ok(peers)
                }
            }
            RoutingStrategy::CapabilityBased(required_capabilities) => {
                let peers: Vec<String> = routes
                    .values()
                    .filter(|route| {
                        required_capabilities
                            .iter()
                            .all(|cap| route.capabilities.contains(cap))
                    })
                    .map(|route| route.peer_id.clone())
                    .collect();

                if peers.is_empty() {
                    Err(AvoError::NetworkError {
                        reason: format!(
                            "No peers found with capabilities: {:?}",
                            required_capabilities
                        ),
                    })
                } else {
                    Ok(peers)
                }
            }
        }
    }

    /// Start message processing loop
    async fn start_processing_loop(&self) {
        let queue = self.message_queue.clone();
        let routes = self.peer_routes.clone();
        let stats = self.stats.clone();
        let is_running = self.is_running.clone();
        let tcp_pool = self.tcp_pool.clone();

        tokio::spawn(async move {
            while *is_running.read().await {
                // Process messages by priority (Critical -> High -> Normal -> Low)
                let priorities = vec![
                    MessagePriority::Critical,
                    MessagePriority::High,
                    MessagePriority::Normal,
                    MessagePriority::Low,
                ];

                let mut processed_any = false;

                for priority in priorities {
                    let message_opt = {
                        let mut queue_guard = queue.write().await;
                        if let Some(priority_queue) = queue_guard.get_mut(&priority) {
                            priority_queue.pop_front()
                        } else {
                            None
                        }
                    };

                    if let Some(mut queued_message) = message_opt {
                        processed_any = true;

                        let start_time = std::time::Instant::now();

                        // Process the message with real TCP delivery
                        match Self::process_queued_message(&queued_message, &routes, &tcp_pool).await {
                            Ok(_) => {
                                // Update success stats
                                let mut stats_guard = stats.write().await;
                                stats_guard.messages_routed += 1;
                                stats_guard.queue_size = stats_guard.queue_size.saturating_sub(1);

                                let routing_time = start_time.elapsed().as_millis() as f64;
                                stats_guard.average_routing_time_ms =
                                    (stats_guard.average_routing_time_ms + routing_time) / 2.0;
                            }
                            Err(e) => {
                                // Handle retry logic
                                let current_retry_count = queued_message.metadata.retry_count;
                                let message_id = queued_message.metadata.message_id.clone();
                                queued_message.metadata.retry_count += 1;

                                if queued_message.metadata.retry_count
                                    < queued_message.metadata.max_retries
                                {
                                    // Re-queue for retry
                                    let mut queue_guard = queue.write().await;
                                    if let Some(priority_queue) = queue_guard.get_mut(&priority) {
                                        priority_queue.push_back(queued_message);
                                    }

                                    let mut stats_guard = stats.write().await;
                                    stats_guard.messages_retried += 1;

                                    println!(
                                        "🔄 Retrying message {} (attempt {})",
                                        message_id,
                                        current_retry_count + 1
                                    );
                                } else {
                                    // Max retries exceeded
                                    let mut stats_guard = stats.write().await;
                                    stats_guard.messages_failed += 1;
                                    stats_guard.queue_size =
                                        stats_guard.queue_size.saturating_sub(1);

                                    println!(
                                        "❌ Message {} failed after {} retries: {}",
                                        queued_message.metadata.message_id,
                                        queued_message.metadata.retry_count,
                                        e
                                    );
                                }
                            }
                        }

                        // Break after processing one message to ensure fairness
                        break;
                    }
                }

                if !processed_any {
                    // No messages to process, sleep briefly
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        });
    }

    /// Process a queued message with real TCP delivery
    async fn process_queued_message(
        queued_message: &QueuedMessage,
        routes: &Arc<RwLock<HashMap<String, PeerRouteInfo>>>,
        tcp_pool: &Arc<TcpConnectionPool>,
    ) -> Result<(), AvoError> {
        let routes_guard = routes.read().await;

        let mut delivery_success = false;
        let mut last_error = None;

        for peer_id in &queued_message.target_peers {
            if let Some(peer_route) = routes_guard.get(peer_id) {
                // Check peer reliability
                if peer_route.reliability_score < 0.5 && peer_route.consecutive_failures > 3 {
                    warn!("⚠️ Skipping unreliable peer {}", peer_id);
                    continue;
                }

                info!(
                    "📤 Routing message {} to peer {} at {:?} (latency: {:?})",
                    queued_message.metadata.message_id,
                    peer_id,
                    peer_route.endpoint,
                    peer_route.latency
                );

                // Serialize message with bincode
                let serialized = match bincode::serialize(&queued_message.message) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("❌ Failed to serialize message: {}", e);
                        last_error = Some(AvoError::network(format!("Serialization failed: {}", e)));
                        continue;
                    }
                };

                // Ensure connection exists (get_or_connect already establishes if needed)
                if let Err(e) = tcp_pool
                    .get_or_connect(peer_id.clone(), peer_route.endpoint.address)
                    .await
                {
                    warn!("⚠️ Failed to connect to peer {}: {}", peer_id, e);
                    last_error = Some(e);
                    continue;
                }

                // Send message via TCP
                match tcp_pool.send_to_peer(peer_id, &serialized).await {
                    Ok(_) => {
                        info!(
                            "✅ Successfully delivered message {} to peer {} ({} bytes)",
                            queued_message.metadata.message_id,
                            peer_id,
                            serialized.len()
                        );

                        // Wait for ACK (optional, with timeout)
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            Self::wait_for_ack(tcp_pool, peer_id, &queued_message.metadata.message_id),
                        )
                        .await
                        {
                            Ok(Ok(true)) => {
                                debug!("✅ Received ACK from peer {}", peer_id);
                                delivery_success = true;
                                break; // Successfully delivered, no need to try other peers
                            }
                            Ok(Ok(false)) => {
                                warn!("⚠️ Received NACK from peer {}", peer_id);
                                last_error = Some(AvoError::network("Peer rejected message".to_string()));
                            }
                            Ok(Err(e)) => {
                                warn!("⚠️ ACK error from peer {}: {}", peer_id, e);
                                last_error = Some(e);
                            }
                            Err(_) => {
                                warn!("⏱️ ACK timeout from peer {}", peer_id);
                                // Still consider it delivered if send succeeded
                                delivery_success = true;
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "❌ Failed to send message {} to peer {}: {}",
                            queued_message.metadata.message_id, peer_id, e
                        );
                        last_error = Some(e);
                        // Try next peer
                    }
                }
            }
        }

        if delivery_success {
            Ok(())
        } else {
            Err(last_error.unwrap_or_else(|| {
                AvoError::network("No peers available for delivery".to_string())
            }))
        }
    }

    /// Wait for ACK/NACK response from peer
    async fn wait_for_ack(
        tcp_pool: &Arc<TcpConnectionPool>,
        peer_id: &str,
        expected_message_id: &str,
    ) -> Result<bool, AvoError> {
        // Receive ACK message
        let ack_bytes = tcp_pool.receive_from_peer(&peer_id.to_string()).await?;

        // Deserialize ACK
        #[derive(Serialize, Deserialize)]
        struct AckMessage {
            message_id: String,
            status: bool, // true = ACK, false = NACK
        }

        let ack: AckMessage = bincode::deserialize(&ack_bytes)
            .map_err(|e| AvoError::network(format!("Failed to deserialize ACK: {}", e)))?;

        if ack.message_id != expected_message_id {
            return Err(AvoError::network(format!(
                "ACK message_id mismatch: expected {}, got {}",
                expected_message_id, ack.message_id
            )));
        }

        Ok(ack.status)
    }

    /// Start cleanup task for expired messages and stale routes
    async fn start_cleanup_task(&self) {
        let queue = self.message_queue.clone();
        let routes = self.peer_routes.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            while *is_running.read().await {
                // Clean up expired messages
                {
                    let mut queue_guard = queue.write().await;
                    let now = SystemTime::now();

                    for priority_queue in queue_guard.values_mut() {
                        priority_queue.retain(|msg| {
                            if let Ok(elapsed) = now.duration_since(msg.metadata.timestamp) {
                                elapsed.as_secs() < 300 // Keep messages for max 5 minutes
                            } else {
                                false
                            }
                        });
                    }
                }

                // Clean up stale peer routes
                {
                    let mut routes_guard = routes.write().await;
                    let now = SystemTime::now();

                    routes_guard.retain(|_peer_id, route| {
                        if let Some(last_success) = route.last_success {
                            if let Ok(elapsed) = now.duration_since(last_success) {
                                elapsed.as_secs() < 3600 // Keep routes for max 1 hour without success
                            } else {
                                false
                            }
                        } else {
                            // No successful communication yet, keep for now
                            true
                        }
                    });
                }

                // Run cleanup every 60 seconds
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }

    /// Update peer reliability based on delivery success/failure
    pub async fn update_peer_reliability(&self, peer_id: &str, success: bool) {
        let mut routes = self.peer_routes.write().await;

        if let Some(route) = routes.get_mut(peer_id) {
            if success {
                route.last_success = Some(SystemTime::now());
                route.consecutive_failures = 0;
                route.reliability_score = (route.reliability_score * 0.9 + 1.0 * 0.1).min(1.0);
                route.message_count += 1;
            } else {
                route.consecutive_failures += 1;
                route.reliability_score = (route.reliability_score * 0.9).max(0.0);
            }
        }
    }

    /// Get best peer for a specific message type or shard
    pub async fn get_best_peer_for_shard(&self, shard_id: u32) -> Option<String> {
        let routes = self.peer_routes.read().await;

        let mut best_peer: Option<&PeerRouteInfo> = None;
        let mut best_score = 0.0f64;

        for route in routes.values() {
            if route.shard_assignments.contains(&shard_id) {
                // Calculate score based on reliability and latency
                let latency_score = match route.latency {
                    Some(lat) => 1.0 / (lat.as_millis() as f64 + 1.0),
                    None => 0.5,
                };

                let total_score = route.reliability_score * 0.7 + latency_score * 0.3;

                if total_score > best_score {
                    best_score = total_score;
                    best_peer = Some(route);
                }
            }
        }

        best_peer.map(|peer| peer.peer_id.clone())
    }
}
