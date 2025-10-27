use crate::error::AvoError;
use crate::network::tcp_pool::TcpConnectionPool;
use crate::types::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

/// High-performance gossip protocol for AVO network
#[derive(Debug)]
pub struct OptimizedGossipProtocol {
    /// Local node identifier
    local_node_id: NodeId,
    /// Connected peers for gossip
    connected_peers: Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
    /// TCP connection pool for real network communication
    tcp_pool: Arc<TcpConnectionPool>,
    /// Message cache to prevent duplicates
    message_cache: Arc<RwLock<MessageCache>>,
    /// Gossip configuration
    config: GossipConfig,
    /// Message sender for outbound gossip
    outbound_sender: mpsc::UnboundedSender<GossipMessage>,
    /// Message receiver for inbound gossip
    inbound_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<GossipMessage>>>>,
    /// Event broadcaster for application layer
    event_broadcaster: broadcast::Sender<GossipEvent>,
    /// Gossip statistics
    stats: Arc<RwLock<GossipStats>>,
    /// Priority queues for different message types
    priority_queues: Arc<RwLock<PriorityQueues>>,
}

/// Connection information for a gossip peer
#[derive(Debug, Clone)]
pub struct PeerConnection {
    pub node_id: NodeId,
    pub addr: SocketAddr, // Real network address
    pub last_seen: u64,
    pub message_count: u64,
    pub latency_ms: f64,
    pub reliability_score: f64,
    pub is_validator: bool,
    pub supported_protocols: Vec<String>,
}

/// Gossip message with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub id: MessageId,
    pub message_type: GossipMessageType,
    pub payload: Vec<u8>,
    pub sender: NodeId,
    pub timestamp: u64,
    pub ttl: u8,
    pub priority: MessagePriority,
    pub path: Vec<NodeId>,
    pub signature: Option<Vec<u8>>,
}

/// Types of gossip messages
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GossipMessageType {
    /// Transaction gossip
    Transaction,
    /// Block/batch gossip
    Block,
    /// Consensus messages
    Consensus,
    /// Network topology updates
    Topology,
    /// Node announcements
    NodeAnnouncement,
    /// Application-specific data
    Application,
    /// Health checks and heartbeats
    Heartbeat,
}

/// Message priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    Critical = 0,   // Consensus messages
    High = 1,       // Blocks
    Medium = 2,     // Transactions
    Low = 3,        // Announcements
    Background = 4, // Heartbeats
}

/// Unique message identifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MessageId {
    pub hash: [u8; 32],
}

/// Message cache for duplicate detection
#[derive(Debug)]
struct MessageCache {
    /// Recently seen messages
    seen_messages: HashMap<MessageId, u64>,
    /// Maximum cache size
    max_size: usize,
    /// Cache cleanup threshold
    cleanup_threshold: u64,
}

/// Gossip configuration
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Maximum number of peers to gossip to per message
    pub fanout: usize,
    /// Message time-to-live
    pub default_ttl: u8,
    /// Gossip interval in milliseconds
    pub gossip_interval_ms: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Message cache size
    pub cache_size: usize,
    /// Enable message compression
    pub compression_enabled: bool,
    /// Enable message batching
    pub batching_enabled: bool,
    /// Batch size for message aggregation
    pub batch_size: usize,
    /// Adaptive fanout based on network conditions
    pub adaptive_fanout: bool,
}

/// Gossip statistics
#[derive(Debug, Default, Clone)]
pub struct GossipStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_duplicated: u64,
    pub messages_dropped: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub average_latency_ms: f64,
    pub network_coverage: f64,
    pub gossip_efficiency: f64,
}

/// Priority queues for different message types
#[derive(Debug, Default)]
struct PriorityQueues {
    critical: VecDeque<GossipMessage>,
    high: VecDeque<GossipMessage>,
    medium: VecDeque<GossipMessage>,
    low: VecDeque<GossipMessage>,
    background: VecDeque<GossipMessage>,
}

/// Events emitted by gossip protocol
#[derive(Debug, Clone)]
pub enum GossipEvent {
    MessageReceived {
        message: GossipMessage,
        from_peer: NodeId,
    },
    PeerConnected {
        peer_id: NodeId,
    },
    PeerDisconnected {
        peer_id: NodeId,
    },
    NetworkPartition {
        affected_peers: Vec<NodeId>,
    },
    HighLatencyDetected {
        peer_id: NodeId,
        latency_ms: f64,
    },
}

impl OptimizedGossipProtocol {
    /// Create new optimized gossip protocol
    pub fn new(
        local_node_id: NodeId,
        config: GossipConfig,
    ) -> (Self, broadcast::Receiver<GossipEvent>) {
        let (outbound_sender, _outbound_receiver) = mpsc::unbounded_channel();
        let (_inbound_sender, inbound_receiver) = mpsc::unbounded_channel();
        let (event_broadcaster, event_receiver) = broadcast::channel(1000);

        // Create TCP connection pool for real network communication
        let tcp_pool = Arc::new(TcpConnectionPool::new(
            1000,                         // max 1000 connections
            Duration::from_secs(300),     // 5 minute idle timeout
        ));

        let protocol = Self {
            local_node_id,
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            tcp_pool,
            message_cache: Arc::new(RwLock::new(MessageCache::new(config.cache_size))),
            config,
            outbound_sender,
            inbound_receiver: Arc::new(RwLock::new(Some(inbound_receiver))),
            event_broadcaster,
            stats: Arc::new(RwLock::new(GossipStats::default())),
            priority_queues: Arc::new(RwLock::new(PriorityQueues::default())),
        };

        (protocol, event_receiver)
    }

    /// Add or update a peer connection with network address
    pub async fn add_peer(&self, peer: PeerConnection) -> Result<(), AvoError> {
        info!(
            "📡 Adding peer {} at {} to gossip protocol",
            peer.node_id, peer.addr
        );

        // Attempt to establish TCP connection
        self.tcp_pool
            .get_or_connect(peer.node_id.clone(), peer.addr)
            .await?;

        // Add peer to connected peers list
        let mut peers = self.connected_peers.write().await;
        peers.insert(peer.node_id.clone(), peer.clone());

        // Emit event
        let _ = self
            .event_broadcaster
            .send(GossipEvent::PeerConnected {
                peer_id: peer.node_id.clone(),
            });

        info!("✅ Peer {} connected successfully", peer.node_id);
        Ok(())
    }

    /// Remove a peer connection
    pub async fn remove_peer(&self, peer_id: &NodeId) -> Result<(), AvoError> {
        let mut peers = self.connected_peers.write().await;
        if peers.remove(peer_id).is_some() {
            info!("🔌 Removed peer {} from gossip protocol", peer_id);

            // Emit event
            let _ = self
                .event_broadcaster
                .send(GossipEvent::PeerDisconnected {
                    peer_id: peer_id.clone(),
                });
        }
        Ok(())
    }

    /// Get list of connected peers
    pub async fn get_connected_peers(&self) -> Vec<NodeId> {
        let peers = self.connected_peers.read().await;
        peers.keys().cloned().collect()
    }

    /// Start the gossip protocol
    pub async fn start(&self) -> Result<(), AvoError> {
        info!(
            "🗣️ Starting optimized gossip protocol for node {}",
            self.local_node_id
        );

        // Start gossip processing loop
        self.start_gossip_loop().await;

        // Start priority message processing
        self.start_priority_processing().await;

        // Start statistics collection
        self.start_stats_collection().await;

        // Start adaptive optimization
        self.start_adaptive_optimization().await;

        info!("✅ Gossip protocol started successfully");
        Ok(())
    }

    /// Start the main gossip processing loop
    async fn start_gossip_loop(&self) {
        let _outbound_sender = self.outbound_sender.clone();
        let connected_peers = self.connected_peers.clone();
        let message_cache = self.message_cache.clone();
        let stats = self.stats.clone();
        let config = self.config.clone();
        let local_node_id = self.local_node_id.clone();
        let event_broadcaster = self.event_broadcaster.clone();

        tokio::spawn(async move {
            let mut gossip_interval = interval(Duration::from_millis(config.gossip_interval_ms));

            loop {
                gossip_interval.tick().await;

                // Process pending outbound messages
                Self::process_outbound_messages(
                    &connected_peers,
                    &message_cache,
                    &stats,
                    &config,
                    &local_node_id,
                    &event_broadcaster,
                )
                .await;
            }
        });
    }

    /// Start priority message processing
    async fn start_priority_processing(&self) {
        let priority_queues = self.priority_queues.clone();
        let connected_peers = self.connected_peers.clone();
        let tcp_pool = self.tcp_pool.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut processing_interval = interval(Duration::from_millis(10)); // High frequency for priority

            loop {
                processing_interval.tick().await;

                Self::process_priority_queues(&priority_queues, &connected_peers, &tcp_pool, &config, &stats)
                    .await;
            }
        });
    }

    /// Process messages by priority
    async fn process_priority_queues(
        priority_queues: &Arc<RwLock<PriorityQueues>>,
        connected_peers: &Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
        tcp_pool: &Arc<TcpConnectionPool>,
        config: &GossipConfig,
        stats: &Arc<RwLock<GossipStats>>,
    ) {
        let mut queues = priority_queues.write().await;

        // Process critical messages first
        while let Some(message) = queues.critical.pop_front() {
            Self::gossip_message_to_peers(&message, connected_peers, tcp_pool, config, stats).await;
        }

        // Process high priority messages
        let high_batch_size = config.batch_size / 2;
        for _ in 0..high_batch_size {
            if let Some(message) = queues.high.pop_front() {
                Self::gossip_message_to_peers(&message, connected_peers, tcp_pool, config, stats).await;
            } else {
                break;
            }
        }

        // Process medium priority messages
        let medium_batch_size = config.batch_size / 4;
        for _ in 0..medium_batch_size {
            if let Some(message) = queues.medium.pop_front() {
                Self::gossip_message_to_peers(&message, connected_peers, tcp_pool, config, stats).await;
            } else {
                break;
            }
        }

        // Process low priority messages occasionally
        if current_timestamp() % 10 == 0 {
            if let Some(message) = queues.low.pop_front() {
                Self::gossip_message_to_peers(&message, connected_peers, tcp_pool, config, stats).await;
            }
        }

        // Process background messages very occasionally
        if current_timestamp() % 60 == 0 {
            if let Some(message) = queues.background.pop_front() {
                Self::gossip_message_to_peers(&message, connected_peers, tcp_pool, config, stats).await;
            }
        }
    }

    /// Gossip a message to selected peers
    async fn gossip_message_to_peers(
        message: &GossipMessage,
        connected_peers: &Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
        tcp_pool: &Arc<TcpConnectionPool>,
        config: &GossipConfig,
        stats: &Arc<RwLock<GossipStats>>,
    ) {
        let peers = connected_peers.read().await;

        // Select peers for gossip based on message type and network topology
        let selected_peers = Self::select_gossip_peers(&peers, message, config);

        let message_size = Self::estimate_message_size(message);
        let mut successful_sends = 0;
        let mut failed_sends = 0;

        // Send to selected peers using real TCP connections
        for peer_id in selected_peers {
            if let Some(peer) = peers.get(&peer_id) {
                match Self::send_message_to_peer(tcp_pool, peer, message).await {
                    Ok(_) => {
                        successful_sends += 1;
                        // Update statistics
                        let mut stats_guard = stats.write().await;
                        stats_guard.messages_sent += 1;
                        stats_guard.bytes_sent += message_size as u64;
                    }
                    Err(e) => {
                        failed_sends += 1;
                        warn!("⚠️ Failed to gossip to peer {}: {}", peer_id, e);
                        // Update failure statistics
                        let mut stats_guard = stats.write().await;
                        stats_guard.messages_dropped += 1;
                    }
                }
            }
        }

        if successful_sends > 0 {
            debug!(
                "📨 Gossip complete: {} successful, {} failed",
                successful_sends, failed_sends
            );
        }
    }

    /// Select optimal peers for gossip
    fn select_gossip_peers(
        peers: &HashMap<NodeId, PeerConnection>,
        message: &GossipMessage,
        config: &GossipConfig,
    ) -> Vec<NodeId> {
        let mut candidates: Vec<&PeerConnection> = peers.values().collect();

        // Filter out sender to avoid echo
        candidates.retain(|peer| peer.node_id != message.sender);

        // Filter out nodes already in message path
        let path_set: HashSet<&NodeId> = message.path.iter().collect();
        candidates.retain(|peer| !path_set.contains(&peer.node_id));

        // Sort by selection criteria
        candidates.sort_by(|a, b| {
            let a_score = Self::calculate_peer_score(a, message);
            let b_score = Self::calculate_peer_score(b, message);
            b_score
                .partial_cmp(&a_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Determine fanout
        let fanout = if config.adaptive_fanout {
            Self::calculate_adaptive_fanout(message, candidates.len(), config.fanout)
        } else {
            config.fanout
        };

        candidates
            .into_iter()
            .take(fanout)
            .map(|peer| peer.node_id.clone())
            .collect()
    }

    /// Calculate peer selection score
    fn calculate_peer_score(peer: &PeerConnection, message: &GossipMessage) -> f64 {
        let latency_score = if peer.latency_ms < 50.0 {
            3.0
        } else if peer.latency_ms < 100.0 {
            2.0
        } else if peer.latency_ms < 200.0 {
            1.0
        } else {
            0.5
        };

        let reliability_score = peer.reliability_score;

        let type_bonus = match message.message_type {
            GossipMessageType::Consensus | GossipMessageType::Block => {
                if peer.is_validator {
                    2.0
                } else {
                    1.0
                }
            }
            _ => 1.0,
        };

        latency_score * 0.4 + reliability_score * 0.4 + type_bonus * 0.2
    }

    /// Calculate adaptive fanout based on network conditions
    fn calculate_adaptive_fanout(
        message: &GossipMessage,
        available_peers: usize,
        base_fanout: usize,
    ) -> usize {
        let priority_multiplier = match message.priority {
            MessagePriority::Critical => 1.5,
            MessagePriority::High => 1.2,
            MessagePriority::Medium => 1.0,
            MessagePriority::Low => 0.8,
            MessagePriority::Background => 0.5,
        };

        let network_density_factor = if available_peers < 10 {
            1.5 // Increase fanout in sparse networks
        } else if available_peers > 100 {
            0.8 // Decrease fanout in dense networks
        } else {
            1.0
        };

        let calculated_fanout =
            (base_fanout as f64 * priority_multiplier * network_density_factor) as usize;

        // Ensure reasonable bounds
        calculated_fanout
            .max(2)
            .min(available_peers)
            .min(base_fanout * 2)
    }

    /// Send message to peer via real TCP connection
    async fn send_message_to_peer(
        tcp_pool: &Arc<TcpConnectionPool>,
        peer: &PeerConnection,
        message: &GossipMessage,
    ) -> Result<(), AvoError> {
        // Serialize message using bincode for efficient network transmission
        let message_bytes = bincode::serialize(message).map_err(|e| {
            error!("❌ Failed to serialize gossip message: {}", e);
            AvoError::network(format!("Serialization error: {}", e))
        })?;

        // Establish or reuse TCP connection
        tcp_pool
            .get_or_connect(peer.node_id.clone(), peer.addr)
            .await?;

        // Send message via TCP
        match tcp_pool.send_to_peer(&peer.node_id, &message_bytes).await {
            Ok(_) => {
                debug!(
                    "� Real gossip message {} sent to peer {} at {} ({} bytes)",
                    hex::encode(&message.id.hash[..8]),
                    peer.node_id,
                    peer.addr,
                    message_bytes.len()
                );
                Ok(())
            }
            Err(e) => {
                warn!(
                    "⚠️ Failed to send message to peer {} at {}: {}",
                    peer.node_id, peer.addr, e
                );
                Err(e)
            }
        }
    }

    /// Process outbound messages from queue
    async fn process_outbound_messages(
        _connected_peers: &Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
        message_cache: &Arc<RwLock<MessageCache>>,
        _stats: &Arc<RwLock<GossipStats>>,
        _config: &GossipConfig,
        local_node_id: &NodeId,
        _event_broadcaster: &broadcast::Sender<GossipEvent>,
    ) {
        // In real implementation, this would process actual queued messages
        // For now, we simulate periodic gossip activity

        debug!("🔄 Processing gossip messages for node {}", local_node_id);

        // Simulate cache cleanup
        let mut cache = message_cache.write().await;
        cache.cleanup(current_timestamp());
    }

    /// Start statistics collection
    async fn start_stats_collection(&self) {
        let stats = self.stats.clone();
        let connected_peers = self.connected_peers.clone();

        tokio::spawn(async move {
            let mut stats_interval = interval(Duration::from_secs(30));

            loop {
                stats_interval.tick().await;

                let peers = connected_peers.read().await;
                let mut stats_guard = stats.write().await;

                // Calculate network coverage
                stats_guard.network_coverage = peers.len() as f64 / 100.0; // Assume max 100 peers

                // Calculate gossip efficiency
                if stats_guard.messages_sent > 0 {
                    stats_guard.gossip_efficiency =
                        (stats_guard.messages_received as f64) / (stats_guard.messages_sent as f64);
                }

                // Calculate average latency
                if !peers.is_empty() {
                    stats_guard.average_latency_ms =
                        peers.values().map(|p| p.latency_ms).sum::<f64>() / peers.len() as f64;
                }

                debug!(
                    "📊 Gossip stats - Sent: {}, Received: {}, Coverage: {:.2}, Efficiency: {:.2}",
                    stats_guard.messages_sent,
                    stats_guard.messages_received,
                    stats_guard.network_coverage,
                    stats_guard.gossip_efficiency
                );
            }
        });
    }

    /// Start adaptive optimization
    async fn start_adaptive_optimization(&self) {
        let _config = self.config.clone();
        let stats = self.stats.clone();
        let connected_peers = self.connected_peers.clone();

        tokio::spawn(async move {
            let mut optimization_interval = interval(Duration::from_secs(60));

            loop {
                optimization_interval.tick().await;

                Self::optimize_gossip_parameters(&stats, &connected_peers).await;
            }
        });
    }

    /// Optimize gossip parameters based on network conditions
    async fn optimize_gossip_parameters(
        stats: &Arc<RwLock<GossipStats>>,
        connected_peers: &Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
    ) {
        let stats_guard = stats.read().await;
        let peers = connected_peers.read().await;

        // Adaptive optimizations based on network metrics
        if stats_guard.gossip_efficiency < 0.7 {
            info!("🔧 Low gossip efficiency detected, optimizing parameters");
            // In real implementation, adjust fanout, intervals, etc.
        }

        if stats_guard.average_latency_ms > 200.0 {
            info!("🔧 High latency detected, optimizing routing");
            // In real implementation, prefer low-latency peers
        }

        if peers.len() < 5 {
            info!("🔧 Low peer count, increasing discovery");
            // In real implementation, trigger more aggressive peer discovery
        }
    }

    /// Gossip a new message
    pub async fn gossip_message(
        &self,
        message_type: GossipMessageType,
        payload: Vec<u8>,
        priority: MessagePriority,
    ) -> Result<MessageId, AvoError> {
        if payload.len() > self.config.max_message_size {
            return Err(AvoError::network("Message too large"));
        }

        let message_id = MessageId {
            hash: Self::calculate_message_hash(&payload),
        };

        let message = GossipMessage {
            id: message_id.clone(),
            message_type,
            payload,
            sender: self.local_node_id.clone(),
            timestamp: current_timestamp(),
            ttl: self.config.default_ttl,
            priority: priority.clone(),
            path: vec![self.local_node_id.clone()],
            signature: None, // In real implementation, sign the message
        };

        // Add to appropriate priority queue
        let mut queues = self.priority_queues.write().await;
        match message.priority {
            MessagePriority::Critical => queues.critical.push_back(message),
            MessagePriority::High => queues.high.push_back(message),
            MessagePriority::Medium => queues.medium.push_back(message),
            MessagePriority::Low => queues.low.push_back(message),
            MessagePriority::Background => queues.background.push_back(message),
        }

        info!(
            "📤 Queued gossip message {} with priority {:?}",
            hex::encode(&message_id.hash[..8]),
            priority
        );

        Ok(message_id)
    }

    /// Get current gossip statistics
    pub async fn get_stats(&self) -> GossipStats {
        self.stats.read().await.clone()
    }

    /// Calculate message hash
    fn calculate_message_hash(payload: &[u8]) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        payload.hash(&mut hasher);
        let hash_u64 = hasher.finish();

        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&hash_u64.to_be_bytes());
        hash
    }

    /// Estimate message size
    fn estimate_message_size(message: &GossipMessage) -> usize {
        // Rough estimation
        message.payload.len() + 200 // Add overhead for metadata
    }
}

impl MessageCache {
    fn new(max_size: usize) -> Self {
        Self {
            seen_messages: HashMap::new(),
            max_size,
            cleanup_threshold: 3600, // 1 hour
        }
    }

    fn has_seen(&self, message_id: &MessageId) -> bool {
        self.seen_messages.contains_key(message_id)
    }

    fn mark_seen(&mut self, message_id: MessageId, timestamp: u64) {
        if self.seen_messages.len() >= self.max_size {
            self.cleanup(timestamp);
        }

        self.seen_messages.insert(message_id, timestamp);
    }

    fn cleanup(&mut self, current_time: u64) {
        self.seen_messages
            .retain(|_, timestamp| current_time - *timestamp < self.cleanup_threshold);
    }
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            fanout: 6,
            default_ttl: 7,
            gossip_interval_ms: 100,
            max_message_size: 1024 * 1024, // 1MB
            cache_size: 10000,
            compression_enabled: true,
            batching_enabled: true,
            batch_size: 50,
            adaptive_fanout: true,
        }
    }
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
