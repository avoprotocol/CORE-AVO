use crate::error::AvoError;
use crate::network::optimized_gossip::OptimizedGossipProtocol;
use crate::network::{NetworkConfig, NodeEndpoint};
use crate::types::Hash;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Gossip message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// Transaction gossip
    Transaction {
        tx_hash: Hash,
        tx_data: Vec<u8>,
        timestamp: SystemTime,
        hop_count: u32,
    },
    /// Block gossip
    Block {
        block_hash: Hash,
        block_data: Vec<u8>,
        timestamp: SystemTime,
        hop_count: u32,
    },
    /// Peer announcement
    PeerAnnouncement {
        peer_info: NodeEndpoint,
        timestamp: SystemTime,
        hop_count: u32,
    },
    /// Network status update
    NetworkStatus {
        node_id: String,
        status: String,
        timestamp: SystemTime,
        hop_count: u32,
    },
    /// Custom application message
    Custom {
        message_type: String,
        data: Vec<u8>,
        timestamp: SystemTime,
        hop_count: u32,
    },
}

/// Gossip configuration
#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub max_hop_count: u32,
    pub propagation_delay: Duration,
    pub max_message_age: Duration,
    pub max_peer_fanout: usize,
    pub enable_deduplication: bool,
    pub message_cache_size: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_hop_count: 10,
            propagation_delay: Duration::from_millis(100),
            max_message_age: Duration::from_secs(300), // 5 minutes
            max_peer_fanout: 3,
            enable_deduplication: true,
            message_cache_size: 1000,
        }
    }
}

/// Gossip statistics
#[derive(Debug, Clone, Default)]
pub struct GossipStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_forwarded: u64,
    pub messages_dropped: u64,
    pub duplicate_messages: u64,
    pub active_messages: usize,
    pub cache_hit_rate: f64,
}

/// Message tracking information
#[derive(Debug, Clone)]
struct MessageTracker {
    message_id: Hash,
    first_seen: SystemTime,
    source_peer: String,
    propagation_count: u32,
}

/// Basic Gossip Protocol - Simple and efficient message propagation
pub struct GossipProtocol {
    /// Gossip configuration
    config: GossipConfig,
    /// Network configuration
    network_config: NetworkConfig,
    /// Optimized gossip service
    optimized_gossip: Arc<OptimizedGossipProtocol>,
    /// Message cache for deduplication
    message_cache: Arc<RwLock<HashMap<Hash, MessageTracker>>>,
    /// Connected peers for gossip
    gossip_peers: Arc<RwLock<HashSet<String>>>,
    /// Gossip statistics
    stats: Arc<RwLock<GossipStats>>,
    /// Running status
    is_running: Arc<RwLock<bool>>,
}

impl GossipProtocol {
    /// Create new gossip protocol
    pub fn new(network_config: NetworkConfig) -> Self {
        let config = GossipConfig::default();
        let optimized_gossip = Arc::new(
            OptimizedGossipProtocol::new(network_config.node_id.clone(), Default::default()).0,
        );

        Self {
            config,
            network_config,
            optimized_gossip,
            message_cache: Arc::new(RwLock::new(HashMap::new())),
            gossip_peers: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(RwLock::new(GossipStats::default())),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Create with custom configuration
    pub fn with_config(network_config: NetworkConfig, gossip_config: GossipConfig) -> Self {
        let optimized_gossip = Arc::new(
            OptimizedGossipProtocol::new(network_config.node_id.clone(), Default::default()).0,
        );

        Self {
            config: gossip_config,
            network_config,
            optimized_gossip,
            message_cache: Arc::new(RwLock::new(HashMap::new())),
            gossip_peers: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(RwLock::new(GossipStats::default())),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start gossip protocol
    pub async fn start(&self) -> Result<(), AvoError> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }
        *is_running = true;
        drop(is_running);

        println!("🗣️ Starting Gossip Protocol");
        println!("   • Max hop count: {}", self.config.max_hop_count);
        println!("   • Max fanout: {}", self.config.max_peer_fanout);
        println!(
            "   • Propagation delay: {:?}",
            self.config.propagation_delay
        );

        // Start optimized gossip service
        if let Err(e) = self.optimized_gossip.start().await {
            eprintln!("⚠️ Optimized gossip failed to start: {:?}", e);
        }

        // Start message cleanup task
        self.start_cleanup_task().await;

        println!("✅ Gossip Protocol started");
        Ok(())
    }

    /// Stop gossip protocol
    pub async fn stop(&self) -> Result<(), AvoError> {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }
        *is_running = false;
        drop(is_running);

        println!("🛑 Stopping Gossip Protocol");

        // Stop optimized gossip
        // TODO: implement proper stop method
        // if let Err(e) = self.optimized_gossip.stop().await {
        //     eprintln!("⚠️ Optimized gossip failed to stop: {:?}", e);
        // }

        // Clear message cache
        {
            let mut cache = self.message_cache.write().await;
            cache.clear();
        }

        // Clear peer list
        {
            let mut peers = self.gossip_peers.write().await;
            peers.clear();
        }

        println!("✅ Gossip Protocol stopped");
        Ok(())
    }

    /// Gossip a message to the network
    pub async fn gossip_message(&self, message: GossipMessage) -> Result<Hash, AvoError> {
        let message_id = self.calculate_message_id(&message);

        // Check if message is too old
        let message_timestamp = self.get_message_timestamp(&message);
        if let Ok(age) = SystemTime::now().duration_since(message_timestamp) {
            if age > self.config.max_message_age {
                return Err(AvoError::NetworkError {
                    reason: "Message too old to gossip".to_string(),
                });
            }
        }

        // Check for duplicate
        if self.config.enable_deduplication {
            let cache = self.message_cache.read().await;
            if cache.contains_key(&message_id) {
                let mut stats = self.stats.write().await;
                stats.duplicate_messages += 1;
                return Err(AvoError::NetworkError {
                    reason: "Duplicate message".to_string(),
                });
            }
        }

        // Add to cache
        {
            let mut cache = self.message_cache.write().await;
            if cache.len() >= self.config.message_cache_size {
                // Remove oldest entries
                let now = SystemTime::now();
                cache.retain(|_, tracker| {
                    now.duration_since(tracker.first_seen)
                        .map(|age| age < self.config.max_message_age)
                        .unwrap_or(false)
                });
            }

            cache.insert(
                message_id,
                MessageTracker {
                    message_id,
                    first_seen: SystemTime::now(),
                    source_peer: "local".to_string(),
                    propagation_count: 0,
                },
            );
        }

        // Select peers for gossip
        let target_peers = self.select_gossip_peers().await;

        if target_peers.is_empty() {
            return Err(AvoError::NetworkError {
                reason: "No peers available for gossip".to_string(),
            });
        }

        // Propagate message
        let mut propagated_count = 0;
        for peer_id in target_peers {
            if let Err(e) = self.send_gossip_to_peer(&peer_id, &message).await {
                eprintln!("⚠️ Failed to gossip to peer {}: {}", peer_id, e);
            } else {
                propagated_count += 1;
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.messages_sent += 1;
            stats.messages_forwarded += propagated_count;
        }

        // Try optimized gossip for high-priority messages
        match &message {
            GossipMessage::Block { .. } | GossipMessage::Transaction { .. } => {
                // TODO: implement proper broadcast_high_priority method
                // if let Err(e) = self.optimized_gossip.broadcast_high_priority(
                //     bincode::serialize(&message).unwrap_or_default()
                // ).await {
                //     eprintln!("⚠️ Optimized gossip failed: {:?}", e);
                // }
            }
            _ => {} // Use basic gossip for other messages
        }

        println!("📢 Gossiped message to {} peers", propagated_count);
        Ok(message_id)
    }

    /// Handle incoming gossip message
    pub async fn handle_gossip_message(
        &self,
        message: GossipMessage,
        source_peer: &str,
    ) -> Result<bool, AvoError> {
        let message_id = self.calculate_message_id(&message);

        // Update receive stats
        {
            let mut stats = self.stats.write().await;
            stats.messages_received += 1;
        }

        // Check for duplicate
        if self.config.enable_deduplication {
            let mut cache = self.message_cache.write().await;
            if let Some(tracker) = cache.get_mut(&message_id) {
                // Update cache hit rate
                let mut stats = self.stats.write().await;
                stats.duplicate_messages += 1;
                stats.cache_hit_rate =
                    stats.duplicate_messages as f64 / stats.messages_received as f64;

                return Ok(false); // Duplicate, don't propagate
            } else {
                // Add to cache
                cache.insert(
                    message_id,
                    MessageTracker {
                        message_id,
                        first_seen: SystemTime::now(),
                        source_peer: source_peer.to_string(),
                        propagation_count: 0,
                    },
                );
            }
        }

        // Check hop count
        let hop_count = self.get_message_hop_count(&message);
        if hop_count >= self.config.max_hop_count {
            let mut stats = self.stats.write().await;
            stats.messages_dropped += 1;
            return Ok(false); // Don't propagate further
        }

        // Check message age
        let message_timestamp = self.get_message_timestamp(&message);
        if let Ok(age) = SystemTime::now().duration_since(message_timestamp) {
            if age > self.config.max_message_age {
                let mut stats = self.stats.write().await;
                stats.messages_dropped += 1;
                return Ok(false); // Too old, don't propagate
            }
        }

        // Process the message (application-specific logic would go here)
        self.process_gossip_message(&message).await?;

        // Forward to other peers (excluding source)
        let mut forwarded_message = message;
        self.increment_hop_count(&mut forwarded_message);

        let target_peers = self.select_gossip_peers_excluding(source_peer).await;
        let mut forward_count = 0;

        for peer_id in target_peers {
            if let Err(e) = self.send_gossip_to_peer(&peer_id, &forwarded_message).await {
                eprintln!("⚠️ Failed to forward gossip to peer {}: {}", peer_id, e);
            } else {
                forward_count += 1;
            }
        }

        // Update forwarding stats
        {
            let mut stats = self.stats.write().await;
            stats.messages_forwarded += forward_count;
        }

        println!("🔄 Forwarded gossip message to {} peers", forward_count);
        Ok(true)
    }

    /// Add a peer for gossiping
    pub async fn add_gossip_peer(&self, peer_id: String) {
        let mut peers = self.gossip_peers.write().await;
        peers.insert(peer_id.clone());
        println!("➕ Added gossip peer: {}", peer_id);
    }

    /// Remove a peer from gossiping
    pub async fn remove_gossip_peer(&self, peer_id: &str) {
        let mut peers = self.gossip_peers.write().await;
        peers.remove(peer_id);
        println!("➖ Removed gossip peer: {}", peer_id);
    }

    /// Get gossip statistics
    pub async fn get_stats(&self) -> GossipStats {
        let mut stats = self.stats.read().await.clone();

        // Update active messages count
        let cache = self.message_cache.read().await;
        stats.active_messages = cache.len();

        // Update cache hit rate if we have received messages
        if stats.messages_received > 0 {
            stats.cache_hit_rate = stats.duplicate_messages as f64 / stats.messages_received as f64;
        }

        stats
    }

    /// Get active gossip peers
    pub async fn get_gossip_peers(&self) -> Vec<String> {
        let peers = self.gossip_peers.read().await;
        peers.iter().cloned().collect()
    }

    /// Calculate message ID for deduplication
    fn calculate_message_id(&self, message: &GossipMessage) -> Hash {
        let message_data = bincode::serialize(message).unwrap_or_default();
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&message_data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result[..32]);
        hash
    }

    /// Get message timestamp
    fn get_message_timestamp(&self, message: &GossipMessage) -> SystemTime {
        match message {
            GossipMessage::Transaction { timestamp, .. } => *timestamp,
            GossipMessage::Block { timestamp, .. } => *timestamp,
            GossipMessage::PeerAnnouncement { timestamp, .. } => *timestamp,
            GossipMessage::NetworkStatus { timestamp, .. } => *timestamp,
            GossipMessage::Custom { timestamp, .. } => *timestamp,
        }
    }

    /// Get message hop count
    fn get_message_hop_count(&self, message: &GossipMessage) -> u32 {
        match message {
            GossipMessage::Transaction { hop_count, .. } => *hop_count,
            GossipMessage::Block { hop_count, .. } => *hop_count,
            GossipMessage::PeerAnnouncement { hop_count, .. } => *hop_count,
            GossipMessage::NetworkStatus { hop_count, .. } => *hop_count,
            GossipMessage::Custom { hop_count, .. } => *hop_count,
        }
    }

    /// Increment hop count in message
    fn increment_hop_count(&self, message: &mut GossipMessage) {
        match message {
            GossipMessage::Transaction { hop_count, .. } => *hop_count += 1,
            GossipMessage::Block { hop_count, .. } => *hop_count += 1,
            GossipMessage::PeerAnnouncement { hop_count, .. } => *hop_count += 1,
            GossipMessage::NetworkStatus { hop_count, .. } => *hop_count += 1,
            GossipMessage::Custom { hop_count, .. } => *hop_count += 1,
        }
    }

    /// Select peers for gossip (random subset)
    async fn select_gossip_peers(&self) -> Vec<String> {
        let peers = self.gossip_peers.read().await;
        let peer_list: Vec<_> = peers.iter().cloned().collect();

        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let mut selected = peer_list;
        selected.shuffle(&mut rng);

        selected
            .into_iter()
            .take(self.config.max_peer_fanout)
            .collect()
    }

    /// Select peers for gossip excluding a specific peer
    async fn select_gossip_peers_excluding(&self, exclude_peer: &str) -> Vec<String> {
        let peers = self.gossip_peers.read().await;
        let peer_list: Vec<_> = peers
            .iter()
            .filter(|&peer| peer != exclude_peer)
            .cloned()
            .collect();

        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let mut selected = peer_list;
        selected.shuffle(&mut rng);

        selected
            .into_iter()
            .take(self.config.max_peer_fanout)
            .collect()
    }

    /// Send gossip message to a specific peer
    async fn send_gossip_to_peer(
        &self,
        peer_id: &str,
        message: &GossipMessage,
    ) -> Result<(), AvoError> {
        // Add propagation delay
        tokio::time::sleep(self.config.propagation_delay).await;

        // In a real implementation, this would send through P2P manager
        // For now, we'll simulate the sending
        let message_size = bincode::serialize(message).unwrap_or_default().len();
        println!(
            "📤 Sent gossip to peer {} ({} bytes)",
            peer_id, message_size
        );

        Ok(())
    }

    /// Process incoming gossip message (application-specific logic)
    async fn process_gossip_message(&self, message: &GossipMessage) -> Result<(), AvoError> {
        match message {
            GossipMessage::Transaction { tx_hash, .. } => {
                println!("📥 Received transaction gossip: {:?}", &tx_hash[..8]);
                // Process transaction...
            }
            GossipMessage::Block { block_hash, .. } => {
                println!("📥 Received block gossip: {:?}", &block_hash[..8]);
                // Process block...
            }
            GossipMessage::PeerAnnouncement { peer_info, .. } => {
                println!(
                    "📥 Received peer announcement: {}:{}",
                    peer_info.address,
                    peer_info.address.port()
                );
                // Process peer announcement...
            }
            GossipMessage::NetworkStatus {
                node_id, status, ..
            } => {
                println!("📥 Received network status from {}: {}", node_id, status);
                // Process network status...
            }
            GossipMessage::Custom { message_type, .. } => {
                println!("📥 Received custom gossip: {}", message_type);
                // Process custom message...
            }
        }

        Ok(())
    }

    /// Start cleanup task for old messages
    async fn start_cleanup_task(&self) {
        let message_cache = self.message_cache.clone();
        let config = self.config.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            while *is_running.read().await {
                let now = SystemTime::now();

                // Clean up old messages
                let removed_count = {
                    let mut cache = message_cache.write().await;
                    let initial_size = cache.len();

                    cache.retain(|_, tracker| {
                        if let Ok(age) = now.duration_since(tracker.first_seen) {
                            age < config.max_message_age
                        } else {
                            false
                        }
                    });

                    initial_size - cache.len()
                };

                if removed_count > 0 {
                    println!("🧹 Cleaned up {} old gossip messages", removed_count);
                }

                // Run cleanup every minute
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }

    /// Create a transaction gossip message
    pub fn create_transaction_gossip(tx_hash: Hash, tx_data: Vec<u8>) -> GossipMessage {
        GossipMessage::Transaction {
            tx_hash,
            tx_data,
            timestamp: SystemTime::now(),
            hop_count: 0,
        }
    }

    /// Create a block gossip message
    pub fn create_block_gossip(block_hash: Hash, block_data: Vec<u8>) -> GossipMessage {
        GossipMessage::Block {
            block_hash,
            block_data,
            timestamp: SystemTime::now(),
            hop_count: 0,
        }
    }

    /// Create a peer announcement gossip message
    pub fn create_peer_announcement(peer_info: NodeEndpoint) -> GossipMessage {
        GossipMessage::PeerAnnouncement {
            peer_info,
            timestamp: SystemTime::now(),
            hop_count: 0,
        }
    }

    /// Create a network status gossip message
    pub fn create_network_status(node_id: String, status: String) -> GossipMessage {
        GossipMessage::NetworkStatus {
            node_id,
            status,
            timestamp: SystemTime::now(),
            hop_count: 0,
        }
    }

    /// Create a custom gossip message
    pub fn create_custom_gossip(message_type: String, data: Vec<u8>) -> GossipMessage {
        GossipMessage::Custom {
            message_type,
            data,
            timestamp: SystemTime::now(),
            hop_count: 0,
        }
    }
}
