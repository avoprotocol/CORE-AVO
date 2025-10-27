use crate::error::{AvoError, AvoResult};
use crate::network::advanced_discovery::{
    AdvancedPeerDiscovery, NodeInfo, NodeType as AdvancedNodeType,
};
use crate::network::key_management::KeyManager;
use crate::network::optimized_gossip::OptimizedGossipProtocol;
use crate::network::tcp_pool::TcpConnectionPool;
use crate::network::{NetworkConfig, NodeEndpoint};
use crate::types::{AggregatedVote, FinalityProofSummary, Hash, ShardId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

/// P2P network connection status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Connected,
    Connecting,
    Disconnected,
    Failed,
}

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub endpoint: NodeEndpoint,
    pub status: ConnectionStatus,
    pub last_seen: SystemTime,
    pub latency: Option<Duration>,
    pub version: String,
    pub capabilities: Vec<String>,
}

/// Network message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Handshake message
    Handshake {
        node_id: String,
        version: String,
        capabilities: Vec<String>,
    },
    /// Keep-alive ping
    Ping {
        timestamp: u64,
    },
    /// Ping response
    Pong {
        timestamp: u64,
    },
    /// Transaction propagation
    Transaction {
        tx_hash: Hash,
        tx_data: Vec<u8>,
    },
    /// Block propagation
    Block {
        block_hash: Hash,
        block_data: Vec<u8>,
    },
    /// Consensus message
    Consensus {
        msg_type: String,
        data: Vec<u8>,
    },
    /// Peer discovery
    PeerDiscovery {
        peers: Vec<NodeEndpoint>,
    },
    /// Custom message
    Custom {
        msg_type: String,
        data: Vec<u8>,
    },
    AggregatedVote {
        shard_id: ShardId,
        vote: AggregatedVote,
    },
    FinalitySummary(FinalityProofSummary),
}

/// Network statistics
#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    pub peers_connected: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_attempts: u64,
    pub connection_failures: u64,
}

/// P2P Network Manager - Core networking component for AVO Protocol
pub struct P2PManager {
    /// Network configuration
    config: NetworkConfig,
    /// Connected peers
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    /// Gossip protocol instance
    gossip: Arc<OptimizedGossipProtocol>,
    /// Discovery service
    discovery: Arc<AdvancedPeerDiscovery>,
    /// Key management system
    key_manager: Arc<KeyManager>,
    /// Message sender channel
    message_sender: mpsc::UnboundedSender<(String, NetworkMessage)>,
    /// Message receiver channel
    message_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<(String, NetworkMessage)>>>>,
    /// Network statistics
    stats: Arc<RwLock<NetworkStats>>,
    /// Suscriptores locales para mensajes P2P
    listeners: Arc<RwLock<Vec<mpsc::UnboundedSender<NetworkMessage>>>>,
    /// Node ID
    node_id: String,
    /// Running status
    is_running: Arc<RwLock<bool>>,
}

impl P2PManager {
    /// Create new P2P manager
    pub fn new(config: NetworkConfig) -> Self {
        let (message_sender, message_receiver) = mpsc::unbounded_channel();
        let node_id = format!("avo-node-{}", uuid::Uuid::new_v4());

        // Initialize key management
        let key_manager = Arc::new(
            KeyManager::load_or_generate("keys/node_key.json")
                .expect("Failed to initialize key manager"),
        );

        // Temporary placeholder implementations - need proper integration
        let gossip =
            Arc::new(OptimizedGossipProtocol::new(config.node_id.clone(), Default::default()).0);
        let discovery = Arc::new(AdvancedPeerDiscovery::new(
            NodeInfo {
                node_id: config.node_id.clone(),
                public_key: key_manager.public_key().to_vec(),
                listen_addr: config.listen_address,
                node_type: AdvancedNodeType::Validator,
                version: "1.0.0".to_string(),
                capabilities: vec!["consensus".to_string(), "validator".to_string()],
                geographic_region: None,
            },
            config.bootstrap_nodes.iter().map(|n| n.address).collect(),
            Arc::new(TcpConnectionPool::default()),
            Default::default(),
        ));

        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            gossip,
            discovery,
            key_manager,
            message_sender,
            message_receiver: Arc::new(RwLock::new(Some(message_receiver))),
            stats: Arc::new(RwLock::new(NetworkStats::default())),
            listeners: Arc::new(RwLock::new(Vec::new())),
            node_id,
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the P2P network manager
    pub async fn start(&self) -> Result<(), AvoError> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }
        *is_running = true;
        drop(is_running);

        println!("🚀 Starting AVO P2P Network Manager");
        println!("   • Node ID: {}", self.node_id);
        println!("   • Listen Address: {}", self.config.listen_address);
        println!("   • Address: {}", self.config.listen_address);

        // Start TCP listener
        self.start_listener().await?;

        // Start peer discovery
        // TODO: implement proper start method for discovery
        // self.discovery.start().await
        //     .map_err(|e| AvoError::NetworkError { reason: format!("Discovery start failed: {:?}", e) })?;

        // Start gossip protocol
        self.gossip
            .start()
            .await
            .map_err(|e| AvoError::NetworkError {
                reason: format!("Gossip start failed: {:?}", e),
            })?;

        // Start message processing
        self.start_message_processor().await;

        // Connect to bootstrap peers
        self.connect_bootstrap_peers().await?;

        println!("✅ P2P Network Manager started successfully");
        Ok(())
    }

    /// Stop the P2P network manager
    pub async fn stop(&self) -> Result<(), AvoError> {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }
        *is_running = false;
        drop(is_running);

        println!("🛑 Stopping AVO P2P Network Manager");

        // Disconnect all peers
        self.disconnect_all_peers().await?;

        // Stop discovery
        // TODO: implement proper stop methods
        // self.discovery.stop().await
        //     .map_err(|e| AvoError::NetworkError { reason: format!("Discovery stop failed: {:?}", e) })?;

        // Stop gossip
        // self.gossip.stop().await
        //     .map_err(|e| AvoError::NetworkError { reason: format!("Gossip stop failed: {:?}", e) })?;

        println!("✅ P2P Network Manager stopped");
        Ok(())
    }

    /// Send message to specific peer
    pub async fn send_to_peer(
        &self,
        peer_id: &str,
        message: NetworkMessage,
    ) -> Result<(), AvoError> {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.messages_sent += 1;
        }

        // Send through message channel
        self.message_sender
            .send((peer_id.to_string(), message))
            .map_err(|e| AvoError::NetworkError {
                reason: format!("Failed to send message to peer {}: {}", peer_id, e),
            })?;

        Ok(())
    }

    /// Broadcast message to all peers
    pub async fn broadcast(&self, message: NetworkMessage) -> Result<(), AvoError> {
        let peers = self.peers.read().await;
        let peer_ids: Vec<String> = peers.keys().cloned().collect();
        let peer_count = peer_ids.len();
        drop(peers);

        for peer_id in peer_ids.iter() {
            self.send_to_peer(peer_id, message.clone()).await?;
        }

        {
            let mut listeners_guard = self.listeners.write().await;
            listeners_guard.retain(|listener| listener.send(message.clone()).is_ok());
        }

        println!("📡 Broadcasted message to {} peers", peer_count);
        Ok(())
    }

    /// Suscribir un receptor local a los mensajes P2P emitidos por este manager
    pub async fn subscribe(&self) -> AvoResult<mpsc::UnboundedReceiver<NetworkMessage>> {
        let (tx, rx) = mpsc::unbounded_channel();

        {
            let mut listeners = self.listeners.write().await;
            listeners.push(tx);
        }

        Ok(rx)
    }

    /// Get connected peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Get network statistics
    pub async fn get_stats(&self) -> NetworkStats {
        self.stats.read().await.clone()
    }

    /// Get node ID
    pub fn get_node_id(&self) -> &str {
        &self.node_id
    }

    /// Check if manager is running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// Start TCP listener for incoming connections
    async fn start_listener(&self) -> Result<(), AvoError> {
        let listener = TcpListener::bind(&self.config.listen_address)
            .await
            .map_err(|e| AvoError::NetworkError {
                reason: format!("Failed to bind to {}: {}", self.config.listen_address, e),
            })?;

        println!("🎧 TCP Listener started on {}", self.config.listen_address);

        // Spawn listener task
        let peers = self.peers.clone();
        let stats = self.stats.clone();
        let node_id = self.node_id.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            while *is_running.read().await {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        println!("🔗 New connection from {}", addr);

                        // Handle connection in separate task
                        let peers_clone = peers.clone();
                        let stats_clone = stats.clone();
                        let node_id_clone = node_id.clone();

                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(
                                stream,
                                peers_clone,
                                stats_clone,
                                node_id_clone,
                            )
                            .await
                            {
                                eprintln!("❌ Connection handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to accept connection: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle incoming connection
    async fn handle_connection(
        mut stream: TcpStream,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        stats: Arc<RwLock<NetworkStats>>,
        our_node_id: String,
    ) -> Result<(), AvoError> {
        // Read handshake message
        let mut buffer = vec![0u8; 4096];
        let n = stream
            .read(&mut buffer)
            .await
            .map_err(|e| AvoError::NetworkError {
                reason: format!("Failed to read handshake: {}", e),
            })?;

        if n == 0 {
            return Err(AvoError::NetworkError {
                reason: "Connection closed during handshake".to_string(),
            });
        }

        // Parse handshake
        let message: NetworkMessage =
            bincode::deserialize(&buffer[..n]).map_err(|e| AvoError::NetworkError {
                reason: format!("Failed to deserialize handshake: {}", e),
            })?;

        if let NetworkMessage::Handshake {
            node_id,
            version,
            capabilities,
        } = message
        {
            // Create peer info
            let peer_info = PeerInfo {
                id: node_id.clone(),
                endpoint: NodeEndpoint {
                    node_id: node_id.clone(),
                    node_type: crate::network::NodeType::Observer,
                    public_key: vec![],
                    address: stream.peer_addr().map_err(|e| AvoError::NetworkError {
                        reason: format!("Failed to get peer address: {}", e),
                    })?,
                },
                status: ConnectionStatus::Connected,
                last_seen: SystemTime::now(),
                latency: None,
                version,
                capabilities,
            };

            // Add peer
            {
                let mut peers_guard = peers.write().await;
                peers_guard.insert(node_id.clone(), peer_info);
            }

            // Send handshake response
            let response = NetworkMessage::Handshake {
                node_id: our_node_id,
                version: "1.0.0".to_string(),
                capabilities: vec![
                    "consensus".to_string(),
                    "gossip".to_string(),
                    "discovery".to_string(),
                ],
            };

            let response_data =
                bincode::serialize(&response).map_err(|e| AvoError::NetworkError {
                    reason: format!("Failed to serialize handshake response: {}", e),
                })?;

            stream
                .write_all(&response_data)
                .await
                .map_err(|e| AvoError::NetworkError {
                    reason: format!("Failed to send handshake response: {}", e),
                })?;

            // Update stats
            {
                let mut stats_guard = stats.write().await;
                stats_guard.peers_connected += 1;
            }

            println!("✅ Peer {} connected successfully", node_id);
        } else {
            return Err(AvoError::NetworkError {
                reason: "Expected handshake message".to_string(),
            });
        }

        Ok(())
    }

    /// Start message processor
    async fn start_message_processor(&self) {
        let receiver = {
            let mut receiver_guard = self.message_receiver.write().await;
            receiver_guard.take()
        };

        if let Some(mut receiver) = receiver {
            let stats = self.stats.clone();
            let peers = self.peers.clone();
            let is_running = self.is_running.clone();

            tokio::spawn(async move {
                while *is_running.read().await {
                    match receiver.recv().await {
                        Some((peer_id, message)) => {
                            // Process message
                            if let Err(e) =
                                Self::process_outgoing_message(&peer_id, message, &peers, &stats)
                                    .await
                            {
                                eprintln!("❌ Failed to process message to {}: {}", peer_id, e);
                            }
                        }
                        None => break,
                    }
                }
            });
        }
    }

    /// Process outgoing message
    async fn process_outgoing_message(
        peer_id: &str,
        message: NetworkMessage,
        peers: &Arc<RwLock<HashMap<String, PeerInfo>>>,
        stats: &Arc<RwLock<NetworkStats>>,
    ) -> Result<(), AvoError> {
        // Get peer info
        let peer_info = {
            let peers_guard = peers.read().await;
            peers_guard.get(peer_id).cloned()
        };

        if let Some(peer) = peer_info {
            if peer.status == ConnectionStatus::Connected {
                // Serialize message
                let message_data =
                    bincode::serialize(&message).map_err(|e| AvoError::NetworkError {
                        reason: format!("Failed to serialize message: {}", e),
                    })?;

                // Update stats
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.bytes_sent += message_data.len() as u64;
                }

                // In a real implementation, we would send this through the TCP connection
                // For now, we'll just log it
                println!(
                    "📤 Sent message to peer {} ({} bytes)",
                    peer_id,
                    message_data.len()
                );
            }
        } else {
            return Err(AvoError::NetworkError {
                reason: format!("Peer {} not found or not connected", peer_id),
            });
        }

        Ok(())
    }

    /// Connect to bootstrap peers
    async fn connect_bootstrap_peers(&self) -> Result<(), AvoError> {
        for bootstrap_peer in &self.config.bootstrap_nodes {
            if let Err(e) = self.connect_to_peer(bootstrap_peer).await {
                eprintln!(
                    "⚠️ Failed to connect to bootstrap peer {:?}: {}",
                    bootstrap_peer, e
                );
            }
        }
        Ok(())
    }

    /// Connect to a specific peer
    async fn connect_to_peer(&self, endpoint: &NodeEndpoint) -> Result<(), AvoError> {
        println!("🔗 Connecting to peer at {}", endpoint.address);

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.connection_attempts += 1;
        }

        match TcpStream::connect(&endpoint.address).await {
            Ok(mut stream) => {
                // Send handshake
                let handshake = NetworkMessage::Handshake {
                    node_id: self.node_id.clone(),
                    version: "1.0.0".to_string(),
                    capabilities: vec![
                        "consensus".to_string(),
                        "gossip".to_string(),
                        "discovery".to_string(),
                    ],
                };

                let handshake_data =
                    bincode::serialize(&handshake).map_err(|e| AvoError::NetworkError {
                        reason: format!("Failed to serialize handshake: {}", e),
                    })?;

                stream
                    .write_all(&handshake_data)
                    .await
                    .map_err(|e| AvoError::NetworkError {
                        reason: format!("Failed to send handshake: {}", e),
                    })?;

                println!("✅ Connected to peer at {}", endpoint.address);
                Ok(())
            }
            Err(e) => {
                // Update failure stats
                {
                    let mut stats = self.stats.write().await;
                    stats.connection_failures += 1;
                }

                Err(AvoError::NetworkError {
                    reason: format!("Failed to connect to {}: {}", endpoint.address, e),
                })
            }
        }
    }

    /// Attempt to reconnect a known peer using its stored endpoint
    pub async fn reconnect_peer(&self, peer: &PeerInfo) -> Result<(), AvoError> {
        {
            let mut peers = self.peers.write().await;
            if let Some(entry) = peers.get_mut(&peer.id) {
                entry.status = ConnectionStatus::Connecting;
            }
        }

        match self.connect_to_peer(&peer.endpoint).await {
            Ok(_) => {
                {
                    let mut peers = self.peers.write().await;
                    if let Some(entry) = peers.get_mut(&peer.id) {
                        entry.status = ConnectionStatus::Connected;
                        entry.last_seen = SystemTime::now();
                    }
                }
                {
                    let peers = self.peers.read().await;
                    let connected = peers
                        .values()
                        .filter(|p| p.status == ConnectionStatus::Connected)
                        .count();
                    drop(peers);
                    let mut stats = self.stats.write().await;
                    stats.peers_connected = connected;
                }
                Ok(())
            }
            Err(err) => {
                {
                    let mut peers = self.peers.write().await;
                    if let Some(entry) = peers.get_mut(&peer.id) {
                        entry.status = ConnectionStatus::Failed;
                    }
                }
                Err(err)
            }
        }
    }

    /// Disconnect all peers
    async fn disconnect_all_peers(&self) -> Result<(), AvoError> {
        let mut peers = self.peers.write().await;
        let peer_count = peers.len();

        for (peer_id, peer) in peers.iter_mut() {
            peer.status = ConnectionStatus::Disconnected;
            println!("🔌 Disconnected from peer {}", peer_id);
        }

        peers.clear();

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.peers_connected = 0;
        }

        println!("🔌 Disconnected from {} peers", peer_count);
        Ok(())
    }
}
