pub mod advanced_discovery;
pub mod advanced_p2p_manager;
pub mod bootstrap_manager;
pub mod discovery;
pub mod gossip;
pub mod gossip_scoring;
pub mod kademlia_dht;
pub mod key_management;
pub mod libp2p_network;
pub mod message_routing;
pub mod multi_node_config;
pub mod network_metrics;
pub mod optimized_gossip;
pub mod p2p;
pub mod tcp_pool; // TCP connection pool for real network communication

#[cfg(test)]
pub mod p2p_integration_tests;

// Re-export key types for convenience
pub use multi_node_config::{
    ConsensusConfig, MonitoringConfig, NetworkConfig, NetworkTopology, NodeEndpoint, NodeType,
    PerformanceConfig, SecurityConfig,
};

// Re-exports
pub use advanced_discovery::*;
pub use discovery::PeerDiscovery;
pub use gossip::GossipProtocol;
pub use message_routing::MessageRouter;
pub use optimized_gossip::*;
pub use tcp_pool::{TcpConnectionPool, ConnectionStats, PeerId};
pub use p2p::P2PManager;

// Advanced P2P components
pub use advanced_p2p_manager::{
    AdvancedP2PConfig, AdvancedP2PManager, ConnectionState, ConnectionStatus, P2PManagerMetrics,
    P2PMessage, P2PMessageType,
};
pub use bootstrap_manager::{
    BootstrapConfig, BootstrapManager, BootstrapNode, BootstrapStatusReport, NetworkHealthStatus,
    StakeInfo,
};
pub use gossip_scoring::{
    GlobalScoringMetrics, GossipScorer, GossipScoringConfig, MessageProcessingResult,
    PeerGossipScore,
};
pub use kademlia_dht::{
    DHTHealthReport, DHTMetrics, KademliaDHT, KademliaId, PeerInfo as KademliaPeerInfo,
};
pub use key_management::{KeyManager, KeyManagerStats, NodeKeyPair};
pub use libp2p_network::{
    spawn_libp2p_network, Libp2pNetworkConfig, Libp2pNetworkController, NetworkCommand,
    NetworkEvent, PeerMetadata,
};
pub use network_metrics::{
    AggregatedNetworkMetrics, CrossShardMetrics, MEVProtectionMetrics, NetworkMetricsCollector,
    NetworkMetricsConfig, NetworkMetricsReport,
};
