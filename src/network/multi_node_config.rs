use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Multi-node network configuration for production deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Node identification and networking
    pub node_id: String,
    pub node_type: NodeType,
    pub listen_address: SocketAddr,
    pub external_address: Option<SocketAddr>,

    /// Network topology
    pub bootstrap_nodes: Vec<NodeEndpoint>,
    pub max_peers: usize,
    pub min_peers: usize,

    /// Shard configuration
    pub shard_assignment: Vec<u32>,
    pub cross_shard_enabled: bool,

    /// Consensus parameters
    pub consensus_config: ConsensusConfig,

    /// Performance tuning
    pub performance_config: PerformanceConfig,

    /// Security settings
    pub security_config: SecurityConfig,

    /// Monitoring and logging
    pub monitoring_config: MonitoringConfig,
}

/// Types of nodes in the network
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeType {
    /// Primary consensus validator
    Validator,
    /// Backup validator (standby)
    BackupValidator,
    /// Observer node (read-only)
    Observer,
    /// Archive node (full history)
    Archive,
    /// Seed node (bootstrapping)
    Seed,
}

/// Network endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEndpoint {
    pub node_id: String,
    pub address: SocketAddr,
    pub node_type: NodeType,
    pub public_key: Vec<u8>,
}

/// Consensus-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Flow consensus parameters
    pub block_time_ms: u64,
    pub finality_threshold: u32,
    pub byzantine_tolerance: f64,

    /// Batch processing settings
    pub max_batch_size: usize,
    pub batch_timeout_ms: u64,
    pub parallel_validation: bool,

    /// Cross-shard coordination
    pub cross_shard_timeout_ms: u64,
    pub shard_sync_interval_ms: u64,
}

/// Performance optimization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Worker thread configuration
    pub consensus_threads: usize,
    pub network_threads: usize,
    pub validation_threads: usize,

    /// Memory management
    pub memory_pool_size: usize,
    pub cache_size_mb: usize,
    pub gc_interval_ms: u64,

    /// Network optimization
    pub tcp_nodelay: bool,
    pub tcp_keepalive: bool,
    pub buffer_size_kb: usize,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Cryptographic settings
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub key_rotation_interval_hours: u64,

    /// Network security
    pub tls_enabled: bool,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,

    /// Access control
    pub whitelist_enabled: bool,
    pub allowed_peers: Vec<String>,
    pub rate_limit_rps: u32,
}

/// Monitoring and observability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Metrics collection
    pub metrics_enabled: bool,
    pub metrics_port: u16,
    pub metrics_path: String,

    /// Logging configuration
    pub log_level: String,
    pub log_file: Option<PathBuf>,
    pub log_rotation_mb: u64,

    /// Health checks
    pub health_check_port: u16,
    pub health_check_interval_ms: u64,

    /// Tracing and debugging
    pub tracing_enabled: bool,
    pub debug_endpoints: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            node_id: "node-0".to_string(),
            node_type: NodeType::Validator,
            listen_address: "127.0.0.1:8000".parse().unwrap(),
            external_address: None,
            bootstrap_nodes: Vec::new(),
            max_peers: 32,
            min_peers: 4,
            shard_assignment: vec![0],
            cross_shard_enabled: true,
            consensus_config: ConsensusConfig::default(),
            performance_config: PerformanceConfig::default(),
            security_config: SecurityConfig::default(),
            monitoring_config: MonitoringConfig::default(),
        }
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_ms: 1000,
            finality_threshold: 67, // 67% for Byzantine fault tolerance
            byzantine_tolerance: 0.33,
            max_batch_size: 50000, // Ultra-optimized from Phase 4A
            batch_timeout_ms: 100,
            parallel_validation: true,
            cross_shard_timeout_ms: 5000,
            shard_sync_interval_ms: 1000,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            consensus_threads: num_cpus::get() * 2,
            network_threads: num_cpus::get(),
            validation_threads: num_cpus::get() * 4, // Ultra-optimized
            memory_pool_size: 500000,                // From Phase 4A optimization
            cache_size_mb: 1024,
            gc_interval_ms: 60000,
            tcp_nodelay: true,
            tcp_keepalive: true,
            buffer_size_kb: 64,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            private_key_path: PathBuf::from("keys/private.key"),
            public_key_path: PathBuf::from("keys/public.key"),
            key_rotation_interval_hours: 24,
            tls_enabled: true,
            tls_cert_path: Some(PathBuf::from("certs/server.crt")),
            tls_key_path: Some(PathBuf::from("certs/server.key")),
            whitelist_enabled: false,
            allowed_peers: Vec::new(),
            rate_limit_rps: 10000,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            metrics_port: 9090,
            metrics_path: "/metrics".to_string(),
            log_level: "info".to_string(),
            log_file: Some(PathBuf::from("logs/avo-node.log")),
            log_rotation_mb: 100,
            health_check_port: 8080,
            health_check_interval_ms: 5000,
            tracing_enabled: true,
            debug_endpoints: false,
        }
    }
}

impl NetworkConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: NetworkConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Create validator node configuration
    pub fn validator_config(node_id: String, listen_port: u16) -> Self {
        let mut config = Self::default();
        config.node_id = node_id;
        config.node_type = NodeType::Validator;
        config.listen_address = format!("0.0.0.0:{}", listen_port).parse().unwrap();
        config
    }

    /// Create production cluster configuration
    pub fn production_cluster(cluster_size: usize) -> Vec<Self> {
        let mut configs = Vec::new();

        for i in 0..cluster_size {
            let mut config = Self::validator_config(format!("validator-{}", i), 8000 + i as u16);

            // Set bootstrap nodes (first node is bootstrap)
            if i > 0 {
                config.bootstrap_nodes.push(NodeEndpoint {
                    node_id: "validator-0".to_string(),
                    address: "127.0.0.1:8000".parse().unwrap(),
                    node_type: NodeType::Validator,
                    public_key: vec![], // Will be filled with actual keys
                });
            }

            // Distribute shards
            config.shard_assignment = vec![i as u32 % 2]; // Distribute across 2 shards

            configs.push(config);
        }

        configs
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.node_id.is_empty() {
            return Err("Node ID cannot be empty".to_string());
        }

        if self.max_peers < self.min_peers {
            return Err("Max peers must be >= min peers".to_string());
        }

        if self.shard_assignment.is_empty() {
            return Err("Must be assigned to at least one shard".to_string());
        }

        if self.consensus_config.finality_threshold > 100 {
            return Err("Finality threshold cannot exceed 100%".to_string());
        }

        Ok(())
    }
}

/// Network topology manager
pub struct NetworkTopology {
    pub nodes: HashMap<String, NodeEndpoint>,
    pub shards: HashMap<u32, Vec<String>>,
}

impl NetworkTopology {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            shards: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, endpoint: NodeEndpoint) {
        let node_id = endpoint.node_id.clone();
        self.nodes.insert(node_id, endpoint);
    }

    pub fn assign_to_shard(&mut self, node_id: String, shard_id: u32) {
        self.shards
            .entry(shard_id)
            .or_insert_with(Vec::new)
            .push(node_id);
    }

    pub fn get_shard_nodes(&self, shard_id: u32) -> Vec<&NodeEndpoint> {
        self.shards
            .get(&shard_id)
            .map(|node_ids| {
                node_ids
                    .iter()
                    .filter_map(|id| self.nodes.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_validators(&self) -> Vec<&NodeEndpoint> {
        self.nodes
            .values()
            .filter(|node| {
                matches!(
                    node.node_type,
                    NodeType::Validator | NodeType::BackupValidator
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NetworkConfig::default();
        assert_eq!(config.node_type, NodeType::Validator);
        assert_eq!(config.max_peers, 32);
        assert!(config.cross_shard_enabled);
    }

    #[test]
    fn test_production_cluster() {
        let configs = NetworkConfig::production_cluster(4);
        assert_eq!(configs.len(), 4);

        // Check that non-bootstrap nodes have bootstrap node configured
        for (i, config) in configs.iter().enumerate() {
            if i > 0 {
                assert!(!config.bootstrap_nodes.is_empty());
            }
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = NetworkConfig::default();
        assert!(config.validate().is_ok());

        config.node_id = "".to_string();
        assert!(config.validate().is_err());

        config.node_id = "test".to_string();
        config.max_peers = 2;
        config.min_peers = 5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_network_topology() {
        let mut topology = NetworkTopology::new();

        let endpoint = NodeEndpoint {
            node_id: "test-node".to_string(),
            address: "127.0.0.1:8000".parse().unwrap(),
            node_type: NodeType::Validator,
            public_key: vec![],
        };

        topology.add_node(endpoint);
        topology.assign_to_shard("test-node".to_string(), 0);

        let shard_nodes = topology.get_shard_nodes(0);
        assert_eq!(shard_nodes.len(), 1);
        assert_eq!(shard_nodes[0].node_id, "test-node");
    }
}
