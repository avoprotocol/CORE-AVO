//! # P2P Manager Avanzado para AVO Protocol
//!
//! Integra DHT Kademlia, Gossip Scoring, Bootstrap Manager y otros componentes
//! para crear un sistema de networking P2P robusto y resistente a ataques.

use crate::error::*;
use crate::network::{
    bootstrap_manager::{
        BootstrapConfig, BootstrapManager, NetworkHealthStatus, PerformanceUpdate,
    },
    gossip_scoring::{GossipScorer, GossipScoringConfig, MessageProcessingResult},
    kademlia_dht::{KademliaDHT, KademliaId, PeerInfo as KademliaPeerInfo},
    multi_node_config::NetworkConfig,
};
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Configuración del P2P Manager avanzado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedP2PConfig {
    /// Configuración de red base
    pub network_config: NetworkConfig,
    /// Configuración DHT Kademlia
    pub enable_kademlia: bool,
    /// Configuración de scoring
    pub scoring_config: GossipScoringConfig,
    /// Configuración de bootstrap
    pub bootstrap_config: BootstrapConfig,
    /// Número máximo de conexiones concurrentes
    pub max_connections: usize,
    /// Intervalo de mantenimiento (segundos)
    pub maintenance_interval: u64,
    /// Timeout para conexiones (segundos)
    pub connection_timeout: u64,
    /// Bandwidth limit por peer (bytes/segundo)
    pub bandwidth_limit_per_peer: u64,
}

impl Default for AdvancedP2PConfig {
    fn default() -> Self {
        Self {
            network_config: NetworkConfig::default(),
            enable_kademlia: true,
            scoring_config: GossipScoringConfig::default(),
            bootstrap_config: BootstrapConfig::default(),
            max_connections: 100,
            maintenance_interval: 60,            // 1 minuto
            connection_timeout: 30,              // 30 segundos
            bandwidth_limit_per_peer: 1_000_000, // 1 MB/s
        }
    }
}

/// Mensaje P2P
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PMessage {
    /// ID del mensaje
    pub id: String,
    /// Tipo de mensaje
    pub message_type: P2PMessageType,
    /// Payload del mensaje
    pub payload: Vec<u8>,
    /// Timestamp
    pub timestamp: SystemTime,
    /// TTL (time-to-live)
    pub ttl: u32,
    /// ID del sender
    pub sender: KademliaId,
    /// Tópico (para gossip)
    pub topic: Option<String>,
}

/// Tipos de mensajes P2P
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessageType {
    /// Mensaje de gossip general
    Gossip,
    /// Query DHT
    DHTQuery,
    /// Respuesta DHT
    DHTResponse,
    /// Anuncio de bootstrap node
    BootstrapAnnouncement,
    /// Heartbeat/ping
    Heartbeat,
    /// Transacción
    Transaction,
    /// Bloque
    Block,
    /// Consenso intra-shard
    IntraShardConsensus,
    /// Consenso inter-shard
    InterShardConsensus,
    /// Voto agregado de consenso
    AggregatedVote,
    /// Resumen de finalidad
    FinalitySummary,
}

/// Estado de una conexión P2P
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Información del peer
    pub peer_info: KademliaPeerInfo,
    /// Estado de la conexión
    pub status: ConnectionStatus,
    /// Tiempo de establecimiento
    pub connected_at: SystemTime,
    /// Último mensaje recibido
    pub last_message: Option<SystemTime>,
    /// Bandwidth utilizado
    pub bandwidth_used: u64,
    /// Mensajes enviados
    pub messages_sent: u64,
    /// Mensajes recibidos
    pub messages_received: u64,
}

/// Estado de conexión
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Connecting,
    Connected,
    Authenticated,
    Disconnecting,
    Disconnected,
    Banned,
}

/// P2P Manager avanzado
#[derive(Debug)]
pub struct AdvancedP2PManager {
    /// Configuración
    config: AdvancedP2PConfig,
    /// ID local del nodo
    local_id: KademliaId,
    /// DHT Kademlia
    dht: Arc<Mutex<KademliaDHT>>,
    /// Sistema de scoring
    scorer: Arc<Mutex<GossipScorer>>,
    /// Manager de bootstrap
    bootstrap_manager: Arc<Mutex<BootstrapManager>>,
    /// Conexiones activas
    connections: Arc<RwLock<HashMap<KademliaId, ConnectionState>>>,
    /// Canal para mensajes entrantes
    message_tx: mpsc::UnboundedSender<P2PMessage>,
    message_rx: Arc<Mutex<mpsc::UnboundedReceiver<P2PMessage>>>,
    /// Métricas del sistema
    metrics: Arc<RwLock<P2PManagerMetrics>>,
    /// Estado del manager
    is_running: Arc<RwLock<bool>>,
}

/// Métricas del P2P Manager
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct P2PManagerMetrics {
    pub total_connections: usize,
    pub active_connections: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bootstrap_nodes_count: usize,
    pub dht_peers_count: usize,
    pub average_latency: f64,
    pub network_health: NetworkHealthStatus,
    pub uptime: Duration,
}

impl AdvancedP2PManager {
    /// Crear nuevo P2P Manager
    pub fn new(config: AdvancedP2PConfig, local_id: KademliaId) -> Self {
        info!(
            "🌐 Inicializando Advanced P2P Manager con ID: {}",
            local_id.to_hex()
        );

        let dht = if config.enable_kademlia {
            Arc::new(Mutex::new(KademliaDHT::new(local_id)))
        } else {
            Arc::new(Mutex::new(KademliaDHT::new(local_id))) // Siempre habilitamos por ahora
        };

        let scorer = Arc::new(Mutex::new(GossipScorer::new(config.scoring_config.clone())));
        let bootstrap_manager = Arc::new(Mutex::new(BootstrapManager::new(
            config.bootstrap_config.clone(),
            config.scoring_config.clone(),
        )));

        let (message_tx, message_rx) = mpsc::unbounded_channel();

        Self {
            config,
            local_id,
            dht,
            scorer,
            bootstrap_manager,
            connections: Arc::new(RwLock::new(HashMap::new())),
            message_tx,
            message_rx: Arc::new(Mutex::new(message_rx)),
            metrics: Arc::new(RwLock::new(P2PManagerMetrics::default())),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Iniciar el P2P Manager
    pub async fn start(&self) -> AvoResult<()> {
        info!("🚀 Starting Advanced P2P Manager");

        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(AvoError::network("P2P Manager already running"));
        }
        *is_running = true;
        drop(is_running);

        // Inicializar bootstrap nodes
        self.initialize_bootstrap_nodes().await?;

        // Iniciar loops de mantenimiento
        self.start_maintenance_loops().await;

        // Iniciar descubrimiento de peers
        self.start_peer_discovery().await?;

        info!("✅ Advanced P2P Manager started successfully");
        Ok(())
    }

    /// Detener el P2P Manager
    pub async fn stop(&self) -> AvoResult<()> {
        info!("🛑 Stopping Advanced P2P Manager");

        let mut is_running = self.is_running.write().await;
        *is_running = false;

        // Desconectar todos los peers
        let mut connections = self.connections.write().await;
        for (peer_id, connection) in connections.iter_mut() {
            if connection.status == ConnectionStatus::Connected
                || connection.status == ConnectionStatus::Authenticated
            {
                connection.status = ConnectionStatus::Disconnected;
                debug!("👋 Disconnected from peer: {}", peer_id.to_hex());
            }
        }
        connections.clear();

        info!("✅ Advanced P2P Manager stopped");
        Ok(())
    }

    /// Inicializar bootstrap nodes
    async fn initialize_bootstrap_nodes(&self) -> AvoResult<()> {
        info!("🔗 Initializing bootstrap nodes...");

        // En implementación real, esto cargaría bootstrap nodes desde configuración o registry
        let bootstrap_addresses = vec![
            ("bootstrap1.avo.network", 30303, 15_000_000),
            ("bootstrap2.avo.network", 30303, 20_000_000),
            ("bootstrap3.avo.network", 30303, 18_000_000),
        ];

        let mut bootstrap_manager = self.bootstrap_manager.lock().await;

        for (addr, port, stake) in bootstrap_addresses {
            // Simular resolución de dirección
            if let Ok(socket_addr) = format!("{}:{}", addr, port).parse::<SocketAddr>() {
                let peer_id = KademliaId::from_str(&format!("{}:{}", addr, port));
                let peer_info = KademliaPeerInfo::new(peer_id, socket_addr, stake);

                if let Err(e) = bootstrap_manager.register_candidate(peer_info, stake) {
                    warn!("Failed to register bootstrap candidate {}: {}", addr, e);
                } else {
                    info!("✅ Registered bootstrap candidate: {}", addr);
                }
            }
        }

        Ok(())
    }

    /// Iniciar loops de mantenimiento
    async fn start_maintenance_loops(&self) {
        let connections = Arc::clone(&self.connections);
        let metrics = Arc::clone(&self.metrics);
        let dht = Arc::clone(&self.dht);
        let scorer = Arc::clone(&self.scorer);
        let bootstrap_manager = Arc::clone(&self.bootstrap_manager);
        let is_running = Arc::clone(&self.is_running);
        let maintenance_interval = Duration::from_secs(self.config.maintenance_interval);

        tokio::spawn(async move {
            while *is_running.read().await {
                // Limpiar conexiones inactivas
                Self::cleanup_inactive_connections(&connections).await;

                // Actualizar métricas
                Self::update_metrics(&connections, &metrics, &dht, &bootstrap_manager).await;

                // Limpiar peers inactivos en DHT y scorer
                {
                    let mut dht_guard = dht.lock().await;
                    dht_guard.cleanup_inactive_peers();
                }

                {
                    let mut scorer_guard = scorer.lock().await;
                    scorer_guard.cleanup_inactive_peers();
                }

                // Verificar stakes de bootstrap nodes
                {
                    let mut bootstrap_guard = bootstrap_manager.lock().await;
                    if let Err(e) = bootstrap_guard.verify_stakes().await {
                        warn!("Bootstrap stake verification error: {}", e);
                    }
                }

                tokio::time::sleep(maintenance_interval).await;
            }
        });
    }

    /// Iniciar descubrimiento de peers
    async fn start_peer_discovery(&self) -> AvoResult<()> {
        info!("🔍 Starting peer discovery...");

        let dht = Arc::clone(&self.dht);
        let bootstrap_manager = Arc::clone(&self.bootstrap_manager);
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            while *is_running.read().await {
                // Obtener bootstrap nodes para conectar
                let bootstrap_nodes = {
                    let bootstrap_guard = bootstrap_manager.lock().await;
                    bootstrap_guard.get_top_bootstrap_nodes(5)
                };

                // Conectar a bootstrap nodes
                for bootstrap_peer in bootstrap_nodes {
                    // Simular conexión
                    debug!(
                        "🔗 Connecting to bootstrap node: {}",
                        bootstrap_peer.id.to_hex()
                    );

                    // Agregar a DHT
                    {
                        let mut dht_guard = dht.lock().await;
                        if let Err(e) = dht_guard.add_peer(bootstrap_peer) {
                            debug!("Failed to add bootstrap peer to DHT: {}", e);
                        }
                    }
                }

                // Realizar búsquedas DHT periódicas
                {
                    let mut dht_guard = dht.lock().await;
                    let random_target = KademliaId::random();

                    match dht_guard.find_node(random_target).await {
                        Ok(peers) => {
                            debug!("🔍 DHT discovery found {} peers", peers.len());
                        }
                        Err(e) => {
                            debug!("DHT discovery error: {}", e);
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(30)).await; // Cada 30 segundos
            }
        });

        Ok(())
    }

    /// Enviar mensaje a un peer específico
    pub async fn send_message(&self, target: KademliaId, message: P2PMessage) -> AvoResult<()> {
        // Verificar si el peer está conectado
        let connections = self.connections.read().await;
        if let Some(connection) = connections.get(&target) {
            if connection.status != ConnectionStatus::Connected
                && connection.status != ConnectionStatus::Authenticated
            {
                return Err(AvoError::network("Peer not connected"));
            }
        } else {
            return Err(AvoError::network("Peer not found"));
        }
        drop(connections);

        // Verificar scoring del peer
        let scorer = self.scorer.lock().await;
        if !scorer.is_peer_allowed(&target) {
            return Err(AvoError::network("Peer not allowed (low score)"));
        }
        drop(scorer);

        // Simular envío de mensaje
        debug!(
            "📤 Sending message to {}: {:?}",
            target.to_hex(),
            message.message_type
        );

        // Actualizar métricas
        let mut connections = self.connections.write().await;
        if let Some(connection) = connections.get_mut(&target) {
            connection.messages_sent += 1;
            connection.bandwidth_used += message.payload.len() as u64;
        }

        // Actualizar métricas globales
        let mut metrics = self.metrics.write().await;
        metrics.messages_sent += 1;
        metrics.bytes_sent += message.payload.len() as u64;

        Ok(())
    }

    /// Broadcast mensaje a todos los peers conectados
    pub async fn broadcast_message(&self, message: P2PMessage) -> AvoResult<Vec<KademliaId>> {
        let connections = self.connections.read().await;
        let connected_peers: Vec<KademliaId> = connections
            .iter()
            .filter(|(_, conn)| {
                conn.status == ConnectionStatus::Connected
                    || conn.status == ConnectionStatus::Authenticated
            })
            .map(|(id, _)| *id)
            .collect();
        drop(connections);

        let mut successful_sends = Vec::new();

        for peer_id in connected_peers {
            match self.send_message(peer_id, message.clone()).await {
                Ok(_) => successful_sends.push(peer_id),
                Err(e) => debug!("Failed to send to {}: {}", peer_id.to_hex(), e),
            }
        }

        info!(
            "📡 Broadcast message sent to {}/{} peers",
            successful_sends.len(),
            successful_sends.len()
        );

        Ok(successful_sends)
    }

    /// Procesar mensaje recibido
    pub async fn process_received_message(
        &self,
        from: KademliaId,
        message: P2PMessage,
    ) -> AvoResult<()> {
        // Actualizar scoring
        let message_size = message.payload.len();
        let is_valid = self.validate_message(&message).await;
        let topic = message.topic.as_deref().unwrap_or("unknown");

        let processing_result = {
            let mut scorer = self.scorer.lock().await;
            scorer.process_message(from, message_size, is_valid, topic)
        };

        // Manejar resultado del procesamiento
        match processing_result {
            MessageProcessingResult::Valid => {
                debug!("✅ Valid message from {}", from.to_hex());
                self.handle_valid_message(from, message).await?;
            }
            MessageProcessingResult::Invalid => {
                warn!("❌ Invalid message from {}", from.to_hex());
            }
            MessageProcessingResult::Spam => {
                warn!("🚫 Spam detected from {}", from.to_hex());
                // Podríamos considerar desconectar el peer
            }
            MessageProcessingResult::RateLimited => {
                warn!("⏰ Rate limited message from {}", from.to_hex());
            }
        }

        // Actualizar métricas de conexión
        let mut connections = self.connections.write().await;
        if let Some(connection) = connections.get_mut(&from) {
            connection.messages_received += 1;
            connection.last_message = Some(SystemTime::now());
        }

        // Actualizar métricas globales
        let mut metrics = self.metrics.write().await;
        metrics.messages_received += 1;
        metrics.bytes_received += message_size as u64;

        Ok(())
    }

    /// Validar mensaje recibido
    async fn validate_message(&self, message: &P2PMessage) -> bool {
        // Verificaciones básicas
        if message.payload.len() > 10_000_000 {
            // 10MB max
            return false;
        }

        if message.ttl == 0 {
            return false;
        }

        // Verificar timestamp (no más de 5 minutos en el futuro o pasado)
        if let Ok(elapsed) = message.timestamp.elapsed() {
            if elapsed > Duration::from_secs(300) {
                return false;
            }
        } else {
            // Mensaje del futuro
            if let Ok(duration_since_epoch) =
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            {
                if let Ok(msg_duration) = message.timestamp.duration_since(SystemTime::UNIX_EPOCH) {
                    if msg_duration > duration_since_epoch + Duration::from_secs(300) {
                        return false;
                    }
                }
            }
        }

        // Validaciones específicas por tipo de mensaje
        match message.message_type {
            P2PMessageType::DHTQuery | P2PMessageType::DHTResponse => {
                // Validar formato DHT
                true // Simplificado
            }
            P2PMessageType::Transaction => {
                // Validar formato de transacción
                true // Simplificado
            }
            P2PMessageType::Block => {
                // Validar formato de bloque
                true // Simplificado
            }
            _ => true,
        }
    }

    /// Manejar mensaje válido
    async fn handle_valid_message(&self, from: KademliaId, message: P2PMessage) -> AvoResult<()> {
        match message.message_type {
            P2PMessageType::DHTQuery => {
                // Procesar con DHT
                let dht = self.dht.lock().await;
                // En implementación real, procesaría la query DHT
                debug!("Processing DHT query from {}", from.to_hex());
            }
            P2PMessageType::BootstrapAnnouncement => {
                // Procesar anuncio de bootstrap
                debug!("Received bootstrap announcement from {}", from.to_hex());
            }
            P2PMessageType::Heartbeat => {
                // Actualizar último heartbeat
                debug!("Heartbeat from {}", from.to_hex());
            }
            _ => {
                // Reenviar a aplicación
                if let Err(_) = self.message_tx.send(message) {
                    warn!("Failed to forward message to application");
                }
            }
        }

        Ok(())
    }

    /// Limpiar conexiones inactivas
    async fn cleanup_inactive_connections(
        connections: &Arc<RwLock<HashMap<KademliaId, ConnectionState>>>,
    ) {
        let mut connections_guard = connections.write().await;
        let now = SystemTime::now();
        let timeout = Duration::from_secs(300); // 5 minutos

        connections_guard.retain(|peer_id, connection| {
            let is_active = if let Some(last_message) = connection.last_message {
                now.duration_since(last_message).unwrap_or(Duration::MAX) < timeout
            } else {
                now.duration_since(connection.connected_at)
                    .unwrap_or(Duration::MAX)
                    < timeout
            };

            if !is_active {
                debug!("🧹 Removing inactive connection: {}", peer_id.to_hex());
            }

            is_active
        });
    }

    /// Actualizar métricas
    async fn update_metrics(
        connections: &Arc<RwLock<HashMap<KademliaId, ConnectionState>>>,
        metrics: &Arc<RwLock<P2PManagerMetrics>>,
        dht: &Arc<Mutex<KademliaDHT>>,
        bootstrap_manager: &Arc<Mutex<BootstrapManager>>,
    ) {
        let connections_guard = connections.read().await;
        let dht_guard = dht.lock().await;
        let bootstrap_guard = bootstrap_manager.lock().await;
        let mut metrics_guard = metrics.write().await;

        metrics_guard.total_connections = connections_guard.len();
        metrics_guard.active_connections = connections_guard
            .values()
            .filter(|conn| {
                conn.status == ConnectionStatus::Connected
                    || conn.status == ConnectionStatus::Authenticated
            })
            .count();

        metrics_guard.bootstrap_nodes_count = bootstrap_guard.get_active_bootstrap_nodes().len();
        metrics_guard.dht_peers_count = dht_guard.get_metrics().total_peers;

        let bootstrap_metrics = bootstrap_guard.get_metrics();
        metrics_guard.network_health = match bootstrap_metrics.network_reliability {
            r if r >= 0.8 => NetworkHealthStatus::Excellent,
            r if r >= 0.6 => NetworkHealthStatus::Good,
            r if r >= 0.4 => NetworkHealthStatus::Warning,
            _ => NetworkHealthStatus::Critical,
        };
    }

    /// Obtener métricas actuales
    pub async fn get_metrics(&self) -> P2PManagerMetrics {
        self.metrics.read().await.clone()
    }

    /// Obtener estado de conexiones
    pub async fn get_connection_states(&self) -> HashMap<KademliaId, ConnectionState> {
        self.connections.read().await.clone()
    }

    /// Obtener canal para recibir mensajes
    pub async fn get_message_receiver(&self) -> Arc<Mutex<mpsc::UnboundedReceiver<P2PMessage>>> {
        Arc::clone(&self.message_rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_p2p_manager_creation() {
        let config = AdvancedP2PConfig::default();
        let local_id = KademliaId::from_str("test_node");
        let manager = AdvancedP2PManager::new(config, local_id);

        assert_eq!(manager.local_id, local_id);
    }

    #[tokio::test]
    async fn test_message_validation() {
        let config = AdvancedP2PConfig::default();
        let local_id = KademliaId::from_str("test_node");
        let manager = AdvancedP2PManager::new(config, local_id);

        let valid_message = P2PMessage {
            id: "test_msg".to_string(),
            message_type: P2PMessageType::Heartbeat,
            payload: b"test payload".to_vec(),
            timestamp: SystemTime::now(),
            ttl: 5,
            sender: KademliaId::from_str("sender"),
            topic: None,
        };

        assert!(manager.validate_message(&valid_message).await);

        // Mensaje con payload demasiado grande
        let invalid_message = P2PMessage {
            payload: vec![0u8; 20_000_000], // 20MB
            ..valid_message
        };

        assert!(!manager.validate_message(&invalid_message).await);
    }
}
