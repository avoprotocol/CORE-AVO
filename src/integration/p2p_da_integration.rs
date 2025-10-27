//! # Integración P2P + Data Availability
//!
//! Integra el Advanced P2P Manager con el Data Availability Layer para crear
//! un sistema completo de propagación y verificación de datos distribuidos.

use crate::da::{
    DASValidator, DASValidatorConfig, DataAvailabilityBlock, DataAvailabilityConfig,
    DataAvailabilityLayer, DataChunk, SamplingPriority, SamplingRequest,
};
use crate::error::*;
use crate::network::{
    AdvancedP2PConfig, AdvancedP2PManager, ConnectionStatus, KademliaId, P2PMessage, P2PMessageType,
};
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Configuración del sistema integrado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedNetworkConfig {
    /// Configuración P2P
    pub p2p_config: AdvancedP2PConfig,
    /// Configuración DA Layer
    pub da_config: DataAvailabilityConfig,
    /// Configuración DAS Validator
    pub das_config: DASValidatorConfig,
    /// Estrategia de propagación de chunks
    pub chunk_propagation_strategy: ChunkPropagationStrategy,
    /// Número máximo de peers para propagación por chunk
    pub max_peers_per_chunk: usize,
    /// Timeout para requests de chunks (segundos)
    pub chunk_request_timeout: u64,
    /// Intervalo de verificación de disponibilidad (segundos)
    pub availability_check_interval: u64,
}

/// Estrategia de propagación de chunks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkPropagationStrategy {
    /// Broadcast a todos los peers
    Broadcast,
    /// Enviar solo a peers responsables del shard
    ShardBased,
    /// Distribución aleatoria
    Random,
    /// Basado en scoring de peers
    ScoreBased,
}

impl Default for IntegratedNetworkConfig {
    fn default() -> Self {
        Self {
            p2p_config: AdvancedP2PConfig::default(),
            da_config: DataAvailabilityConfig::default(),
            das_config: DASValidatorConfig::default(),
            chunk_propagation_strategy: ChunkPropagationStrategy::ScoreBased,
            max_peers_per_chunk: 10,
            chunk_request_timeout: 30,
            availability_check_interval: 60,
        }
    }
}

/// Mensaje específico para chunks de datos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMessage {
    /// Tipo de mensaje de chunk
    pub chunk_msg_type: ChunkMessageType,
    /// ID del bloque
    pub block_id: String,
    /// Índice del chunk
    pub chunk_index: usize,
    /// Datos del chunk (si aplica)
    pub chunk_data: Option<DataChunk>,
    /// Peers que tienen este chunk
    pub available_peers: Vec<KademliaId>,
}

/// Tipos de mensajes de chunks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkMessageType {
    /// Anuncio de chunk disponible
    ChunkAnnouncement,
    /// Request de chunk específico
    ChunkRequest,
    /// Respuesta con datos de chunk
    ChunkResponse,
    /// Notificación de chunk no disponible
    ChunkUnavailable,
}

/// Evento de disponibilidad de datos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAvailabilityEvent {
    /// Tipo de evento
    pub event_type: DAEventType,
    /// ID del bloque
    pub block_id: String,
    /// Detalles adicionales
    pub details: HashMap<String, String>,
    /// Timestamp del evento
    pub timestamp: SystemTime,
}

/// Tipos de eventos DA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DAEventType {
    /// Nuevo bloque disponible
    BlockAvailable,
    /// Bloque no disponible
    BlockUnavailable,
    /// Chunk verificado
    ChunkVerified,
    /// Chunk fallido
    ChunkFailed,
    /// Sampling completado
    SamplingCompleted,
}

/// Sistema de red integrado
#[derive(Debug)]
pub struct IntegratedNetworkSystem {
    /// Configuración
    config: IntegratedNetworkConfig,
    /// ID del nodo local
    local_id: KademliaId,
    /// P2P Manager
    p2p_manager: Arc<AdvancedP2PManager>,
    /// Data Availability Layer
    da_layer: Arc<DataAvailabilityLayer>,
    /// DAS Validator
    das_validator: Arc<DASValidator>,
    /// Chunks solicitados pendientes
    pending_chunk_requests: Arc<RwLock<HashMap<String, ChunkRequestInfo>>>,
    /// Cache de disponibilidad de chunks por bloque
    chunk_availability: Arc<RwLock<HashMap<String, HashMap<usize, Vec<KademliaId>>>>>,
    /// Canal de eventos DA
    da_event_tx: mpsc::UnboundedSender<DataAvailabilityEvent>,
    da_event_rx: Arc<Mutex<mpsc::UnboundedReceiver<DataAvailabilityEvent>>>,
    /// Estado del sistema
    is_running: Arc<RwLock<bool>>,
}

/// Información de request de chunk
#[derive(Debug, Clone)]
pub struct ChunkRequestInfo {
    /// ID del request
    pub request_id: String,
    /// ID del bloque
    pub block_id: String,
    /// Índice del chunk
    pub chunk_index: usize,
    /// Peers consultados
    pub queried_peers: HashSet<KademliaId>,
    /// Timestamp del request
    pub requested_at: SystemTime,
    /// Número de reintentos
    pub retry_count: usize,
}

impl IntegratedNetworkSystem {
    /// Crear nuevo sistema integrado
    pub async fn new(config: IntegratedNetworkConfig, local_id: KademliaId) -> AvoResult<Self> {
        info!(
            "🌐 Initializing Integrated Network System with ID: {}",
            local_id.to_hex()
        );

        // Crear componentes
        let p2p_manager = Arc::new(AdvancedP2PManager::new(config.p2p_config.clone(), local_id));
        let da_layer = Arc::new(DataAvailabilityLayer::new(config.da_config.clone()));
        let das_validator = Arc::new(DASValidator::new(
            config.das_config.clone(),
            Arc::clone(&da_layer),
        ));

        let (da_event_tx, da_event_rx) = mpsc::unbounded_channel();

        let system = Self {
            config,
            local_id,
            p2p_manager,
            da_layer,
            das_validator,
            pending_chunk_requests: Arc::new(RwLock::new(HashMap::new())),
            chunk_availability: Arc::new(RwLock::new(HashMap::new())),
            da_event_tx,
            da_event_rx: Arc::new(Mutex::new(da_event_rx)),
            is_running: Arc::new(RwLock::new(false)),
        };

        Ok(system)
    }

    /// Iniciar el sistema integrado
    pub async fn start(&self) -> AvoResult<()> {
        info!("🚀 Starting Integrated Network System");

        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(AvoError::network("System already running"));
        }
        *is_running = true;
        drop(is_running);

        // Iniciar componentes
        self.p2p_manager.start().await?;
        self.das_validator.start().await?;

        // Iniciar handlers de mensajes
        self.start_message_handlers().await;

        // Iniciar verificación periódica de disponibilidad
        self.start_availability_checker().await;

        // Iniciar limpieza de requests
        self.start_request_cleanup().await;

        info!("✅ Integrated Network System started successfully");
        Ok(())
    }

    /// Detener el sistema
    pub async fn stop(&self) -> AvoResult<()> {
        info!("🛑 Stopping Integrated Network System");

        let mut is_running = self.is_running.write().await;
        *is_running = false;

        // Detener componentes
        self.p2p_manager.stop().await?;
        self.das_validator.stop().await?;

        info!("✅ Integrated Network System stopped");
        Ok(())
    }

    /// Iniciar handlers de mensajes
    async fn start_message_handlers(&self) {
        let p2p_manager = Arc::clone(&self.p2p_manager);
        let da_layer = Arc::clone(&self.da_layer);
        let pending_requests = Arc::clone(&self.pending_chunk_requests);
        let chunk_availability = Arc::clone(&self.chunk_availability);
        let da_event_tx = self.da_event_tx.clone();
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            let message_rx = p2p_manager.get_message_receiver().await;
            let mut rx = message_rx.lock().await;

            while *is_running.read().await {
                match rx.recv().await {
                    Some(message) => {
                        if let Err(e) = Self::handle_p2p_message(
                            &message,
                            &da_layer,
                            &pending_requests,
                            &chunk_availability,
                            &da_event_tx,
                        )
                        .await
                        {
                            debug!("Failed to handle P2P message: {}", e);
                        }
                    }
                    None => break,
                }
            }
        });
    }

    /// Manejar mensaje P2P
    async fn handle_p2p_message(
        message: &P2PMessage,
        da_layer: &Arc<DataAvailabilityLayer>,
        pending_requests: &Arc<RwLock<HashMap<String, ChunkRequestInfo>>>,
        chunk_availability: &Arc<RwLock<HashMap<String, HashMap<usize, Vec<KademliaId>>>>>,
        da_event_tx: &mpsc::UnboundedSender<DataAvailabilityEvent>,
    ) -> AvoResult<()> {
        match message.message_type {
            P2PMessageType::Block => {
                // Procesar nuevo bloque para DA
                if let Ok(chunk_msg) = serde_json::from_slice::<ChunkMessage>(&message.payload) {
                    Self::handle_chunk_message(
                        &chunk_msg,
                        da_layer,
                        pending_requests,
                        chunk_availability,
                        da_event_tx,
                    )
                    .await?;
                }
            }
            P2PMessageType::Transaction => {
                // Pueden contener datos que requieren DA
                debug!("Received transaction, checking for DA requirements");
            }
            _ => {
                // Otros tipos de mensajes
                debug!("Received P2P message type: {:?}", message.message_type);
            }
        }

        Ok(())
    }

    /// Manejar mensaje de chunk
    async fn handle_chunk_message(
        chunk_msg: &ChunkMessage,
        da_layer: &Arc<DataAvailabilityLayer>,
        pending_requests: &Arc<RwLock<HashMap<String, ChunkRequestInfo>>>,
        chunk_availability: &Arc<RwLock<HashMap<String, HashMap<usize, Vec<KademliaId>>>>>,
        da_event_tx: &mpsc::UnboundedSender<DataAvailabilityEvent>,
    ) -> AvoResult<()> {
        match chunk_msg.chunk_msg_type {
            ChunkMessageType::ChunkAnnouncement => {
                // Actualizar disponibilidad de chunk
                let mut availability = chunk_availability.write().await;
                let block_chunks = availability
                    .entry(chunk_msg.block_id.clone())
                    .or_insert_with(HashMap::new);

                block_chunks.insert(chunk_msg.chunk_index, chunk_msg.available_peers.clone());

                // Enviar evento
                let event = DataAvailabilityEvent {
                    event_type: DAEventType::ChunkVerified,
                    block_id: chunk_msg.block_id.clone(),
                    details: [("chunk_index".to_string(), chunk_msg.chunk_index.to_string())]
                        .into(),
                    timestamp: SystemTime::now(),
                };
                let _ = da_event_tx.send(event);

                debug!(
                    "📢 Chunk {} announced for block {}",
                    chunk_msg.chunk_index, chunk_msg.block_id
                );
            }
            ChunkMessageType::ChunkRequest => {
                // Responder con chunk si lo tenemos
                debug!(
                    "📥 Chunk request for block {} chunk {}",
                    chunk_msg.block_id, chunk_msg.chunk_index
                );
                // En implementación real, buscaríamos el chunk y responderíamos
            }
            ChunkMessageType::ChunkResponse => {
                // Procesar respuesta de chunk
                if let Some(chunk_data) = &chunk_msg.chunk_data {
                    debug!(
                        "📦 Received chunk {} for block {}",
                        chunk_msg.chunk_index, chunk_msg.block_id
                    );

                    // Remover de requests pendientes
                    let request_id = format!("{}_{}", chunk_msg.block_id, chunk_msg.chunk_index);
                    {
                        let mut pending = pending_requests.write().await;
                        pending.remove(&request_id);
                    }

                    // Enviar evento
                    let event = DataAvailabilityEvent {
                        event_type: DAEventType::ChunkVerified,
                        block_id: chunk_msg.block_id.clone(),
                        details: [("chunk_index".to_string(), chunk_msg.chunk_index.to_string())]
                            .into(),
                        timestamp: SystemTime::now(),
                    };
                    let _ = da_event_tx.send(event);
                }
            }
            ChunkMessageType::ChunkUnavailable => {
                debug!(
                    "❌ Chunk {} unavailable for block {}",
                    chunk_msg.chunk_index, chunk_msg.block_id
                );

                // Enviar evento de fallo
                let event = DataAvailabilityEvent {
                    event_type: DAEventType::ChunkFailed,
                    block_id: chunk_msg.block_id.clone(),
                    details: [("chunk_index".to_string(), chunk_msg.chunk_index.to_string())]
                        .into(),
                    timestamp: SystemTime::now(),
                };
                let _ = da_event_tx.send(event);
            }
        }

        Ok(())
    }

    /// Iniciar verificador de disponibilidad
    async fn start_availability_checker(&self) {
        let das_validator = Arc::clone(&self.das_validator);
        let chunk_availability = Arc::clone(&self.chunk_availability);
        let da_event_tx = self.da_event_tx.clone();
        let is_running = Arc::clone(&self.is_running);
        let check_interval = Duration::from_secs(self.config.availability_check_interval);

        tokio::spawn(async move {
            while *is_running.read().await {
                // Obtener bloques para verificar
                let blocks_to_check: Vec<String> = {
                    let availability = chunk_availability.read().await;
                    availability.keys().cloned().collect()
                };

                // Verificar cada bloque
                for block_id in blocks_to_check {
                    let request = das_validator
                        .create_sampling_request(
                            block_id.clone(),
                            0, // Height se debería obtener de otra fuente
                            SamplingPriority::Normal,
                        )
                        .await;

                    if let Err(e) = das_validator.submit_sampling_request(request).await {
                        debug!("Failed to submit sampling request for {}: {}", block_id, e);
                    }
                }

                tokio::time::sleep(check_interval).await;
            }
        });
    }

    /// Iniciar limpieza de requests
    async fn start_request_cleanup(&self) {
        let pending_requests = Arc::clone(&self.pending_chunk_requests);
        let is_running = Arc::clone(&self.is_running);
        let timeout = Duration::from_secs(self.config.chunk_request_timeout);

        tokio::spawn(async move {
            while *is_running.read().await {
                let cutoff_time = SystemTime::now() - timeout;

                {
                    let mut pending = pending_requests.write().await;
                    pending.retain(|_, request_info| request_info.requested_at > cutoff_time);
                }

                tokio::time::sleep(Duration::from_secs(60)).await; // Limpiar cada minuto
            }
        });
    }

    /// Publicar bloque con DA
    pub async fn publish_block_with_da(
        &self,
        block_id: String,
        block_data: Vec<u8>,
    ) -> AvoResult<()> {
        info!("📡 Publishing block with DA: {}", block_id);

        // Preparar datos para disponibilidad
        let da_block = self
            .da_layer
            .prepare_data_availability(block_id.clone(), block_data)
            .await?;

        // Propagar chunks según estrategia
        match self.config.chunk_propagation_strategy {
            ChunkPropagationStrategy::Broadcast => {
                self.broadcast_chunks(&da_block).await?;
            }
            ChunkPropagationStrategy::ScoreBased => {
                self.propagate_chunks_by_score(&da_block).await?;
            }
            ChunkPropagationStrategy::ShardBased => {
                self.propagate_chunks_by_shard(&da_block).await?;
            }
            ChunkPropagationStrategy::Random => {
                self.propagate_chunks_randomly(&da_block).await?;
            }
        }

        // Enviar evento
        let event = DataAvailabilityEvent {
            event_type: DAEventType::BlockAvailable,
            block_id: block_id.clone(),
            details: [(
                "chunk_count".to_string(),
                da_block.data_chunks.len().to_string(),
            )]
            .into(),
            timestamp: SystemTime::now(),
        };
        let _ = self.da_event_tx.send(event);

        info!("✅ Block published with DA: {}", block_id);
        Ok(())
    }

    /// Broadcast chunks a todos los peers
    async fn broadcast_chunks(&self, da_block: &DataAvailabilityBlock) -> AvoResult<()> {
        for chunk in &da_block.data_chunks {
            let chunk_msg = ChunkMessage {
                chunk_msg_type: ChunkMessageType::ChunkAnnouncement,
                block_id: da_block.block_id.clone(),
                chunk_index: chunk.index,
                chunk_data: Some(chunk.clone()),
                available_peers: vec![self.local_id],
            };

            let message = P2PMessage {
                id: format!("chunk_{}_{}", da_block.block_id, chunk.index),
                message_type: P2PMessageType::Block,
                payload: serde_json::to_vec(&chunk_msg)?,
                timestamp: SystemTime::now(),
                ttl: 10,
                sender: self.local_id,
                topic: Some("data_availability".to_string()),
            };

            if let Err(e) = self.p2p_manager.broadcast_message(message).await {
                warn!("Failed to broadcast chunk {}: {}", chunk.index, e);
            }
        }

        Ok(())
    }

    /// Propagar chunks basado en scoring
    async fn propagate_chunks_by_score(&self, da_block: &DataAvailabilityBlock) -> AvoResult<()> {
        // En implementación real, seleccionaría peers con mejor score
        self.broadcast_chunks(da_block).await
    }

    /// Propagar chunks por shard
    async fn propagate_chunks_by_shard(&self, da_block: &DataAvailabilityBlock) -> AvoResult<()> {
        // En implementación real, enviaría chunks solo a peers del shard correspondiente
        self.broadcast_chunks(da_block).await
    }

    /// Propagar chunks aleatoriamente
    async fn propagate_chunks_randomly(&self, da_block: &DataAvailabilityBlock) -> AvoResult<()> {
        // En implementación real, seleccionaría peers aleatorios
        self.broadcast_chunks(da_block).await
    }

    /// Solicitar chunk específico
    pub async fn request_chunk(&self, block_id: String, chunk_index: usize) -> AvoResult<String> {
        let request_id = format!("{}_{}", block_id, chunk_index);

        let request_info = ChunkRequestInfo {
            request_id: request_id.clone(),
            block_id: block_id.clone(),
            chunk_index,
            queried_peers: HashSet::new(),
            requested_at: SystemTime::now(),
            retry_count: 0,
        };

        // Agregar a requests pendientes
        {
            let mut pending = self.pending_chunk_requests.write().await;
            pending.insert(request_id.clone(), request_info);
        }

        // Crear mensaje de request
        let chunk_msg = ChunkMessage {
            chunk_msg_type: ChunkMessageType::ChunkRequest,
            block_id,
            chunk_index,
            chunk_data: None,
            available_peers: vec![],
        };

        let message = P2PMessage {
            id: request_id.clone(),
            message_type: P2PMessageType::Block,
            payload: serde_json::to_vec(&chunk_msg)?,
            timestamp: SystemTime::now(),
            ttl: 5,
            sender: self.local_id,
            topic: Some("chunk_request".to_string()),
        };

        // Broadcast request
        self.p2p_manager.broadcast_message(message).await?;

        Ok(request_id)
    }

    /// Obtener canal de eventos DA
    pub async fn get_da_event_receiver(
        &self,
    ) -> Arc<Mutex<mpsc::UnboundedReceiver<DataAvailabilityEvent>>> {
        Arc::clone(&self.da_event_rx)
    }

    /// Obtener métricas del sistema
    pub async fn get_system_metrics(&self) -> SystemMetrics {
        let p2p_metrics = self.p2p_manager.get_metrics().await;
        let das_metrics = self.das_validator.get_metrics().await;
        let da_health = self.da_layer.get_health_report().await;

        SystemMetrics {
            p2p_connections: p2p_metrics.active_connections,
            p2p_messages_sent: p2p_metrics.messages_sent,
            p2p_messages_received: p2p_metrics.messages_received,
            das_samplings: das_metrics.total_samplings,
            das_success_rate: if das_metrics.total_samplings > 0 {
                das_metrics.successful_samplings as f64 / das_metrics.total_samplings as f64
            } else {
                0.0
            },
            da_blocks_available: da_health.available_blocks,
            da_average_availability: da_health.average_availability,
        }
    }
}

/// Métricas del sistema integrado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub p2p_connections: usize,
    pub p2p_messages_sent: u64,
    pub p2p_messages_received: u64,
    pub das_samplings: u64,
    pub das_success_rate: f64,
    pub da_blocks_available: usize,
    pub da_average_availability: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_integrated_system_creation() {
        let config = IntegratedNetworkConfig::default();
        let local_id = KademliaId::from_str("test_integrated_node");

        let result = IntegratedNetworkSystem::new(config, local_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_chunk_message_serialization() {
        let chunk_msg = ChunkMessage {
            chunk_msg_type: ChunkMessageType::ChunkAnnouncement,
            block_id: "test_block".to_string(),
            chunk_index: 0,
            chunk_data: None,
            available_peers: vec![],
        };

        let serialized = serde_json::to_vec(&chunk_msg);
        assert!(serialized.is_ok());

        let deserialized: Result<ChunkMessage, _> = serde_json::from_slice(&serialized.unwrap());
        assert!(deserialized.is_ok());
    }
}
