//! # DAS Validator - Data Availability Sampling Validator
//!
//! Implementa validadores especializados que realizan Data Availability Sampling
//! de manera eficiente y coordinada para verificar disponibilidad de datos.

use crate::da::{DataAvailabilityLayer, DataChunk, KZGCommitment, KZGProof, SamplingResult};
use crate::error::*;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Configuración del DAS Validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DASValidatorConfig {
    /// ID del validador
    pub validator_id: String,
    /// Shards asignados a este validador
    pub assigned_shards: Vec<usize>,
    /// Número de samples por bloque
    pub samples_per_block: usize,
    /// Intervalo entre samplings (segundos)
    pub sampling_interval: u64,
    /// Timeout para cada sample (segundos)
    pub sample_timeout: u64,
    /// Número máximo de samples concurrentes
    pub max_concurrent_samples: usize,
    /// Threshold de confianza para marcar como disponible
    pub confidence_threshold: f64,
    /// Período de retención de resultados (segundos)
    pub result_retention_period: u64,
}

impl Default for DASValidatorConfig {
    fn default() -> Self {
        Self {
            validator_id: "das_validator_1".to_string(),
            assigned_shards: vec![0, 1, 2, 3],
            samples_per_block: 15,
            sampling_interval: 10, // 10 segundos entre samplings
            sample_timeout: 5,     // 5 segundos timeout por sample
            max_concurrent_samples: 10,
            confidence_threshold: 0.85,    // 85% de confianza
            result_retention_period: 3600, // 1 hora
        }
    }
}

/// Request de sampling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingRequest {
    /// ID único del request
    pub request_id: String,
    /// ID del bloque a samplear
    pub block_id: String,
    /// Altura del bloque
    pub block_height: u64,
    /// Chunks específicos a samplear (None = aleatorio)
    pub target_chunks: Option<Vec<usize>>,
    /// Prioridad del request
    pub priority: SamplingPriority,
    /// Deadline para completar el sampling
    pub deadline: SystemTime,
    /// Metadata adicional
    pub metadata: HashMap<String, String>,
}

/// Prioridad de sampling
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SamplingPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Resultado detallado de sampling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedSamplingResult {
    /// Request ID original
    pub request_id: String,
    /// Resultado base del sampling
    pub sampling_result: SamplingResult,
    /// Detalles por chunk
    pub chunk_details: Vec<ChunkSamplingDetail>,
    /// Tiempo total de procesamiento
    pub total_processing_time: Duration,
    /// Validador que realizó el sampling
    pub validator_id: String,
    /// Score de confianza
    pub confidence_score: f64,
}

/// Detalle de sampling por chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkSamplingDetail {
    /// Índice del chunk
    pub chunk_index: usize,
    /// Fue verificado exitosamente
    pub verified: bool,
    /// Tiempo de verificación
    pub verification_time: Duration,
    /// Tamaño del chunk
    pub chunk_size: usize,
    /// Error si hubo fallo
    pub error: Option<String>,
    /// Latencia de red para obtener el chunk
    pub network_latency: Duration,
}

/// Métricas del DAS Validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DASValidatorMetrics {
    /// Total de samplings realizados
    pub total_samplings: u64,
    /// Samplings exitosos
    pub successful_samplings: u64,
    /// Samplings fallidos
    pub failed_samplings: u64,
    /// Tiempo promedio de sampling (ms)
    pub average_sampling_time: f64,
    /// Latencia promedio de red (ms)
    pub average_network_latency: f64,
    /// Chunks verificados
    pub chunks_verified: u64,
    /// Chunks fallidos
    pub chunks_failed: u64,
    /// Bloques marcados como disponibles
    pub blocks_available: u64,
    /// Bloques marcados como no disponibles
    pub blocks_unavailable: u64,
    /// Score de confianza promedio
    pub average_confidence: f64,
}

impl Default for DASValidatorMetrics {
    fn default() -> Self {
        Self {
            total_samplings: 0,
            successful_samplings: 0,
            failed_samplings: 0,
            average_sampling_time: 0.0,
            average_network_latency: 0.0,
            chunks_verified: 0,
            chunks_failed: 0,
            blocks_available: 0,
            blocks_unavailable: 0,
            average_confidence: 0.0,
        }
    }
}

/// DAS Validator principal
#[derive(Debug)]
pub struct DASValidator {
    /// Configuración
    config: DASValidatorConfig,
    /// Data Availability Layer
    da_layer: Arc<DataAvailabilityLayer>,
    /// Cola de requests pendientes
    pending_requests: Arc<RwLock<BTreeMap<SamplingPriority, Vec<SamplingRequest>>>>,
    /// Resultados de sampling
    sampling_results: Arc<RwLock<HashMap<String, DetailedSamplingResult>>>,
    /// Métricas del validador
    metrics: Arc<RwLock<DASValidatorMetrics>>,
    /// Canal para nuevos requests
    request_tx: mpsc::UnboundedSender<SamplingRequest>,
    request_rx: Arc<Mutex<mpsc::UnboundedReceiver<SamplingRequest>>>,
    /// Estado del validador
    is_running: Arc<RwLock<bool>>,
    /// Workers activos
    active_workers: Arc<RwLock<usize>>,
}

impl DASValidator {
    /// Crear nuevo DAS Validator
    pub fn new(config: DASValidatorConfig, da_layer: Arc<DataAvailabilityLayer>) -> Self {
        info!("🔍 Initializing DAS Validator: {}", config.validator_id);
        info!("📋 Assigned shards: {:?}", config.assigned_shards);

        let (request_tx, request_rx) = mpsc::unbounded_channel();

        Self {
            config,
            da_layer,
            pending_requests: Arc::new(RwLock::new(BTreeMap::new())),
            sampling_results: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(DASValidatorMetrics::default())),
            request_tx,
            request_rx: Arc::new(Mutex::new(request_rx)),
            is_running: Arc::new(RwLock::new(false)),
            active_workers: Arc::new(RwLock::new(0)),
        }
    }

    /// Iniciar el DAS Validator
    pub async fn start(&self) -> AvoResult<()> {
        info!("🚀 Starting DAS Validator: {}", self.config.validator_id);

        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(AvoError::network("DAS Validator already running"));
        }
        *is_running = true;
        drop(is_running);

        // Iniciar request processor
        self.start_request_processor().await;

        // Iniciar sampling workers
        self.start_sampling_workers().await;

        // Iniciar cleanup task
        self.start_cleanup_task().await;

        info!("✅ DAS Validator started successfully");
        Ok(())
    }

    /// Detener el DAS Validator
    pub async fn stop(&self) -> AvoResult<()> {
        info!("🛑 Stopping DAS Validator: {}", self.config.validator_id);

        let mut is_running = self.is_running.write().await;
        *is_running = false;

        // Esperar a que terminen los workers
        while *self.active_workers.read().await > 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("✅ DAS Validator stopped");
        Ok(())
    }

    /// Iniciar procesador de requests
    async fn start_request_processor(&self) {
        let request_rx = Arc::clone(&self.request_rx);
        let pending_requests = Arc::clone(&self.pending_requests);
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            let mut rx = request_rx.lock().await;

            while *is_running.read().await {
                match rx.recv().await {
                    Some(request) => {
                        debug!("📥 Received sampling request: {}", request.request_id);

                        let mut pending = pending_requests.write().await;
                        pending
                            .entry(request.priority.clone())
                            .or_insert_with(Vec::new)
                            .push(request);
                    }
                    None => break,
                }
            }
        });
    }

    /// Iniciar workers de sampling
    async fn start_sampling_workers(&self) {
        let worker_count = self.config.max_concurrent_samples;

        for worker_id in 0..worker_count {
            let pending_requests = Arc::clone(&self.pending_requests);
            let da_layer = Arc::clone(&self.da_layer);
            let sampling_results = Arc::clone(&self.sampling_results);
            let metrics = Arc::clone(&self.metrics);
            let is_running = Arc::clone(&self.is_running);
            let active_workers = Arc::clone(&self.active_workers);
            let config = self.config.clone();

            tokio::spawn(async move {
                {
                    let mut workers = active_workers.write().await;
                    *workers += 1;
                }

                info!("👷 Starting DAS sampling worker {}", worker_id);

                while *is_running.read().await {
                    // Obtener próximo request por prioridad
                    let request = {
                        let mut pending = pending_requests.write().await;

                        let mut found_request = None;
                        // Buscar request de mayor prioridad
                        for priority in [
                            SamplingPriority::Critical,
                            SamplingPriority::High,
                            SamplingPriority::Normal,
                            SamplingPriority::Low,
                        ] {
                            if let Some(requests) = pending.get_mut(&priority) {
                                if !requests.is_empty() {
                                    found_request = Some(requests.remove(0));
                                    break;
                                }
                            }
                        }
                        found_request
                    };

                    if let Some(request) = request {
                        // Procesar request
                        if let Err(e) = Self::process_sampling_request(
                            &request,
                            &da_layer,
                            &sampling_results,
                            &metrics,
                            &config,
                        )
                        .await
                        {
                            error!(
                                "❌ Failed to process sampling request {}: {}",
                                request.request_id, e
                            );
                        }
                    } else {
                        // No hay requests, esperar un poco
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }

                {
                    let mut workers = active_workers.write().await;
                    *workers -= 1;
                }

                info!("👷 DAS sampling worker {} stopped", worker_id);
            });
        }
    }

    /// Procesar un request de sampling
    async fn process_sampling_request(
        request: &SamplingRequest,
        da_layer: &Arc<DataAvailabilityLayer>,
        sampling_results: &Arc<RwLock<HashMap<String, DetailedSamplingResult>>>,
        metrics: &Arc<RwLock<DASValidatorMetrics>>,
        config: &DASValidatorConfig,
    ) -> AvoResult<()> {
        let start_time = Instant::now();
        info!("🔍 Processing sampling request: {}", request.request_id);

        // Verificar deadline
        if SystemTime::now() > request.deadline {
            warn!("⏰ Sampling request {} expired", request.request_id);
            return Err(AvoError::network("Sampling deadline exceeded"));
        }

        // Realizar sampling del bloque
        let sampling_result = da_layer.sample_data_availability(&request.block_id).await?;

        // Obtener detalles adicionales de chunks
        let chunk_details =
            Self::get_chunk_details(&request.block_id, &sampling_result, da_layer).await?;

        // Calcular score de confianza
        let confidence_score =
            Self::calculate_confidence_score(&sampling_result, &chunk_details, config);

        let total_processing_time = start_time.elapsed();

        let detailed_result = DetailedSamplingResult {
            request_id: request.request_id.clone(),
            sampling_result,
            chunk_details,
            total_processing_time,
            validator_id: config.validator_id.clone(),
            confidence_score,
        };

        // Almacenar resultado
        {
            let mut results = sampling_results.write().await;
            results.insert(request.request_id.clone(), detailed_result.clone());
        }

        // Actualizar métricas
        Self::update_metrics(metrics, &detailed_result).await;

        info!(
            "✅ Sampling completed for {}: {:.1}% confidence",
            request.request_id,
            confidence_score * 100.0
        );

        Ok(())
    }

    /// Obtener detalles de chunks
    async fn get_chunk_details(
        block_id: &str,
        sampling_result: &SamplingResult,
        da_layer: &Arc<DataAvailabilityLayer>,
    ) -> AvoResult<Vec<ChunkSamplingDetail>> {
        let mut chunk_details = Vec::new();

        // Simular obtención de detalles de chunks verificados
        for &chunk_index in &sampling_result.verified_chunks {
            let detail = ChunkSamplingDetail {
                chunk_index,
                verified: true,
                verification_time: Duration::from_millis(10 + chunk_index as u64 * 2), // Simulado
                chunk_size: 512 * 1024,                                                // 512 KB
                error: None,
                network_latency: Duration::from_millis(5 + chunk_index as u64), // Simulado
            };
            chunk_details.push(detail);
        }

        // Agregar detalles de chunks fallidos
        for &chunk_index in &sampling_result.failed_chunks {
            let detail = ChunkSamplingDetail {
                chunk_index,
                verified: false,
                verification_time: Duration::from_millis(100), // Timeout
                chunk_size: 0,
                error: Some("Verification failed".to_string()),
                network_latency: Duration::from_millis(100), // Timeout
            };
            chunk_details.push(detail);
        }

        Ok(chunk_details)
    }

    /// Calcular score de confianza
    fn calculate_confidence_score(
        sampling_result: &SamplingResult,
        chunk_details: &[ChunkSamplingDetail],
        config: &DASValidatorConfig,
    ) -> f64 {
        let total_samples =
            sampling_result.verified_chunks.len() + sampling_result.failed_chunks.len();
        if total_samples == 0 {
            return 0.0;
        }

        // Score base por disponibilidad
        let availability_score = sampling_result.availability_percentage / 100.0;

        // Penalizar por latencia alta
        let avg_latency = chunk_details
            .iter()
            .map(|d| d.network_latency.as_millis() as f64)
            .sum::<f64>()
            / chunk_details.len() as f64;

        let latency_penalty = if avg_latency > 100.0 {
            (avg_latency - 100.0) / 1000.0 // Penalizar latencia > 100ms
        } else {
            0.0
        };

        // Score de tiempo de sampling
        let sampling_time_score = if sampling_result.sampling_duration.as_millis() < 5000 {
            1.0
        } else {
            0.8 // Penalizar si toma más de 5 segundos
        };

        // Combinar scores
        let final_score = (availability_score * 0.7 + sampling_time_score * 0.3) - latency_penalty;

        final_score.max(0.0).min(1.0)
    }

    /// Actualizar métricas
    async fn update_metrics(
        metrics: &Arc<RwLock<DASValidatorMetrics>>,
        result: &DetailedSamplingResult,
    ) {
        let mut metrics_guard = metrics.write().await;

        metrics_guard.total_samplings += 1;

        if result.sampling_result.is_available {
            metrics_guard.successful_samplings += 1;
            metrics_guard.blocks_available += 1;
        } else {
            metrics_guard.failed_samplings += 1;
            metrics_guard.blocks_unavailable += 1;
        }

        // Actualizar promedios (moving average simplificado)
        let alpha = 0.1; // Factor de smoothing

        let new_sampling_time = result.total_processing_time.as_millis() as f64;
        metrics_guard.average_sampling_time =
            metrics_guard.average_sampling_time * (1.0 - alpha) + new_sampling_time * alpha;

        let new_network_latency = result
            .chunk_details
            .iter()
            .map(|d| d.network_latency.as_millis() as f64)
            .sum::<f64>()
            / result.chunk_details.len().max(1) as f64;
        metrics_guard.average_network_latency =
            metrics_guard.average_network_latency * (1.0 - alpha) + new_network_latency * alpha;

        metrics_guard.average_confidence =
            metrics_guard.average_confidence * (1.0 - alpha) + result.confidence_score * alpha;

        metrics_guard.chunks_verified += result.sampling_result.verified_chunks.len() as u64;
        metrics_guard.chunks_failed += result.sampling_result.failed_chunks.len() as u64;
    }

    /// Iniciar tarea de limpieza
    async fn start_cleanup_task(&self) {
        let sampling_results = Arc::clone(&self.sampling_results);
        let is_running = Arc::clone(&self.is_running);
        let retention_period = Duration::from_secs(self.config.result_retention_period);

        tokio::spawn(async move {
            while *is_running.read().await {
                let cutoff_time = SystemTime::now() - retention_period;

                {
                    let mut results = sampling_results.write().await;
                    results.retain(|_, result| {
                        result.sampling_result.block_id.len() > 0 && // Mantener resultados válidos
                        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap() -
                        result.total_processing_time < retention_period
                    });
                }

                tokio::time::sleep(Duration::from_secs(300)).await; // Limpiar cada 5 minutos
            }
        });
    }

    /// Enviar request de sampling
    pub async fn submit_sampling_request(&self, request: SamplingRequest) -> AvoResult<()> {
        debug!("📤 Submitting sampling request: {}", request.request_id);

        if let Err(_) = self.request_tx.send(request) {
            return Err(AvoError::network("Failed to submit sampling request"));
        }

        Ok(())
    }

    /// Crear request de sampling para un bloque
    pub async fn create_sampling_request(
        &self,
        block_id: String,
        block_height: u64,
        priority: SamplingPriority,
    ) -> SamplingRequest {
        let request_id = format!(
            "{}_{}_{}_{}",
            self.config.validator_id,
            block_id,
            block_height,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );

        let deadline = SystemTime::now() + Duration::from_secs(self.config.sample_timeout * 2);

        SamplingRequest {
            request_id,
            block_id,
            block_height,
            target_chunks: None, // Muestreo aleatorio
            priority,
            deadline,
            metadata: HashMap::new(),
        }
    }

    /// Obtener resultado de sampling
    pub async fn get_sampling_result(&self, request_id: &str) -> Option<DetailedSamplingResult> {
        let results = self.sampling_results.read().await;
        results.get(request_id).cloned()
    }

    /// Obtener métricas del validador
    pub async fn get_metrics(&self) -> DASValidatorMetrics {
        self.metrics.read().await.clone()
    }

    /// Obtener todos los resultados recientes
    pub async fn get_recent_results(&self, limit: usize) -> Vec<DetailedSamplingResult> {
        let results = self.sampling_results.read().await;
        let mut sorted_results: Vec<_> = results.values().cloned().collect();

        sorted_results.sort_by(|a, b| b.total_processing_time.cmp(&a.total_processing_time));

        sorted_results.truncate(limit);
        sorted_results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da::{DataAvailabilityConfig, DataAvailabilityLayer};

    #[tokio::test]
    async fn test_das_validator_creation() {
        let config = DASValidatorConfig::default();
        let da_config = DataAvailabilityConfig::default();
        let da_layer = Arc::new(DataAvailabilityLayer::new(da_config));

        let validator = DASValidator::new(config.clone(), da_layer);
        assert_eq!(validator.config.validator_id, config.validator_id);
    }

    #[tokio::test]
    async fn test_sampling_request_creation() {
        let config = DASValidatorConfig::default();
        let da_config = DataAvailabilityConfig::default();
        let da_layer = Arc::new(DataAvailabilityLayer::new(da_config));

        let validator = DASValidator::new(config, da_layer);

        let request = validator
            .create_sampling_request("test_block".to_string(), 100, SamplingPriority::Normal)
            .await;

        assert_eq!(request.block_id, "test_block");
        assert_eq!(request.block_height, 100);
        assert_eq!(request.priority, SamplingPriority::Normal);
    }

    #[tokio::test]
    async fn test_confidence_score_calculation() {
        use crate::da::SamplingResult;

        let sampling_result = SamplingResult {
            block_id: "test".to_string(),
            verified_chunks: vec![0, 1, 2, 3],
            failed_chunks: vec![],
            availability_percentage: 100.0,
            is_available: true,
            sampling_duration: Duration::from_millis(100),
        };

        let chunk_details = vec![ChunkSamplingDetail {
            chunk_index: 0,
            verified: true,
            verification_time: Duration::from_millis(10),
            chunk_size: 1024,
            error: None,
            network_latency: Duration::from_millis(50),
        }];

        let config = DASValidatorConfig::default();
        let confidence =
            DASValidator::calculate_confidence_score(&sampling_result, &chunk_details, &config);

        assert!(confidence > 0.8); // Debería ser alto para un buen resultado
    }
}
