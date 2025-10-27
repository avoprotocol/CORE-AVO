//! # Data Availability Layer para AVO Protocol
//!
//! Implementa Reed-Solomon erasure coding, KZG commitments, y Data Availability Sampling (DAS)
//! para garantizar que los datos estén disponibles sin requerir que todos los nodos descarguen
//! todo el contenido.

pub mod das_validator;

pub use das_validator::{
    ChunkSamplingDetail, DASValidator, DASValidatorConfig, DASValidatorMetrics,
    DetailedSamplingResult, SamplingPriority, SamplingRequest,
};

use crate::crypto::*;
use crate::error::*;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Configuración del Data Availability Layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAvailabilityConfig {
    /// Número de shards de datos
    pub data_shards: usize,
    /// Número de shards de paridad para Reed-Solomon
    pub parity_shards: usize,
    /// Tamaño máximo de chunk en bytes
    pub max_chunk_size: usize,
    /// Número de samples requeridos para DAS
    pub required_samples: usize,
    /// Timeout para sampling en segundos
    pub sampling_timeout: u64,
    /// Período de retención de datos en segundos
    pub data_retention_period: u64,
    /// Número de validadores por shard
    pub validators_per_shard: usize,
}

impl Default for DataAvailabilityConfig {
    fn default() -> Self {
        Self {
            data_shards: 32,                      // 32 shards de datos
            parity_shards: 16,                    // 16 shards de paridad (50% redundancia)
            max_chunk_size: 512 * 1024,           // 512 KB por chunk
            required_samples: 10,                 // 10 samples para verificar disponibilidad
            sampling_timeout: 30,                 // 30 segundos timeout
            data_retention_period: 7 * 24 * 3600, // 7 días
            validators_per_shard: 5,              // 5 validadores por shard
        }
    }
}

/// Chunk de datos con erasure coding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataChunk {
    /// ID único del chunk
    pub id: String,
    /// Índice del chunk en el conjunto
    pub index: usize,
    /// Datos del chunk (puede ser data o parity)
    pub data: Vec<u8>,
    /// Tipo de chunk
    pub chunk_type: ChunkType,
    /// KZG commitment
    pub kzg_commitment: KZGCommitment,
    /// Proof KZG
    pub kzg_proof: KZGProof,
    /// Hash del chunk
    pub hash: Hash,
    /// Timestamp de creación
    pub created_at: SystemTime,
}

/// Tipo de chunk
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChunkType {
    /// Chunk de datos original
    Data,
    /// Chunk de paridad (Reed-Solomon)
    Parity,
}

/// KZG Commitment (simulado)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KZGCommitment {
    pub point: Vec<u8>, // Punto en la curva elíptica BLS12-381
}

/// KZG Proof (simulado)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KZGProof {
    pub proof: Vec<u8>,      // Proof en la curva elíptica
    pub evaluation: Vec<u8>, // Evaluación del polinomio
}

impl KZGCommitment {
    /// Crear commitment desde datos
    pub fn from_data(data: &[u8]) -> Self {
        // En implementación real, usaría biblioteca KZG
        let hash = blake3::hash(data);
        let mut point = vec![0u8; 48];
        point[..32].copy_from_slice(hash.as_bytes());

        Self { point }
    }

    /// Verificar proof KZG
    pub fn verify_proof(&self, proof: &KZGProof, chunk_index: usize, data: &[u8]) -> bool {
        // Simulación de verificación KZG
        // En implementación real usaría biblioteca como arkworks
        let expected_commitment = Self::from_data(data);

        // Verificar que el commitment coincide
        if self.point != expected_commitment.point {
            return false;
        }

        // Simular verificación del proof (en real usaría pairing)
        let chunk_hash = blake3::hash(&[&chunk_index.to_le_bytes(), data].concat());
        let expected_eval = chunk_hash.as_bytes()[..32].to_vec();

        proof.evaluation == expected_eval
    }
}

impl KZGProof {
    /// Crear proof para un chunk
    pub fn create_proof(data: &[u8], chunk_index: usize) -> Self {
        let chunk_hash = blake3::hash(&[&chunk_index.to_le_bytes(), data].concat());
        let mut proof = vec![0u8; 48];
        let evaluation = chunk_hash.as_bytes()[..32].to_vec();

        // Simular creación de proof
        proof[..32].copy_from_slice(chunk_hash.as_bytes());

        Self { proof, evaluation }
    }
}

/// Bloque de datos para availability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAvailabilityBlock {
    /// ID del bloque
    pub block_id: String,
    /// Altura del bloque
    pub height: u64,
    /// Chunks de datos
    pub data_chunks: Vec<DataChunk>,
    /// Matriz de disponibilidad (qué validadores tienen qué chunks)
    pub availability_matrix: HashMap<String, HashSet<usize>>, // validator_id -> chunk_indices
    /// Root hash de todos los chunks
    pub data_root: Hash,
    /// KZG commitment del bloque completo
    pub block_commitment: KZGCommitment,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Resultado de sampling de disponibilidad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingResult {
    /// ID del bloque sampieado
    pub block_id: String,
    /// Chunks verificados exitosamente
    pub verified_chunks: Vec<usize>,
    /// Chunks fallidos
    pub failed_chunks: Vec<usize>,
    /// Porcentaje de disponibilidad
    pub availability_percentage: f64,
    /// Es suficiente para reconstruir
    pub is_available: bool,
    /// Tiempo total de sampling
    pub sampling_duration: Duration,
}

/// Reporte de salud del DA Layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAHealthReport {
    /// Número total de bloques monitoreados
    pub total_blocks: usize,
    /// Bloques con datos disponibles
    pub available_blocks: usize,
    /// Porcentaje promedio de disponibilidad
    pub average_availability: f64,
    /// Latencia promedio de sampling (ms)
    pub average_sampling_latency: f64,
    /// Número de validadores activos
    pub active_validators: usize,
    /// Espacio de almacenamiento usado (bytes)
    pub storage_used: u64,
}

/// Data Availability Layer principal
#[derive(Debug)]
pub struct DataAvailabilityLayer {
    /// Configuración
    config: DataAvailabilityConfig,
    /// Bloques almacenados
    blocks: Arc<RwLock<HashMap<String, DataAvailabilityBlock>>>,
    /// Cache de chunks por ID
    chunk_cache: Arc<RwLock<HashMap<String, DataChunk>>>,
    /// Validadores registrados por shard
    validators_by_shard: Arc<RwLock<HashMap<usize, Vec<String>>>>,
    /// Métricas de sampling
    sampling_metrics: Arc<RwLock<HashMap<String, SamplingResult>>>,
    /// Encoder Reed-Solomon
    reed_solomon: Arc<Mutex<ReedSolomonEncoder>>,
}

/// Encoder Reed-Solomon (simplificado)
#[derive(Debug)]
pub struct ReedSolomonEncoder {
    data_shards: usize,
    parity_shards: usize,
    total_shards: usize,
}

impl ReedSolomonEncoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
            total_shards: data_shards + parity_shards,
        }
    }

    /// Codificar datos con Reed-Solomon
    pub fn encode(&self, data: &[u8]) -> AvoResult<Vec<Vec<u8>>> {
        let chunk_size = (data.len() + self.data_shards - 1) / self.data_shards;
        let mut chunks = Vec::new();

        // Dividir en chunks de datos
        for i in 0..self.data_shards {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, data.len());

            if start < data.len() {
                let mut chunk = data[start..end].to_vec();
                // Padding si es necesario
                chunk.resize(chunk_size, 0);
                chunks.push(chunk);
            } else {
                chunks.push(vec![0; chunk_size]);
            }
        }

        // Generar chunks de paridad (simulación simple de Reed-Solomon)
        for i in 0..self.parity_shards {
            let parity_chunk = self.generate_parity_chunk(&chunks, i);
            chunks.push(parity_chunk);
        }

        Ok(chunks)
    }

    /// Generar chunk de paridad
    fn generate_parity_chunk(&self, data_chunks: &[Vec<u8>], parity_index: usize) -> Vec<u8> {
        if data_chunks.is_empty() {
            return Vec::new();
        }

        let chunk_size = data_chunks[0].len();
        let mut parity = vec![0u8; chunk_size];

        // XOR simple para simulación (Reed-Solomon real usa GF(256))
        for chunk in data_chunks {
            for (i, &byte) in chunk.iter().enumerate() {
                parity[i] ^= byte.wrapping_mul((parity_index + 1) as u8);
            }
        }

        parity
    }

    /// Decodificar/reconstruir datos desde chunks disponibles
    pub fn decode(&self, chunks: Vec<Option<Vec<u8>>>) -> AvoResult<Vec<u8>> {
        if chunks.len() != self.total_shards {
            return Err(AvoError::InvalidInput(
                "Invalid number of chunks".to_string(),
            ));
        }

        // Contar chunks disponibles
        let available_count = chunks.iter().filter(|c| c.is_some()).count();
        if available_count < self.data_shards {
            return Err(AvoError::network(format!(
                "Need at least {} chunks, got {}",
                self.data_shards, available_count
            )));
        }

        // Extraer chunks de datos disponibles
        let mut data_chunks = Vec::new();
        let mut missing_indices = Vec::new();

        for i in 0..self.data_shards {
            if let Some(ref chunk) = chunks[i] {
                data_chunks.push(chunk.clone());
            } else {
                missing_indices.push(i);
                data_chunks.push(Vec::new()); // Placeholder
            }
        }

        // Reconstruir chunks faltantes usando paridad (simplificado)
        for missing_index in missing_indices {
            if let Some(reconstructed) = self.reconstruct_chunk(&chunks, missing_index) {
                data_chunks[missing_index] = reconstructed;
            } else {
                return Err(AvoError::network(
                    "Cannot reconstruct missing chunk".to_string(),
                ));
            }
        }

        // Concatenar chunks de datos
        let mut result = Vec::new();
        for chunk in data_chunks {
            result.extend_from_slice(&chunk);
        }

        // Remover padding
        while result.last() == Some(&0) {
            result.pop();
        }

        Ok(result)
    }

    /// Reconstruir un chunk faltante (simplificado)
    fn reconstruct_chunk(
        &self,
        chunks: &[Option<Vec<u8>>],
        missing_index: usize,
    ) -> Option<Vec<u8>> {
        // Buscar un chunk de paridad disponible
        for parity_index in 0..self.parity_shards {
            let parity_chunk_index = self.data_shards + parity_index;
            if let Some(ref parity_chunk) = chunks[parity_chunk_index] {
                // Reconstruir usando XOR inverso (simplificado)
                let mut reconstructed = parity_chunk.clone();

                for i in 0..self.data_shards {
                    if i != missing_index {
                        if let Some(ref chunk) = chunks[i] {
                            for (j, &byte) in chunk.iter().enumerate() {
                                if j < reconstructed.len() {
                                    reconstructed[j] ^= byte.wrapping_mul((parity_index + 1) as u8);
                                }
                            }
                        }
                    }
                }

                return Some(reconstructed);
            }
        }

        None
    }
}

impl DataAvailabilityLayer {
    /// Crear nuevo DA Layer
    pub fn new(config: DataAvailabilityConfig) -> Self {
        info!("🗄️  Initializing Data Availability Layer");
        info!(
            "📊 Config: {} data shards, {} parity shards",
            config.data_shards, config.parity_shards
        );

        let reed_solomon = ReedSolomonEncoder::new(config.data_shards, config.parity_shards);

        Self {
            config,
            blocks: Arc::new(RwLock::new(HashMap::new())),
            chunk_cache: Arc::new(RwLock::new(HashMap::new())),
            validators_by_shard: Arc::new(RwLock::new(HashMap::new())),
            sampling_metrics: Arc::new(RwLock::new(HashMap::new())),
            reed_solomon: Arc::new(Mutex::new(reed_solomon)),
        }
    }

    /// Preparar datos para disponibilidad
    pub async fn prepare_data_availability(
        &self,
        block_id: String,
        data: Vec<u8>,
    ) -> AvoResult<DataAvailabilityBlock> {
        info!("📦 Preparing data availability for block: {}", block_id);

        if data.len() > self.config.max_chunk_size * self.config.data_shards {
            return Err(AvoError::InvalidInput(
                "Data too large for current configuration".to_string(),
            ));
        }

        // Codificar con Reed-Solomon
        let encoded_chunks = {
            let encoder = self.reed_solomon.lock().await;
            encoder.encode(&data)?
        };

        // Crear chunks con KZG commitments
        let mut data_chunks = Vec::new();
        for (index, chunk_data) in encoded_chunks.into_iter().enumerate() {
            let chunk_type = if index < self.config.data_shards {
                ChunkType::Data
            } else {
                ChunkType::Parity
            };

            let kzg_commitment = KZGCommitment::from_data(&chunk_data);
            let kzg_proof = KZGProof::create_proof(&chunk_data, index);
            let hash = blake3::hash(&chunk_data);

            let chunk = DataChunk {
                id: format!("{}_{}", block_id, index),
                index,
                data: chunk_data,
                chunk_type,
                kzg_commitment,
                kzg_proof,
                hash: *hash.as_bytes(),
                created_at: SystemTime::now(),
            };

            data_chunks.push(chunk);
        }

        // Calcular data root (Merkle root de todos los chunks)
        let chunk_hashes: Vec<Hash> = data_chunks.iter().map(|c| c.hash).collect();
        let data_root = self.calculate_merkle_root(&chunk_hashes);

        // Crear commitment del bloque completo
        let block_commitment = KZGCommitment::from_data(&data);

        // Distribuir chunks a validadores
        let availability_matrix = self.distribute_chunks_to_validators(&data_chunks).await?;

        let da_block = DataAvailabilityBlock {
            block_id: block_id.clone(),
            height: 0, // Se debe establecer externamente
            data_chunks,
            availability_matrix,
            data_root,
            block_commitment,
            timestamp: SystemTime::now(),
        };

        // Almacenar bloque
        {
            let mut blocks = self.blocks.write().await;
            blocks.insert(block_id.clone(), da_block.clone());
        }

        // Cachear chunks individualmente
        {
            let mut cache = self.chunk_cache.write().await;
            for chunk in &da_block.data_chunks {
                cache.insert(chunk.id.clone(), chunk.clone());
            }
        }

        info!("✅ Data availability prepared for block: {}", block_id);
        Ok(da_block)
    }

    /// Distribuir chunks a validadores
    async fn distribute_chunks_to_validators(
        &self,
        chunks: &[DataChunk],
    ) -> AvoResult<HashMap<String, HashSet<usize>>> {
        let validators_by_shard = self.validators_by_shard.read().await;
        let mut availability_matrix = HashMap::new();

        // Asignar chunks a shards basado en el índice
        for chunk in chunks {
            let shard_id = chunk.index % self.config.data_shards;

            if let Some(validators) = validators_by_shard.get(&shard_id) {
                // Asignar a todos los validadores del shard
                for validator_id in validators {
                    availability_matrix
                        .entry(validator_id.clone())
                        .or_insert_with(HashSet::new)
                        .insert(chunk.index);
                }
            } else {
                warn!("No validators found for shard {}", shard_id);
            }
        }

        Ok(availability_matrix)
    }

    /// Realizar Data Availability Sampling
    pub async fn sample_data_availability(&self, block_id: &str) -> AvoResult<SamplingResult> {
        let start_time = std::time::Instant::now();
        info!(
            "🔍 Starting data availability sampling for block: {}",
            block_id
        );

        let block = {
            let blocks = self.blocks.read().await;
            blocks.get(block_id).cloned()
        };

        let block = match block {
            Some(b) => b,
            None => return Err(AvoError::network(format!("Block not found: {}", block_id))),
        };

        let mut verified_chunks = Vec::new();
        let mut failed_chunks = Vec::new();

        // Seleccionar chunks aleatorios para sampling
        let total_chunks = block.data_chunks.len();
        let sample_indices = self.select_random_chunks(total_chunks, self.config.required_samples);

        for &chunk_index in &sample_indices {
            if let Some(chunk) = block.data_chunks.get(chunk_index) {
                // Verificar KZG commitment y proof
                if chunk
                    .kzg_commitment
                    .verify_proof(&chunk.kzg_proof, chunk.index, &chunk.data)
                {
                    // Verificar hash del chunk
                    let computed_hash = blake3::hash(&chunk.data);
                    if computed_hash.as_bytes() == chunk.hash.as_slice() {
                        verified_chunks.push(chunk_index);
                        debug!("✅ Chunk {} verified", chunk_index);
                    } else {
                        failed_chunks.push(chunk_index);
                        warn!("❌ Chunk {} hash mismatch", chunk_index);
                    }
                } else {
                    failed_chunks.push(chunk_index);
                    warn!("❌ Chunk {} KZG verification failed", chunk_index);
                }
            } else {
                failed_chunks.push(chunk_index);
                warn!("❌ Chunk {} not found", chunk_index);
            }
        }

        let availability_percentage =
            (verified_chunks.len() as f64 / sample_indices.len() as f64) * 100.0;
        let is_available = verified_chunks.len() >= self.config.data_shards;

        let sampling_duration = start_time.elapsed();

        let result = SamplingResult {
            block_id: block_id.to_string(),
            verified_chunks,
            failed_chunks,
            availability_percentage,
            is_available,
            sampling_duration,
        };

        // Guardar métricas
        {
            let mut metrics = self.sampling_metrics.write().await;
            metrics.insert(block_id.to_string(), result.clone());
        }

        info!(
            "📊 Sampling completed: {:.1}% available, {} verified chunks",
            availability_percentage,
            result.verified_chunks.len()
        );

        Ok(result)
    }

    /// Seleccionar chunks aleatorios para sampling
    fn select_random_chunks(&self, total_chunks: usize, sample_count: usize) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..total_chunks).collect();

        // Fisher-Yates shuffle (simplificado)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        let seed = hasher.finish();

        for i in (1..indices.len()).rev() {
            let j = (seed as usize + i) % (i + 1);
            indices.swap(i, j);
        }

        indices.truncate(std::cmp::min(sample_count, total_chunks));
        indices
    }

    /// Reconstruir datos desde chunks disponibles
    pub async fn reconstruct_data(&self, block_id: &str) -> AvoResult<Vec<u8>> {
        info!("🔧 Reconstructing data for block: {}", block_id);

        let block = {
            let blocks = self.blocks.read().await;
            blocks.get(block_id).cloned()
        };

        let block = match block {
            Some(b) => b,
            None => return Err(AvoError::network(format!("Block not found: {}", block_id))),
        };

        // Preparar chunks para decodificación
        let total_shards = self.config.data_shards + self.config.parity_shards;
        let mut chunks_for_decode = vec![None; total_shards];

        for chunk in &block.data_chunks {
            if chunk.index < total_shards {
                chunks_for_decode[chunk.index] = Some(chunk.data.clone());
            }
        }

        // Decodificar con Reed-Solomon
        let decoder = self.reed_solomon.lock().await;
        let reconstructed_data = decoder.decode(chunks_for_decode)?;

        info!("✅ Data reconstructed successfully for block: {}", block_id);
        Ok(reconstructed_data)
    }

    /// Calcular Merkle root
    fn calculate_merkle_root(&self, hashes: &[Hash]) -> Hash {
        if hashes.is_empty() {
            return Hash::default();
        }

        if hashes.len() == 1 {
            return hashes[0];
        }

        let mut current_level = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&current_level[i]);
                    combined.extend_from_slice(&current_level[i + 1]);
                    let hash = blake3::hash(&combined);
                    next_level.push(*hash.as_bytes());
                } else {
                    next_level.push(current_level[i]);
                }
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Registrar validador para un shard
    pub async fn register_validator(&self, shard_id: usize, validator_id: String) -> AvoResult<()> {
        let mut validators_by_shard = self.validators_by_shard.write().await;

        validators_by_shard
            .entry(shard_id)
            .or_insert_with(Vec::new)
            .push(validator_id.clone());

        info!(
            "👤 Registered validator {} for shard {}",
            validator_id, shard_id
        );
        Ok(())
    }

    /// Obtener reporte de salud
    pub async fn get_health_report(&self) -> DAHealthReport {
        let blocks = self.blocks.read().await;
        let metrics = self.sampling_metrics.read().await;
        let validators_by_shard = self.validators_by_shard.read().await;

        let total_blocks = blocks.len();
        let available_blocks = metrics
            .values()
            .filter(|result| result.is_available)
            .count();

        let average_availability = if !metrics.is_empty() {
            metrics
                .values()
                .map(|r| r.availability_percentage)
                .sum::<f64>()
                / metrics.len() as f64
        } else {
            0.0
        };

        let average_sampling_latency = if !metrics.is_empty() {
            metrics
                .values()
                .map(|r| r.sampling_duration.as_millis() as f64)
                .sum::<f64>()
                / metrics.len() as f64
        } else {
            0.0
        };

        let active_validators = validators_by_shard.values().map(|v| v.len()).sum();

        let storage_used = blocks
            .values()
            .flat_map(|block| &block.data_chunks)
            .map(|chunk| chunk.data.len() as u64)
            .sum();

        DAHealthReport {
            total_blocks,
            available_blocks,
            average_availability,
            average_sampling_latency,
            active_validators,
            storage_used,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_data_availability_preparation() {
        let config = DataAvailabilityConfig::default();
        let da_layer = DataAvailabilityLayer::new(config);

        let test_data = b"Hello, Data Availability Layer!".to_vec();
        let block_id = "test_block_1".to_string();

        let result = da_layer
            .prepare_data_availability(block_id.clone(), test_data.clone())
            .await;
        assert!(result.is_ok());

        let da_block = result.unwrap();
        assert_eq!(da_block.block_id, block_id);
        assert!(!da_block.data_chunks.is_empty());
    }

    #[tokio::test]
    async fn test_reed_solomon_encoding() {
        let encoder = ReedSolomonEncoder::new(4, 2);
        let test_data = b"Test data for Reed-Solomon encoding";

        let encoded = encoder.encode(test_data);
        assert!(encoded.is_ok());

        let chunks = encoded.unwrap();
        assert_eq!(chunks.len(), 6); // 4 data + 2 parity

        // Test reconstruction with missing chunk
        let chunks_for_decode = vec![
            Some(chunks[0].clone()),
            Some(chunks[1].clone()),
            None, // Missing chunk
            Some(chunks[3].clone()),
            Some(chunks[4].clone()), // Parity
            Some(chunks[5].clone()), // Parity
        ];

        let decoded = encoder.decode(chunks_for_decode);
        assert!(decoded.is_ok());
    }

    #[tokio::test]
    async fn test_kzg_commitment() {
        let test_data = b"Test data for KZG commitment";
        let commitment = KZGCommitment::from_data(test_data);
        let proof = KZGProof::create_proof(test_data, 0);

        assert!(commitment.verify_proof(&proof, 0, test_data));

        // Test with different data should fail
        let wrong_data = b"Wrong data";
        assert!(!commitment.verify_proof(&proof, 0, wrong_data));
    }
}
