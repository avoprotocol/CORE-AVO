//! # Data Availability Sampling (DAS)
//!
//! Sistema de muestreo aleatorio para verificar disponibilidad de datos
//! sin necesidad de descargar el contenido completo.

use crate::data_availability::blob_storage::BlobStorage;
use crate::data_availability::network::DistributedChunkStore;
use crate::data_availability::{AvailabilityProof, DataBlobId, DataChunk};
use crate::error::AvoError;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};

/// Configuración para el sistema de sampling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    pub sampling_probability: f64,   // Probabilidad de samplear cada chunk
    pub min_samples_required: usize, // Mínimo número de muestras para verificación
    pub confidence_threshold: f64,   // Umbral de confianza para disponibilidad
    pub max_sampling_rounds: usize,  // Máximo número de rondas de sampling
    pub fraud_proof_samples: usize,  // Muestras adicionales para pruebas de fraude
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            sampling_probability: 0.1,  // 10% de sampling
            min_samples_required: 10,   // Al menos 10 muestras
            confidence_threshold: 0.95, // 95% de confianza
            max_sampling_rounds: 5,     // Máximo 5 rondas
            fraud_proof_samples: 20,    // 20 muestras para pruebas de fraude
        }
    }
}

/// Resultado de una muestra individual
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleResult {
    pub chunk_index: usize,
    pub is_available: bool,
    pub chunk_hash: Option<[u8; 32]>,
    pub verification_time_ms: u64,
    pub source_peer: Option<String>,
}

/// Resultado de una ronda de sampling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingRound {
    pub round_number: usize,
    pub samples: Vec<SampleResult>,
    pub availability_ratio: f64,
    pub confidence_level: f64,
    pub timestamp: u64,
}

/// Resultado completo de sampling para un blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingResult {
    pub blob_id: DataBlobId,
    pub rounds: Vec<SamplingRound>,
    pub final_availability_ratio: f64,
    pub confidence_level: f64,
    pub chunks_found: usize,
    pub total_chunks_sampled: usize,
    pub is_available: bool,
    pub proof: Option<AvailabilityProof>,
}

/// Generador de números aleatorios determinístico para sampling
#[derive(Debug)]
pub struct DeterministicSampler {
    rng: StdRng,
    seed: [u8; 32],
}

impl DeterministicSampler {
    pub fn new(blob_id: &DataBlobId, round: usize) -> Self {
        // Crear seed determinístico basado en blob ID y ronda
        let mut hasher = Sha3_256::new();
        hasher.update(&blob_id.hash);
        hasher.update(&round.to_le_bytes());
        let seed: [u8; 32] = hasher.finalize().into();

        let rng = StdRng::from_seed(seed);

        Self { rng, seed }
    }

    pub fn sample_indices(&mut self, total_chunks: usize, sample_count: usize) -> Vec<usize> {
        let mut indices = HashSet::new();

        while indices.len() < sample_count && indices.len() < total_chunks {
            let index = self.rng.gen_range(0..total_chunks);
            indices.insert(index);
        }

        indices.into_iter().collect()
    }
}

/// Sistema principal de Data Availability Sampling
#[derive(Debug)]
pub struct DataSampler {
    config: SamplingConfig,
    sampling_history: HashMap<DataBlobId, Vec<SamplingResult>>,
    fraud_proofs: HashMap<DataBlobId, Vec<AvailabilityProof>>,
    network: DistributedChunkStore,
}

impl DataSampler {
    /// Crear nuevo sampler de disponibilidad de datos
    pub fn new(
        sampling_probability: f64,
        confidence_threshold: f64,
        network: DistributedChunkStore,
    ) -> Self {
        let config = SamplingConfig {
            sampling_probability,
            confidence_threshold,
            ..Default::default()
        };

        tracing::info!(
            "🎲 Data Sampler initialized: {:.1}% sampling, {:.1}% confidence",
            config.sampling_probability * 100.0,
            config.confidence_threshold * 100.0
        );

        Self {
            config,
            sampling_history: HashMap::new(),
            fraud_proofs: HashMap::new(),
            network,
        }
    }

    /// Realizar sampling de disponibilidad para un blob
    pub async fn sample_availability(
        &mut self,
        blob_id: &DataBlobId,
        storage: &mut BlobStorage,
    ) -> Result<SamplingResult, AvoError> {
        tracing::debug!(
            "🎲 Starting availability sampling for blob: {}",
            blob_id
                .hash
                .iter()
                .take(4)
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        // Obtener información del blob
        let blob_info = storage.get_blob_info(blob_id).await?;
        let total_chunks = blob_info.total_chunks;

        if total_chunks == 0 {
            return Err(AvoError::data_availability(
                "Blob has no chunks".to_string(),
            ));
        }

        let mut all_rounds = Vec::new();
        let mut total_samples = 0;
        let mut total_available = 0;

        // Realizar múltiples rondas de sampling
        for round_number in 0..self.config.max_sampling_rounds {
            let round_result = self
                .sample_round(blob_id, total_chunks, round_number, storage)
                .await?;

            total_samples += round_result.samples.len();
            total_available += round_result
                .samples
                .iter()
                .filter(|s| s.is_available)
                .count();

            let current_ratio = total_available as f64 / total_samples as f64;
            let confidence = self.calculate_confidence(total_samples, current_ratio);

            tracing::debug!(
                "Round {}: {:.1}% available, {:.1}% confidence",
                round_number,
                current_ratio * 100.0,
                confidence * 100.0
            );

            all_rounds.push(round_result);

            // Parar si alcanzamos suficiente confianza
            if confidence >= self.config.confidence_threshold {
                break;
            }
        }

        let final_availability_ratio = total_available as f64 / total_samples as f64;
        let final_confidence = self.calculate_confidence(total_samples, final_availability_ratio);
        let is_available = final_availability_ratio >= 0.75; // 75% threshold

        // Generar proof si está disponible
        let proof = if is_available {
            self.generate_availability_proof(blob_id, &all_rounds)
                .await?
        } else {
            None
        };

        let result = SamplingResult {
            blob_id: blob_id.clone(),
            rounds: all_rounds,
            final_availability_ratio,
            confidence_level: final_confidence,
            chunks_found: total_available,
            total_chunks_sampled: total_samples,
            is_available,
            proof,
        };

        // Guardar en historial
        self.sampling_history
            .entry(blob_id.clone())
            .or_insert_with(Vec::new)
            .push(result.clone());

        tracing::info!(
            "✅ Sampling complete: {:.1}% available ({}/{} chunks), {:.1}% confidence",
            final_availability_ratio * 100.0,
            total_available,
            total_samples,
            final_confidence * 100.0
        );

        Ok(result)
    }

    /// Realizar una ronda individual de sampling
    async fn sample_round(
        &self,
        blob_id: &DataBlobId,
        total_chunks: usize,
        round_number: usize,
        storage: &mut BlobStorage,
    ) -> Result<SamplingRound, AvoError> {
        let sample_count = (total_chunks as f64 * self.config.sampling_probability)
            .max(self.config.min_samples_required as f64) as usize;

        // Generar índices de muestra determinísticos
        let mut sampler = DeterministicSampler::new(blob_id, round_number);
        let sample_indices = sampler.sample_indices(total_chunks, sample_count);

        let mut samples = Vec::new();

        // Samplear cada chunk seleccionado
        for chunk_index in sample_indices {
            let start_time = std::time::Instant::now();

            let candidate_peers = self.network.peers_with_chunk(blob_id, chunk_index).await;

            let mut selected_peer: Option<String> = None;
            let mut retrieved_from_storage = false;
            let mut chunk_opt = None;

            if !candidate_peers.is_empty() {
                use sha3::{Digest, Sha3_256};
                let mut hasher = Sha3_256::new();
                hasher.update(&blob_id.hash);
                hasher.update(&round_number.to_le_bytes());
                hasher.update(&chunk_index.to_le_bytes());
                let peer_seed: [u8; 32] = hasher.finalize().into();
                let mut rng = StdRng::from_seed(peer_seed);
                if let Some(peer) = candidate_peers.choose(&mut rng).cloned() {
                    if let Some(chunk) = self.network.fetch_chunk(&peer, blob_id, chunk_index).await
                    {
                        selected_peer = Some(peer);
                        chunk_opt = Some(chunk);
                    } else {
                        selected_peer = Some(peer);
                    }
                }
            }

            if chunk_opt.is_none() {
                if let Ok(chunk) = storage.get_chunk(blob_id, chunk_index).await {
                    chunk_opt = Some(chunk);
                    retrieved_from_storage = true;
                }
            }

            let elapsed = start_time.elapsed().as_millis() as u64;
            let reported_source = selected_peer.clone().or_else(|| {
                if retrieved_from_storage {
                    Some("local-storage".to_string())
                } else {
                    None
                }
            });

            let sample_result = if let Some(chunk) = chunk_opt {
                let chunk_hash = self.calculate_chunk_hash(&chunk.data);
                SampleResult {
                    chunk_index,
                    is_available: true,
                    chunk_hash: Some(chunk_hash),
                    verification_time_ms: elapsed,
                    source_peer: reported_source,
                }
            } else {
                SampleResult {
                    chunk_index,
                    is_available: false,
                    chunk_hash: None,
                    verification_time_ms: elapsed,
                    source_peer: reported_source,
                }
            };

            samples.push(sample_result);
        }

        let available_count = samples.iter().filter(|s| s.is_available).count();
        let availability_ratio = available_count as f64 / samples.len() as f64;
        let confidence_level = self.calculate_confidence(samples.len(), availability_ratio);

        Ok(SamplingRound {
            round_number,
            samples,
            availability_ratio,
            confidence_level,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Calcular nivel de confianza estadística
    fn calculate_confidence(&self, sample_size: usize, success_ratio: f64) -> f64 {
        if sample_size == 0 {
            return 0.0;
        }

        // Usar aproximación de intervalo de confianza binomial
        let z = 1.96; // Para 95% confianza
        let p = success_ratio;
        let n = sample_size as f64;

        if n < 30.0 {
            // Para muestras pequeñas, reducir confianza
            return (n / 30.0) * 0.95;
        }

        let margin_error = z * ((p * (1.0 - p)) / n).sqrt();
        let lower_bound = (p - margin_error).max(0.0);

        // La confianza es la probabilidad de que el verdadero ratio esté por encima del threshold
        if lower_bound >= 0.75 {
            0.95
        } else {
            (lower_bound / 0.75).min(0.95)
        }
    }

    /// Generar prueba de disponibilidad
    async fn generate_availability_proof(
        &self,
        blob_id: &DataBlobId,
        rounds: &[SamplingRound],
    ) -> Result<Option<AvailabilityProof>, AvoError> {
        if rounds.is_empty() {
            return Ok(None);
        }

        // Recopilar hashes de chunks disponibles
        let mut chunk_hashes = Vec::new();
        let mut chunk_indices = Vec::new();

        for round in rounds {
            for sample in &round.samples {
                if sample.is_available {
                    if let Some(hash) = sample.chunk_hash {
                        chunk_hashes.push(hash);
                        chunk_indices.push(sample.chunk_index);
                    }
                }
            }
        }

        if chunk_hashes.is_empty() {
            return Ok(None);
        }

        // Crear Merkle tree de los hashes
        let merkle_root = self.build_merkle_root(&chunk_hashes);

        // Generar path de prueba (simplificado)
        let proof_path = self.generate_merkle_proof(&chunk_hashes, 0);

        Ok(Some(AvailabilityProof {
            blob_id: blob_id.clone(),
            merkle_root,
            proof: proof_path,
            chunk_indices,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }))
    }

    /// Construir Merkle root de chunk hashes
    fn build_merkle_root(&self, hashes: &[[u8; 32]]) -> [u8; 32] {
        if hashes.is_empty() {
            return [0u8; 32];
        }

        if hashes.len() == 1 {
            return hashes[0];
        }

        // Construcción simplificada de Merkle tree
        let mut current_level = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    self.hash_pair(&chunk[0], &chunk[1])
                } else {
                    chunk[0] // Nodo impar
                };
                next_level.push(combined);
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Generar prueba Merkle para un índice específico
    fn generate_merkle_proof(&self, hashes: &[[u8; 32]], _index: usize) -> Vec<[u8; 32]> {
        // Implementación simplificada - en producción sería más robusta
        if hashes.len() < 2 {
            return vec![];
        }

        vec![hashes[1]] // Prueba simplificada
    }

    /// Hash de un par de nodos
    fn hash_pair(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(a);
        hasher.update(b);
        hasher.finalize().into()
    }

    /// Calcular hash de chunk data
    fn calculate_chunk_hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Verificar una prueba de disponibilidad
    pub fn verify_availability_proof(&self, proof: &AvailabilityProof) -> Result<bool, AvoError> {
        if proof.chunk_indices.is_empty() || proof.proof.is_empty() {
            return Ok(false);
        }

        // Verificación simplificada - en producción sería más robusta
        let has_valid_merkle_root = !proof.merkle_root.iter().all(|&x| x == 0);
        let has_recent_timestamp = proof.timestamp > 0;

        Ok(has_valid_merkle_root && has_recent_timestamp)
    }

    /// Generar prueba de fraude si se detecta indisponibilidad
    pub async fn generate_fraud_proof(
        &mut self,
        blob_id: &DataBlobId,
        claimed_available: bool,
        storage: &mut BlobStorage,
    ) -> Result<Option<AvailabilityProof>, AvoError> {
        tracing::warn!(
            "🚨 Generating fraud proof for blob: {}",
            blob_id
                .hash
                .iter()
                .take(4)
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        // Realizar sampling extensivo para prueba de fraude
        let blob_info = storage.get_blob_info(blob_id).await?;
        let sample_count = self.config.fraud_proof_samples;

        let mut sampler = DeterministicSampler::new(blob_id, 999); // Ronda especial para fraude
        let sample_indices = sampler.sample_indices(blob_info.total_chunks, sample_count);

        let mut available_count = 0;
        let mut chunk_hashes = Vec::new();

        for chunk_index in &sample_indices {
            if let Ok(chunk) = storage.get_chunk(blob_id, *chunk_index).await {
                available_count += 1;
                let hash = self.calculate_chunk_hash(&chunk.data);
                chunk_hashes.push(hash);
            }
        }

        let actual_availability = available_count as f64 / sample_indices.len() as f64;
        let is_fraud = (claimed_available && actual_availability < 0.5)
            || (!claimed_available && actual_availability > 0.9);

        if is_fraud {
            let merkle_root = self.build_merkle_root(&chunk_hashes);
            let proof_path = self.generate_merkle_proof(&chunk_hashes, 0);

            let fraud_proof = AvailabilityProof {
                blob_id: blob_id.clone(),
                merkle_root,
                proof: proof_path,
                chunk_indices: sample_indices,
                timestamp: chrono::Utc::now().timestamp() as u64,
            };

            self.fraud_proofs
                .entry(blob_id.clone())
                .or_insert_with(Vec::new)
                .push(fraud_proof.clone());

            tracing::error!(
                "🚨 FRAUD DETECTED: Claimed {}, actual {:.1}%",
                if claimed_available {
                    "available"
                } else {
                    "unavailable"
                },
                actual_availability * 100.0
            );

            Ok(Some(fraud_proof))
        } else {
            Ok(None)
        }
    }

    /// Obtener historial de sampling para un blob
    pub fn get_sampling_history(&self, blob_id: &DataBlobId) -> Option<&Vec<SamplingResult>> {
        self.sampling_history.get(blob_id)
    }

    /// Obtener estadísticas del sampler
    pub fn get_statistics(&self) -> SamplingStatistics {
        let total_blobs_sampled = self.sampling_history.len();
        let total_fraud_proofs = self.fraud_proofs.values().map(|v| v.len()).sum();

        let mut total_confidence = 0.0;
        let mut total_availability = 0.0;
        let mut sample_count = 0;

        for results in self.sampling_history.values() {
            for result in results {
                total_confidence += result.confidence_level;
                total_availability += result.final_availability_ratio;
                sample_count += 1;
            }
        }

        let avg_confidence = if sample_count > 0 {
            total_confidence / sample_count as f64
        } else {
            0.0
        };
        let avg_availability = if sample_count > 0 {
            total_availability / sample_count as f64
        } else {
            0.0
        };

        SamplingStatistics {
            total_blobs_sampled,
            total_fraud_proofs,
            average_confidence: avg_confidence,
            average_availability: avg_availability,
            sampling_probability: self.config.sampling_probability,
        }
    }
}

/// Estadísticas del sistema de sampling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingStatistics {
    pub total_blobs_sampled: usize,
    pub total_fraud_proofs: usize,
    pub average_confidence: f64,
    pub average_availability: f64,
    pub sampling_probability: f64,
}

#[cfg(all(test, feature = "run-tests"))]
mod tests {
    use super::*;
    use crate::data_availability::blob_storage::StorageConfig;
    use crate::data_availability::DataBlob;
    use tempfile::tempdir;

    #[test]
    fn test_deterministic_sampler() {
        let blob_id = DataBlobId([1u8; 32]);
        let mut sampler1 = DeterministicSampler::new(&blob_id, 0);
        let mut sampler2 = DeterministicSampler::new(&blob_id, 0);

        let indices1 = sampler1.sample_indices(100, 10);
        let indices2 = sampler2.sample_indices(100, 10);

        let mut sorted1 = indices1.clone();
        sorted1.sort_unstable();
        let mut sorted2 = indices2.clone();
        sorted2.sort_unstable();

        assert_eq!(sorted1, sorted2); // Debe ser determinístico en contenido
    }

    #[test]
    fn test_confidence_calculation() {
        let sampler = DataSampler::new(0.1, 0.95, DistributedChunkStore::new());

        // Con muchas muestras y alta disponibilidad
        let confidence = sampler.calculate_confidence(100, 0.9);
        assert!(confidence > 0.8);

        // Con pocas muestras
        let confidence = sampler.calculate_confidence(5, 0.9);
        assert!(confidence < 0.5);
    }

    #[test]
    fn test_merkle_root_calculation() {
        let sampler = DataSampler::new(0.1, 0.95, DistributedChunkStore::new());
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let root = sampler.build_merkle_root(&hashes);
        assert_ne!(root, [0u8; 32]); // Debe generar un root válido
    }

    #[tokio::test]
    async fn test_multi_peer_sampling() {
        let store = DistributedChunkStore::new();
        let local_peer = "node-local".to_string();
        let replica_peer = "replica-1".to_string();

        store.register_peer(local_peer.clone()).await;
        store.register_peer(replica_peer.clone()).await;

        let temp_dir = tempdir().expect("temp dir");
        let storage_config = StorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let mut storage = BlobStorage::new(storage_config).await.expect("storage");

        let data = vec![7u8; 512];
        let blob = DataBlob::new(data, 128);
        storage.store_blob(&blob).await.expect("store blob");

        store
            .publish_chunks(&local_peer, &blob.id, &blob.chunks)
            .await;
        for chunk in blob.chunks.iter().step_by(2) {
            store.publish_chunk(&replica_peer, &blob.id, chunk).await;
        }

        let mut sampler = DataSampler::new(0.5, 0.7, store.clone());
        let result = sampler
            .sample_availability(&blob.id, &mut storage)
            .await
            .expect("sampling");

        assert!(result.is_available);
        assert!(result
            .rounds
            .iter()
            .flat_map(|round| round.samples.iter())
            .any(|sample| sample
                .source_peer
                .as_deref()
                .map(|peer| peer == replica_peer)
                .unwrap_or(false)));
    }
}
