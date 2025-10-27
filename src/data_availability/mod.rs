//! # Data Availability Layer
//!
//! Implementación completa del Data Availability Layer del protocolo AVO.
//! Incluye Reed-Solomon erasure coding, KZG commitments, sampling probabilístico,
//! y sistema de almacenamiento eficiente para blobs de datos.

use self::network::{DistributedChunkStore, PeerId};
use crate::error::AvoError;
use crate::types::{BlockId, Hash, TransactionId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub mod blob_storage;
pub mod erasure_coding;
pub mod kzg_commitments;
pub mod network;
pub mod p2p_network; // FASE 11.1: Real P2P network with libp2p
pub mod sampling;

// Re-exports para facilitar el uso
pub use blob_storage::{BlobStorage, StorageConfig};
pub use erasure_coding::ReedSolomonCoder;
pub use kzg_commitments::{KZGCommitment, KZGCommitmentSystem, KZGProof, KzgVerifier}; // FASE 11.1: Export KZG types
pub use p2p_network::{DasNetworkConfig, DasNetworkEvent, DasP2PNetwork}; // FASE 11.1
pub use sampling::{DataSampler, SamplingResult};

/// Identificador único para un data blob
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataBlobId {
    pub hash: Hash,
    pub shard_id: u64, // FASE 11.1: Shard ID for P2P topic routing
}

impl DataBlobId {
    pub fn new(shard_id: u64, data: &[u8]) -> Self {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&shard_id.to_le_bytes());
        hasher.update(data);
        let result = hasher.finalize();
        Self {
            hash: result.into(),
            shard_id,
        }
    }

    pub fn from_hex(shard_id: u64, hex_str: &str) -> Result<Self, AvoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| AvoError::data_availability(format!("Invalid hex string: {}", e)))?;

        if bytes.len() != 32 {
            return Err(AvoError::data_availability(
                "Hash must be 32 bytes".to_string(),
            ));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Self { hash, shard_id })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

impl std::fmt::Display for DataBlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.shard_id, hex::encode(&self.hash[..8]))
    }
}

/// Chunk individual de datos dentro de un blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataChunk {
    pub index: usize,
    pub data: Vec<u8>,
}

impl DataChunk {
    pub fn new(index: usize, data: Vec<u8>) -> Self {
        Self { index, data }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.index.to_le_bytes());
        hasher.update(&self.data);
        hasher.finalize().into()
    }
}

/// Data blob que contiene chunks de datos para disponibilidad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBlob {
    pub id: DataBlobId,
    pub chunks: Vec<DataChunk>,
}

impl DataBlob {
    pub fn new(shard_id: u64, data: Vec<u8>, chunk_size: usize) -> Self {
        let id = DataBlobId::new(shard_id, &data);
        let chunks = Self::split_into_chunks(data, chunk_size);
        Self { id, chunks }
    }

    pub fn from_chunks(shard_id: u64, chunks: Vec<DataChunk>) -> Self {
        // Reconstruir datos para calcular ID
        let mut full_data = Vec::new();
        for chunk in &chunks {
            full_data.extend_from_slice(&chunk.data);
        }

        let id = DataBlobId::new(shard_id, &full_data);
        Self { id, chunks }
    }

    pub fn total_size(&self) -> usize {
        self.chunks.iter().map(|c| c.data.len()).sum()
    }

    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    pub fn reconstruct_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.total_size());
        for chunk in &self.chunks {
            data.extend_from_slice(&chunk.data);
        }
        data
    }

    fn split_into_chunks(data: Vec<u8>, chunk_size: usize) -> Vec<DataChunk> {
        if chunk_size == 0 {
            return vec![];
        }

        data.chunks(chunk_size)
            .enumerate()
            .map(|(index, chunk_data)| DataChunk::new(index, chunk_data.to_vec()))
            .collect()
    }
}

/// Prueba de disponibilidad para un blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityProof {
    pub blob_id: DataBlobId,
    pub merkle_root: [u8; 32],
    pub proof: Vec<[u8; 32]>,      // Merkle proof path
    pub chunk_indices: Vec<usize>, // Índices de chunks verificados
    pub timestamp: u64,
}

impl AvailabilityProof {
    pub fn new(
        blob_id: DataBlobId,
        merkle_root: [u8; 32],
        proof: Vec<[u8; 32]>,
        chunk_indices: Vec<usize>,
    ) -> Self {
        Self {
            blob_id,
            merkle_root,
            proof,
            chunk_indices,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.proof.is_empty() && !self.chunk_indices.is_empty()
    }

    pub fn age_seconds(&self) -> u64 {
        let now = chrono::Utc::now().timestamp() as u64;
        now.saturating_sub(self.timestamp)
    }
}

/// Configuración del Data Availability Layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAvailabilityConfig {
    pub chunk_size: usize,             // Tamaño de chunk en bytes
    pub erasure_coding_ratio: f64,     // Ratio de redundancia para erasure coding
    pub sampling_probability: f64,     // Probabilidad de sampling por chunk
    pub confidence_threshold: f64,     // Umbral de confianza para disponibilidad
    pub kzg_ceremony_size: usize,      // Tamaño de la ceremonia KZG
    pub storage_config: StorageConfig, // Configuración de almacenamiento
    pub max_blob_size: usize,          // Tamaño máximo de blob
    pub proof_validity_hours: u64,     // Validez de las pruebas en horas
}

impl Default for DataAvailabilityConfig {
    fn default() -> Self {
        Self {
            chunk_size: 512 * 1024,     // 512KB por chunk
            erasure_coding_ratio: 0.5,  // 50% redundancia
            sampling_probability: 0.1,  // 10% sampling
            confidence_threshold: 0.95, // 95% confianza
            kzg_ceremony_size: 65536,   // 64K puntos para soportar blobs grandes
            storage_config: StorageConfig::default(),
            max_blob_size: 32 * 1024 * 1024, // 32MB máximo
            proof_validity_hours: 24,        // 24 horas validez
        }
    }
}

/// Administrador principal del Data Availability Layer
#[derive(Debug)]
pub struct DataAvailabilityManager {
    config: DataAvailabilityConfig,
    erasure_coder: ReedSolomonCoder,
    kzg_system: KZGCommitmentSystem,
    data_sampler: DataSampler,
    blob_storage: BlobStorage,
    availability_cache: HashMap<DataBlobId, AvailabilityProof>,
    distributed_store: DistributedChunkStore,
    local_peer_id: PeerId,
    replication_targets: Vec<PeerId>,
}

impl DataAvailabilityManager {
    #[cfg(test)]
    pub(crate) fn distributed_store(&self) -> DistributedChunkStore {
        self.distributed_store.clone()
    }

    #[cfg(test)]
    pub(crate) fn replication_targets(&self) -> &[PeerId] {
        &self.replication_targets
    }

    /// Crear nuevo manager de disponibilidad de datos
    pub async fn new(config: DataAvailabilityConfig) -> Result<Self, AvoError> {
        let data_chunks = (config.erasure_coding_ratio * 2.0) as usize;
        let parity_chunks = data_chunks;

        let erasure_coder = ReedSolomonCoder::new(config.erasure_coding_ratio, config.chunk_size)?;
        let distributed_store = DistributedChunkStore::new();
        let local_peer_id = format!("node-{}", Uuid::new_v4().simple());
        distributed_store.register_peer(local_peer_id.clone()).await;

        let replication_factor = config.storage_config.redundancy_copies.max(1);
        let mut replication_targets = Vec::with_capacity(replication_factor);
        for idx in 0..replication_factor {
            let peer_id = format!("replica-{}", idx + 1);
            distributed_store.register_peer(peer_id.clone()).await;
            replication_targets.push(peer_id);
        }

        let kzg_system = KZGCommitmentSystem::new(config.kzg_ceremony_size)?;
        let data_sampler = DataSampler::new(
            config.sampling_probability,
            config.confidence_threshold,
            distributed_store.clone(),
        );
        let blob_storage = BlobStorage::new(config.storage_config.clone()).await?;

        tracing::info!("🚀 Data Availability Layer initialized");
        tracing::info!("  📦 Chunk size: {} KB", config.chunk_size / 1024);
        tracing::info!(
            "  🔄 Erasure coding: {:.1}% redundancy",
            config.erasure_coding_ratio * 100.0
        );
        tracing::info!(
            "  🎲 Sampling: {:.1}% probability",
            config.sampling_probability * 100.0
        );
        tracing::info!("  🔐 KZG ceremony: {} points", config.kzg_ceremony_size);

        Ok(Self {
            config,
            erasure_coder,
            kzg_system,
            data_sampler,
            blob_storage,
            availability_cache: HashMap::new(),
            distributed_store,
            local_peer_id,
            replication_targets,
        })
    }

    /// Publicar datos para disponibilidad
    pub async fn publish_data(
        &mut self,
        shard_id: u64,
        data: Vec<u8>,
    ) -> Result<DataBlobId, AvoError> {
        if data.len() > self.config.max_blob_size {
            return Err(AvoError::data_availability(format!(
                "Data size {} exceeds maximum {}",
                data.len(),
                self.config.max_blob_size
            )));
        }

        tracing::debug!("📤 Publishing data: {} bytes", data.len());

        // 1. Crear blob con chunks
        let blob = DataBlob::new(shard_id, data, self.config.chunk_size);
        let blob_id = blob.id.clone();

        // 2. Aplicar erasure coding para redundancia
        let encoded_chunks = self.apply_erasure_coding(&blob).await?;
        let mut encoded_blob = DataBlob::from_chunks(shard_id, encoded_chunks);

        // IMPORTANTE: Mantener el mismo ID del blob original
        encoded_blob.id = blob_id.clone();

        // 3. Generar KZG commitment
        let _commitment = self.generate_kzg_commitment(&encoded_blob).await?;
        tracing::debug!("🔐 Generated KZG commitment for blob");

        // 4. Almacenar blob
        let _storage_info = self.blob_storage.store_blob(&encoded_blob).await?;

        // 5. Publicar shards a la red distribuida
        self.distributed_store
            .publish_chunks(&self.local_peer_id, &blob_id, &encoded_blob.chunks)
            .await;

        if !self.replication_targets.is_empty() {
            for (idx, chunk) in encoded_blob.chunks.iter().enumerate() {
                let peer_id = &self.replication_targets[idx % self.replication_targets.len()];
                self.distributed_store
                    .publish_chunk(peer_id, &blob_id, chunk)
                    .await;
            }
        }

        // 6. Generar prueba inicial de disponibilidad
        let availability_proof = self.generate_initial_proof(&encoded_blob)?;
        self.availability_cache
            .insert(blob_id.clone(), availability_proof);

        tracing::info!(
            "✅ Data published with blob ID: {}",
            blob_id.to_hex()[..8].to_string()
        );

        Ok(blob_id)
    }

    /// Verificar disponibilidad de datos
    pub async fn verify_availability(&mut self, blob_id: &DataBlobId) -> Result<bool, AvoError> {
        tracing::debug!(
            "🔍 Verifying availability for blob: {}",
            blob_id.to_hex()[..8].to_string()
        );

        // 1. Verificar si tenemos prueba en caché
        if let Some(cached_proof) = self.availability_cache.get(blob_id) {
            if cached_proof.age_seconds() < self.config.proof_validity_hours * 3600 {
                return Ok(cached_proof.is_valid());
            }
        }

        // 2. Realizar sampling de disponibilidad
        let sampling_result = self
            .data_sampler
            .sample_availability(blob_id, &mut self.blob_storage)
            .await?;

        // 3. Actualizar caché si hay nueva prueba
        if let Some(proof) = sampling_result.proof {
            self.availability_cache.insert(blob_id.clone(), proof);
        }

        tracing::info!(
            "📊 Availability verified: {:.1}% confidence",
            sampling_result.confidence_level * 100.0
        );

        Ok(sampling_result.is_available)
    }

    /// Recuperar datos por ID
    pub async fn retrieve_data(&mut self, blob_id: &DataBlobId) -> Result<Vec<u8>, AvoError> {
        tracing::debug!(
            "📥 Retrieving data for blob: {}",
            blob_id.to_hex()[..8].to_string()
        );

        // 1. Verificar disponibilidad primero
        if !self.verify_availability(blob_id).await? {
            return Err(AvoError::data_availability(
                "Data not available".to_string(),
            ));
        }

        // 2. Recuperar blob desde storage
        let encoded_blob = self.blob_storage.get_blob(blob_id).await?;

        // 3. Aplicar decodificación de erasure coding
        let original_chunks = self.decode_erasure_coding(&encoded_blob).await?;
        let original_blob = DataBlob::from_chunks(blob_id.shard_id, original_chunks);

        // 4. Reconstruir datos originales
        let data = original_blob.reconstruct_data();

        tracing::info!("✅ Data retrieved: {} bytes", data.len());

        Ok(data)
    }

    /// Aplicar erasure coding a un blob
    async fn apply_erasure_coding(&self, blob: &DataBlob) -> Result<Vec<DataChunk>, AvoError> {
        let mut encoded_chunks = Vec::new();

        tracing::debug!("🧮 Applying erasure coding to {} chunks", blob.chunks.len());

        for chunk in &blob.chunks {
            if chunk.data.is_empty() {
                tracing::warn!("⚠️ Empty chunk {} skipped", chunk.index);
                continue;
            }

            tracing::debug!(
                "🔧 Encoding chunk {} ({} bytes)",
                chunk.index,
                chunk.data.len()
            );
            let encoded_data = self.erasure_coder.encode(&chunk.data)?;

            // Crear chunks tanto para datos como paridad
            for (i, shard) in encoded_data.iter().enumerate() {
                let encoded_chunk =
                    DataChunk::new(chunk.index * encoded_data.len() + i, shard.clone());
                encoded_chunks.push(encoded_chunk);
            }

            tracing::debug!(
                "✅ Chunk {} encoded into {} shards",
                chunk.index,
                encoded_data.len()
            );
        }

        tracing::debug!(
            "✅ Erasure coding complete: {} total encoded chunks",
            encoded_chunks.len()
        );

        Ok(encoded_chunks)
    }

    /// Decodificar erasure coding de un blob
    async fn decode_erasure_coding(
        &mut self,
        encoded_blob: &DataBlob,
    ) -> Result<Vec<DataChunk>, AvoError> {
        let shards_per_chunk =
            self.erasure_coder.data_shards() + self.erasure_coder.parity_shards();

        let mut chunk_groups: HashMap<usize, Vec<Option<Vec<u8>>>> = HashMap::new();

        for chunk in &encoded_blob.chunks {
            let original_chunk_index = chunk.index / shards_per_chunk;
            let shard_index = chunk.index % shards_per_chunk;

            let entry = chunk_groups
                .entry(original_chunk_index)
                .or_insert_with(|| vec![None; shards_per_chunk]);

            if entry.len() <= shard_index {
                entry.resize(shards_per_chunk, None);
            }

            entry[shard_index] = Some(chunk.data.clone());
        }

        let mut decoded_chunks = Vec::with_capacity(chunk_groups.len());
        let mut chunk_entries: Vec<(usize, Vec<Option<Vec<u8>>>)> =
            chunk_groups.into_iter().collect();
        chunk_entries.sort_by_key(|(index, _)| *index);

        for (chunk_index, shards) in chunk_entries {
            let available = shards.iter().filter(|s| s.is_some()).count();

            if available < self.erasure_coder.data_shards() {
                return Err(AvoError::data_availability(format!(
                    "Insufficient shards for chunk {}: got {}, need {}",
                    chunk_index,
                    available,
                    self.erasure_coder.data_shards()
                )));
            }

            tracing::debug!(
                "🔧 Decoding chunk {} with {} shards",
                chunk_index,
                available
            );

            let decoded_data = self.erasure_coder.decode(shards)?;
            decoded_chunks.push(DataChunk::new(chunk_index, decoded_data));
        }

        tracing::debug!("✅ Decoded {} chunks successfully", decoded_chunks.len());

        Ok(decoded_chunks)
    }

    /// Generar KZG commitment para un blob
    async fn generate_kzg_commitment(
        &mut self,
        blob: &DataBlob,
    ) -> Result<KZGCommitment, AvoError> {
        let mut flattened = Vec::new();
        for chunk in &blob.chunks {
            flattened.extend_from_slice(&chunk.data);
        }

        self.kzg_system.commit(&flattened)
    }

    /// Generar prueba inicial de disponibilidad a partir de los shards publicados
    fn generate_initial_proof(&self, blob: &DataBlob) -> Result<AvailabilityProof, AvoError> {
        if blob.chunks.is_empty() {
            return Err(AvoError::data_availability(
                "Cannot build availability proof for empty blob".to_string(),
            ));
        }

        let chunk_hashes: Vec<[u8; 32]> = blob
            .chunks
            .iter()
            .map(|chunk| Self::hash_chunk(&chunk.data))
            .collect();

        let merkle_root = Self::build_merkle_root(&chunk_hashes);
        let merkle_proof = Self::generate_merkle_proof(&chunk_hashes, 0);
        let chunk_indices: Vec<usize> = blob.chunks.iter().map(|chunk| chunk.index).collect();

        Ok(AvailabilityProof::new(
            blob.id.clone(),
            merkle_root,
            merkle_proof,
            chunk_indices,
        ))
    }

    fn hash_chunk(data: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    fn build_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }

        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current = leaves.to_vec();
        while current.len() > 1 {
            let mut next = Vec::new();
            for pair in current.chunks(2) {
                let combined = if pair.len() == 2 {
                    Self::hash_pair(&pair[0], &pair[1])
                } else {
                    pair[0]
                };
                next.push(combined);
            }
            current = next;
        }

        current[0]
    }

    fn generate_merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
        if leaves.len() < 2 || index >= leaves.len() {
            return vec![];
        }

        // Simplified proof: include sibling of the target leaf at the first level.
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        if sibling_index < leaves.len() {
            vec![leaves[sibling_index]]
        } else {
            vec![]
        }
    }

    /// Obtener estadísticas del sistema
    pub fn get_statistics(&self) -> DataAvailabilityStatistics {
        let storage_stats = self.blob_storage.get_statistics();
        let sampling_stats = self.data_sampler.get_statistics();

        DataAvailabilityStatistics {
            total_blobs: storage_stats.total_blobs,
            total_size_bytes: storage_stats.total_size_bytes,
            average_compression_ratio: storage_stats.average_compression_ratio,
            total_blobs_sampled: sampling_stats.total_blobs_sampled,
            average_confidence: sampling_stats.average_confidence,
            cached_proofs: self.availability_cache.len(),
        }
    }
}

/// Estadísticas del sistema de disponibilidad de datos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAvailabilityStatistics {
    pub total_blobs: usize,
    pub total_size_bytes: usize,
    pub average_compression_ratio: f64,
    pub total_blobs_sampled: usize,
    pub average_confidence: f64,
    pub cached_proofs: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_data_blob_creation() {
        let data = b"test data for blob creation".to_vec();
        let blob = DataBlob::new(0, data.clone(), 10);

        assert_eq!(blob.total_size(), data.len());
        assert_eq!(blob.reconstruct_data(), data);
    }

    #[test]
    fn test_data_blob_id() {
        let data1 = b"test data 1".to_vec();
        let data2 = b"test data 2".to_vec();

        let id1 = DataBlobId::new(0, &data1);
        let id2 = DataBlobId::new(0, &data2);
        let id1_duplicate = DataBlobId::new(0, &data1);

        assert_ne!(id1, id2);
        assert_eq!(id1, id1_duplicate);
    }

    #[tokio::test]
    async fn publish_and_verify_distributed() {
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let mut config = DataAvailabilityConfig::default();
        config.chunk_size = 128;
        config.erasure_coding_ratio = 0.5;
        config.sampling_probability = 0.5;
        config.confidence_threshold = 0.8;
        config.kzg_ceremony_size = 8192;
        config.storage_config = StorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            redundancy_copies: 2,
            ..Default::default()
        };
        config.max_blob_size = 2 * 1024 * 1024;
        config.proof_validity_hours = 1;

        let data = vec![42u8; 2048];

        let mut manager = DataAvailabilityManager::new(config).await.expect("manager");

        let blob_id = manager
            .publish_data(0, data.clone())
            .await
            .expect("publish data");

        let store = manager.distributed_store();
        let peers = store.peers().await;
        assert!(peers.len() >= 3); // nodo local + réplicas

        let providers = store.peers_with_chunk(&blob_id, 0).await;
        assert!(providers.len() >= 2);

        let replica_set: HashSet<_> = manager.replication_targets().iter().cloned().collect();
        let remote_hits = providers
            .iter()
            .filter(|peer| replica_set.contains(*peer))
            .count();
        assert!(remote_hits >= 1);

        let available = manager
            .verify_availability(&blob_id)
            .await
            .expect("verify availability");
        assert!(available);

        let recovered = manager
            .retrieve_data(&blob_id)
            .await
            .expect("retrieve data");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_availability_proof() {
        let blob_id = DataBlobId::new(0, b"test");
        let proof = AvailabilityProof::new(blob_id, [1u8; 32], vec![[2u8; 32]], vec![0, 1, 2]);

        assert!(proof.is_valid());
        assert!(proof.age_seconds() < 5); // Recién creado
    }
}
