//! # Blob Storage System
//!
//! Sistema de almacenamiento eficiente para blobs de datos con
//! indexación, compresión y gestión de metadatos.

use crate::data_availability::{DataBlob, DataBlobId, DataChunk};
use crate::error::AvoError;
use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

/// Información de un blob almacenado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobInfo {
    pub blob_id: DataBlobId,
    pub total_size: usize,
    pub total_chunks: usize,
    pub chunk_size: usize,
    pub creation_timestamp: u64,
    pub last_access_timestamp: u64,
    pub compression_ratio: f64,
    pub erasure_coding_ratio: f64,
    pub file_path: PathBuf,
    pub chunk_offsets: Vec<u64>, // Offsets de cada chunk en el archivo
    pub chunk_sizes: Vec<u32>,   // Tamaños comprimidos de cada chunk
    pub merkle_root: [u8; 32],
}

/// Configuración del sistema de almacenamiento
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub base_path: PathBuf,
    pub max_file_size: u64,       // Tamaño máximo por archivo
    pub enable_compression: bool, // Habilitar compresión LZ4
    pub compression_level: i32,   // Nivel de compresión (1-9)
    pub cache_size_mb: usize,     // Tamaño de caché en MB
    pub auto_cleanup_hours: u64,  // Limpieza automática después de N horas
    pub redundancy_copies: usize, // Número de copias redundantes
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("./data"),
            max_file_size: 1024 * 1024 * 1024, // 1GB
            enable_compression: true,
            compression_level: 4,
            cache_size_mb: 256,
            auto_cleanup_hours: 24,
            redundancy_copies: 2,
        }
    }
}

/// Caché en memoria para chunks frecuentemente accedidos
#[derive(Debug)]
struct ChunkCache {
    entries: HashMap<(DataBlobId, usize), CacheEntry>,
    max_size_bytes: usize,
    current_size_bytes: usize,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    chunk: DataChunk,
    last_access: u64,
    access_count: usize,
    compressed_size: usize,
}

impl ChunkCache {
    fn new(max_size_mb: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size_bytes: max_size_mb * 1024 * 1024,
            current_size_bytes: 0,
        }
    }

    fn get(&mut self, blob_id: &DataBlobId, chunk_index: usize) -> Option<DataChunk> {
        let key = (blob_id.clone(), chunk_index);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_access = chrono::Utc::now().timestamp() as u64;
            entry.access_count += 1;
            return Some(entry.chunk.clone());
        }
        None
    }

    fn put(
        &mut self,
        blob_id: DataBlobId,
        chunk_index: usize,
        chunk: DataChunk,
        compressed_size: usize,
    ) {
        if compressed_size > self.max_size_bytes {
            return;
        }

        let key = (blob_id, chunk_index);
        let entry = CacheEntry {
            chunk: chunk.clone(),
            last_access: chrono::Utc::now().timestamp() as u64,
            access_count: 1,
            compressed_size,
        };

        // Evitar chunks si excedemos el tamaño máximo
        while self.current_size_bytes + compressed_size > self.max_size_bytes {
            self.evict_lru();
        }

        if let Some(old_entry) = self.entries.insert(key, entry) {
            self.current_size_bytes = self
                .current_size_bytes
                .saturating_sub(old_entry.compressed_size)
                .saturating_add(compressed_size);
        } else {
            self.current_size_bytes += compressed_size;
        }
    }

    fn evict_lru(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        // Encontrar entrada menos recientemente usada
        let lru_key = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| (entry.last_access, entry.access_count))
            .map(|(key, _)| key.clone());

        if let Some(key) = lru_key {
            if let Some(entry) = self.entries.remove(&key) {
                self.current_size_bytes = self
                    .current_size_bytes
                    .saturating_sub(entry.compressed_size);
            }
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.current_size_bytes = 0;
    }
}

/// Sistema principal de almacenamiento de blobs
#[derive(Debug)]
pub struct BlobStorage {
    config: StorageConfig,
    blob_index: HashMap<DataBlobId, BlobInfo>,
    cache: ChunkCache,
    index_file_path: PathBuf,
}

impl BlobStorage {
    /// Crear nuevo sistema de almacenamiento
    pub async fn new(config: StorageConfig) -> Result<Self, AvoError> {
        // Crear directorio base si no existe
        fs::create_dir_all(&config.base_path)
            .await
            .map_err(|e| AvoError::state(format!("Failed to create storage directory: {}", e)))?;

        let index_file_path = config.base_path.join("blob_index.json");
        let cache = ChunkCache::new(config.cache_size_mb);

        let mut storage = Self {
            config,
            blob_index: HashMap::new(),
            cache,
            index_file_path,
        };

        // Cargar índice existente
        storage.load_index().await?;

        tracing::info!(
            "💾 Blob Storage initialized: {} blobs indexed",
            storage.blob_index.len()
        );

        Ok(storage)
    }

    /// Almacenar un blob completo
    pub async fn store_blob(&mut self, blob: &DataBlob) -> Result<BlobInfo, AvoError> {
        tracing::debug!(
            "💾 Storing blob: {} ({} chunks)",
            blob.id
                .hash
                .iter()
                .take(4)
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            blob.chunks.len()
        );

        if blob.chunks.is_empty() {
            return Err(AvoError::data_availability(
                "Cannot store empty blob".to_string(),
            ));
        }

        // Crear archivo para el blob
        let blob_filename = format!("{}.blob", hex::encode(&blob.id.hash[..8]));
        let blob_file_path = self.config.base_path.join(&blob_filename);

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&blob_file_path)
            .await
            .map_err(|e| {
                AvoError::data_availability(format!("Failed to create blob file: {}", e))
            })?;

        let mut chunk_offsets = Vec::new();
        let mut chunk_sizes = Vec::new();
        let mut total_compressed_size = 0u64;
        let mut chunk_hashes = Vec::new();

        // Escribir chunks con compresión
        for (index, chunk) in blob.chunks.iter().enumerate() {
            let offset = file.stream_position().await.map_err(|e| {
                AvoError::data_availability(format!("Failed to get file position: {}", e))
            })?;
            chunk_offsets.push(offset);

            let compressed_data = if self.config.enable_compression {
                compress_prepend_size(&chunk.data)
            } else {
                chunk.data.clone()
            };

            let compressed_size = compressed_data.len() as u32;
            chunk_sizes.push(compressed_size);
            total_compressed_size += compressed_size as u64;

            // Escribir datos comprimidos
            file.write_all(&compressed_data).await.map_err(|e| {
                AvoError::data_availability(format!("Failed to write chunk {}: {}", index, e))
            })?;

            // Calcular hash del chunk
            let chunk_hash = self.calculate_chunk_hash(&chunk.data);
            chunk_hashes.push(chunk_hash);

            // Agregar al caché
            self.cache.put(
                blob.id.clone(),
                index,
                chunk.clone(),
                compressed_size as usize,
            );
        }

        file.sync_all()
            .await
            .map_err(|e| AvoError::data_availability(format!("Failed to sync blob file: {}", e)))?;

        // Calcular Merkle root
        let merkle_root = self.calculate_merkle_root(&chunk_hashes);

        // Calcular ratio de compresión
        let original_size: usize = blob.chunks.iter().map(|c| c.data.len()).sum();
        let compression_ratio = if original_size > 0 {
            total_compressed_size as f64 / original_size as f64
        } else {
            1.0
        };

        let blob_info = BlobInfo {
            blob_id: blob.id.clone(),
            total_size: original_size,
            total_chunks: blob.chunks.len(),
            chunk_size: if !blob.chunks.is_empty() {
                blob.chunks[0].data.len()
            } else {
                0
            },
            creation_timestamp: chrono::Utc::now().timestamp() as u64,
            last_access_timestamp: chrono::Utc::now().timestamp() as u64,
            compression_ratio,
            erasure_coding_ratio: 1.0, // TODO: Calcular desde erasure coding
            file_path: blob_file_path,
            chunk_offsets,
            chunk_sizes,
            merkle_root,
        };

        // Actualizar índice
        self.blob_index.insert(blob.id.clone(), blob_info.clone());
        self.save_index().await?;

        tracing::info!(
            "✅ Blob stored: {:.1}% compression, {} MB",
            (1.0 - compression_ratio) * 100.0,
            total_compressed_size / 1024 / 1024
        );

        Ok(blob_info)
    }

    /// Recuperar un blob completo
    pub async fn get_blob(&mut self, blob_id: &DataBlobId) -> Result<DataBlob, AvoError> {
        let blob_info = self
            .blob_index
            .get(blob_id)
            .ok_or_else(|| AvoError::data_availability(format!("Blob not found: {:?}", blob_id)))?
            .clone();

        tracing::debug!(
            "📖 Loading blob: {} ({} chunks)",
            blob_id
                .hash
                .iter()
                .take(4)
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            blob_info.total_chunks
        );

        let mut chunks = Vec::with_capacity(blob_info.total_chunks);

        // Cargar todos los chunks
        for chunk_index in 0..blob_info.total_chunks {
            let chunk = self.get_chunk(blob_id, chunk_index).await?;
            chunks.push(chunk);
        }

        // Actualizar timestamp de acceso
        self.update_access_timestamp(blob_id).await?;

        Ok(DataBlob {
            id: blob_id.clone(),
            chunks,
        })
    }

    /// Recuperar un chunk específico
    pub async fn get_chunk(
        &mut self,
        blob_id: &DataBlobId,
        chunk_index: usize,
    ) -> Result<DataChunk, AvoError> {
        // Intentar desde caché primero
        if let Some(cached_chunk) = self.cache.get(blob_id, chunk_index) {
            return Ok(cached_chunk);
        }

        let blob_info = self
            .blob_index
            .get(blob_id)
            .ok_or_else(|| AvoError::data_availability(format!("Blob not found: {:?}", blob_id)))?
            .clone();

        if chunk_index >= blob_info.total_chunks {
            return Err(AvoError::data_availability(format!(
                "Chunk index {} out of bounds (max: {})",
                chunk_index, blob_info.total_chunks
            )));
        }

        // Abrir archivo del blob
        let mut file = File::open(&blob_info.file_path)
            .await
            .map_err(|e| AvoError::data_availability(format!("Failed to open blob file: {}", e)))?;

        // Buscar posición del chunk
        let offset = blob_info.chunk_offsets[chunk_index];
        let size = blob_info.chunk_sizes[chunk_index] as usize;

        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| AvoError::data_availability(format!("Failed to seek to chunk: {}", e)))?;

        // Leer datos comprimidos
        let mut compressed_data = vec![0u8; size];
        file.read_exact(&mut compressed_data).await.map_err(|e| {
            AvoError::data_availability(format!("Failed to read chunk data: {}", e))
        })?;

        // Descomprimir si es necesario
        let chunk_data = if self.config.enable_compression {
            decompress_size_prepended(&compressed_data).map_err(|e| {
                AvoError::data_availability(format!("Failed to decompress chunk: {}", e))
            })?
        } else {
            compressed_data
        };

        let chunk = DataChunk {
            index: chunk_index,
            data: chunk_data,
        };

        // Agregar al caché
        self.cache
            .put(blob_id.clone(), chunk_index, chunk.clone(), size);

        Ok(chunk)
    }

    /// Verificar existencia de un blob
    pub async fn has_blob(&self, blob_id: &DataBlobId) -> bool {
        self.blob_index.contains_key(blob_id)
    }

    /// Verificar existencia de un chunk específico
    pub async fn has_chunk(&self, blob_id: &DataBlobId, chunk_index: usize) -> bool {
        if let Some(blob_info) = self.blob_index.get(blob_id) {
            chunk_index < blob_info.total_chunks
        } else {
            false
        }
    }

    /// Obtener información de un blob
    pub async fn get_blob_info(&self, blob_id: &DataBlobId) -> Result<BlobInfo, AvoError> {
        self.blob_index
            .get(blob_id)
            .cloned()
            .ok_or_else(|| AvoError::data_availability(format!("Blob not found: {:?}", blob_id)))
    }

    /// Eliminar un blob
    pub async fn delete_blob(&mut self, blob_id: &DataBlobId) -> Result<(), AvoError> {
        let blob_info = self
            .blob_index
            .remove(blob_id)
            .ok_or_else(|| AvoError::data_availability(format!("Blob not found: {:?}", blob_id)))?;

        // Eliminar archivo
        if blob_info.file_path.exists() {
            fs::remove_file(&blob_info.file_path).await.map_err(|e| {
                AvoError::data_availability(format!("Failed to delete blob file: {}", e))
            })?;
        }

        // Limpiar caché
        self.cache.entries.retain(|(id, _), _| id != blob_id);

        // Actualizar índice
        self.save_index().await?;

        tracing::info!(
            "🗑️ Blob deleted: {}",
            blob_id
                .hash
                .iter()
                .take(4)
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        Ok(())
    }

    /// Listar todos los blobs
    pub fn list_blobs(&self) -> Vec<DataBlobId> {
        self.blob_index.keys().cloned().collect()
    }

    /// Obtener estadísticas de almacenamiento
    pub fn get_statistics(&self) -> StorageStatistics {
        let total_blobs = self.blob_index.len();
        let total_chunks: usize = self.blob_index.values().map(|info| info.total_chunks).sum();
        let total_size: usize = self.blob_index.values().map(|info| info.total_size).sum();
        let compressed_size: u64 = self
            .blob_index
            .values()
            .map(|info| info.chunk_sizes.iter().map(|&s| s as u64).sum::<u64>())
            .sum();

        let avg_compression_ratio = if total_blobs > 0 {
            self.blob_index
                .values()
                .map(|info| info.compression_ratio)
                .sum::<f64>()
                / total_blobs as f64
        } else {
            1.0
        };

        StorageStatistics {
            total_blobs,
            total_chunks,
            total_size_bytes: total_size,
            compressed_size_bytes: compressed_size,
            average_compression_ratio: avg_compression_ratio,
            cache_hit_ratio: 0.0, // TODO: Implementar tracking de hits/misses
            cache_size_bytes: self.cache.current_size_bytes,
        }
    }

    /// Limpiar blobs antiguos
    pub async fn cleanup_old_blobs(&mut self, max_age_hours: u64) -> Result<usize, AvoError> {
        let cutoff_timestamp = chrono::Utc::now().timestamp() as u64 - (max_age_hours * 3600);
        let mut deleted_count = 0;

        let old_blob_ids: Vec<DataBlobId> = self
            .blob_index
            .iter()
            .filter(|(_, info)| info.last_access_timestamp < cutoff_timestamp)
            .map(|(id, _)| id.clone())
            .collect();

        for blob_id in old_blob_ids {
            self.delete_blob(&blob_id).await?;
            deleted_count += 1;
        }

        if deleted_count > 0 {
            tracing::info!(
                "🧹 Cleaned up {} old blobs (older than {} hours)",
                deleted_count,
                max_age_hours
            );
        }

        Ok(deleted_count)
    }

    /// Cargar índice desde disco
    async fn load_index(&mut self) -> Result<(), AvoError> {
        if !self.index_file_path.exists() {
            return Ok(()); // Archivo de índice no existe aún
        }

        let index_data = fs::read_to_string(&self.index_file_path)
            .await
            .map_err(|e| {
                AvoError::data_availability(format!("Failed to read index file: {}", e))
            })?;

        // Deserializar desde formato string y convertir a HashMap con DataBlobId
        let string_index: HashMap<String, BlobInfo> =
            serde_json::from_str(&index_data).map_err(|e| {
                AvoError::data_availability(format!("Failed to parse index file: {}", e))
            })?;

        // Convertir strings de vuelta a DataBlobId
        self.blob_index = string_index
            .into_iter()
            .map(|(_, v)| (v.blob_id.clone(), v))
            .collect();

        Ok(())
    }

    /// Guardar índice a disco
    async fn save_index(&self) -> Result<(), AvoError> {
        // Convertir el HashMap a uno que use strings como claves
        let string_index: HashMap<String, BlobInfo> = self
            .blob_index
            .iter()
            .map(|(k, v)| (k.to_hex(), v.clone()))
            .collect();

        let index_data = serde_json::to_string_pretty(&string_index).map_err(|e| {
            AvoError::data_availability(format!("Failed to serialize index: {}", e))
        })?;

        fs::write(&self.index_file_path, index_data)
            .await
            .map_err(|e| {
                AvoError::data_availability(format!("Failed to write index file: {}", e))
            })?;

        Ok(())
    }

    /// Actualizar timestamp de acceso
    async fn update_access_timestamp(&mut self, blob_id: &DataBlobId) -> Result<(), AvoError> {
        if let Some(blob_info) = self.blob_index.get_mut(blob_id) {
            blob_info.last_access_timestamp = chrono::Utc::now().timestamp() as u64;
            // Guardar cambios en el índice de forma asíncrona
            // En producción, esto podría ser batch para eficiencia
        }
        Ok(())
    }

    /// Calcular hash de chunk
    fn calculate_chunk_hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Calcular Merkle root de chunk hashes
    fn calculate_merkle_root(&self, hashes: &[[u8; 32]]) -> [u8; 32] {
        if hashes.is_empty() {
            return [0u8; 32];
        }

        if hashes.len() == 1 {
            return hashes[0];
        }

        let mut current_level = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    self.hash_pair(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                };
                next_level.push(combined);
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Hash de un par de nodos
    fn hash_pair(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(a);
        hasher.update(b);
        hasher.finalize().into()
    }
}

/// Estadísticas del sistema de almacenamiento
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatistics {
    pub total_blobs: usize,
    pub total_chunks: usize,
    pub total_size_bytes: usize,
    pub compressed_size_bytes: u64,
    pub average_compression_ratio: f64,
    pub cache_hit_ratio: f64,
    pub cache_size_bytes: usize,
}

#[cfg(all(test, feature = "run-tests"))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_storage() -> (BlobStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            base_path: temp_dir.path().to_path_buf(),
            cache_size_mb: 10,
            ..Default::default()
        };
        let storage = BlobStorage::new(config).await.unwrap();
        (storage, temp_dir)
    }

    #[tokio::test]
    async fn test_store_and_retrieve_blob() {
        let (mut storage, _temp_dir) = create_test_storage().await;

        let blob_id = DataBlobId::new(0, b"test data 1");
        let chunks = vec![
            DataChunk {
                index: 0,
                data: b"chunk 0 data".to_vec(),
            },
            DataChunk {
                index: 1,
                data: b"chunk 1 data".to_vec(),
            },
        ];
        let blob = DataBlob {
            id: blob_id.clone(),
            chunks,
        };

        // Almacenar blob
        let blob_info = storage.store_blob(&blob).await.unwrap();
        assert_eq!(blob_info.total_chunks, 2);
        assert!(
            blob_info.compression_ratio <= 1.5,
            "Compression ratio should stay close to 1.0 even with small-chunk overhead, got {:.3}",
            blob_info.compression_ratio
        );

        // Recuperar blob
        let retrieved_blob = storage.get_blob(&blob_id).await.unwrap();
        assert_eq!(retrieved_blob.chunks.len(), 2);
        assert_eq!(retrieved_blob.chunks[0].data, b"chunk 0 data");
        assert_eq!(retrieved_blob.chunks[1].data, b"chunk 1 data");
    }

    #[tokio::test]
    async fn test_chunk_cache() {
        let (mut storage, _temp_dir) = create_test_storage().await;

        let blob_id = DataBlobId::new(0, b"test data 2");
        let chunks = vec![DataChunk {
            index: 0,
            data: b"test data".to_vec(),
        }];
        let blob = DataBlob {
            id: blob_id.clone(),
            chunks,
        };

        storage.store_blob(&blob).await.unwrap();

        // Primera lectura (desde disco)
        let chunk1 = storage.get_chunk(&blob_id, 0).await.unwrap();

        // Segunda lectura (desde caché)
        let chunk2 = storage.get_chunk(&blob_id, 0).await.unwrap();

        assert_eq!(chunk1.data, chunk2.data);
    }

    #[test]
    fn test_chunk_cache_eviction() {
        let mut cache = ChunkCache::new(1); // 1MB max
        let blob_id = DataBlobId::new(0, b"test data 3");

        // Agregar chunk que excede límite
        let large_data = vec![0u8; 2 * 1024 * 1024]; // 2MB
        let chunk = DataChunk {
            index: 0,
            data: large_data,
        };

        cache.put(blob_id.clone(), 0, chunk, 2 * 1024 * 1024);

        // Caché debe estar vacío debido a eviction
        assert!(cache.entries.is_empty());
    }
}
