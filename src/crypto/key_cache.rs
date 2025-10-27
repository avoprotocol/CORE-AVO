use crate::{
    crypto::{
        bls_signatures::{BlsKeyGenerator, BlsPrivateKey, BlsPublicKey},
        threshold_encryption::{ThresholdKeyGenerator, ThresholdKeyShare, ThresholdMasterKey},
        vrf::{VrfKeyGenerator, VrfPrivateKey, VrfPublicKey},
        zk_proofs::{ZkParameterGenerator, ZkParameters},
    },
    AvoError, AvoResult,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, time::Instant};
use tracing::{debug, info, warn};

/// Configuración para el sistema de cache de claves
#[derive(Debug, Clone)]
pub struct KeyCacheConfig {
    /// Directorio base para almacenar claves
    pub cache_dir: PathBuf,
    /// Número de claves BLS a generar
    pub bls_key_count: usize,
    /// Número de claves VRF a generar  
    pub vrf_key_count: usize,
    /// Número de shares threshold a generar
    pub threshold_shares: usize,
    /// Tamaño de circuito para parámetros zk-SNARK
    pub zk_circuit_size: usize,
    /// Forzar regeneración de claves
    pub force_regenerate: bool,
}

impl Default for KeyCacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from("avo_keys"),
            bls_key_count: 10,
            vrf_key_count: 10,
            threshold_shares: 5,
            zk_circuit_size: 1024,
            force_regenerate: false,
        }
    }
}

/// Cache de claves criptográficas serializables
#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedKeys {
    /// Claves BLS (privadas y públicas)
    pub bls_keys: Vec<(BlsPrivateKey, BlsPublicKey)>,
    /// Claves VRF (privadas y públicas)
    pub vrf_keys: Vec<(VrfPrivateKey, VrfPublicKey)>,
    /// Clave maestra threshold
    pub threshold_master: ThresholdMasterKey,
    /// Shares threshold
    pub threshold_shares: Vec<ThresholdKeyShare>,
    /// Parámetros zk-SNARK
    pub zk_parameters: ZkParameters,
    /// Timestamp de generación
    pub generated_at: u64,
    /// Versión del esquema de claves
    pub version: u32,
}

/// Gestor de cache de claves criptográficas
#[derive(Debug)]
pub struct KeyCacheManager {
    config: KeyCacheConfig,
    cache_file: PathBuf,
}

impl KeyCacheManager {
    /// Crea un nuevo gestor de cache de claves
    pub fn new(config: KeyCacheConfig) -> AvoResult<Self> {
        // Crear directorio de cache si no existe
        if !config.cache_dir.exists() {
            fs::create_dir_all(&config.cache_dir).map_err(|e| AvoError::IoError { source: e })?;
        }

        let cache_file = config.cache_dir.join("crypto_keys.bin");

        Ok(Self { config, cache_file })
    }

    /// Carga o genera claves criptográficas
    pub async fn load_or_generate_keys(&self) -> AvoResult<PersistedKeys> {
        info!("🔑 Inicializando sistema de claves criptográficas...");
        let start_time = Instant::now();

        // Intentar cargar claves existentes si no se fuerza regeneración
        if !self.config.force_regenerate && self.cache_file.exists() {
            match self.load_keys_from_cache().await {
                Ok(keys) => {
                    let load_time = start_time.elapsed();
                    info!("✅ Claves cargadas desde cache en {:?}", load_time);
                    self.validate_keys(&keys)?;
                    return Ok(keys);
                }
                Err(e) => {
                    warn!("⚠️ Error cargando cache, regenerando claves: {}", e);
                }
            }
        }

        // Generar nuevas claves
        info!("🔨 Generando nuevas claves criptográficas...");
        let keys = self.generate_fresh_keys().await?;

        // Persistir claves generadas
        self.save_keys_to_cache(&keys).await?;

        let total_time = start_time.elapsed();
        info!("✅ Claves generadas y cacheadas en {:?}", total_time);

        Ok(keys)
    }

    /// Carga claves desde el cache
    async fn load_keys_from_cache(&self) -> AvoResult<PersistedKeys> {
        debug!("📂 Cargando claves desde: {:?}", self.cache_file);

        let data = fs::read(&self.cache_file).map_err(|e| AvoError::IoError { source: e })?;

        let keys: PersistedKeys =
            bincode::deserialize(&data).map_err(|e| AvoError::SerializationError { source: e })?;

        debug!(
            "📊 Claves cargadas: {} BLS, {} VRF, {} threshold shares",
            keys.bls_keys.len(),
            keys.vrf_keys.len(),
            keys.threshold_shares.len()
        );

        Ok(keys)
    }

    /// Genera claves frescas
    async fn generate_fresh_keys(&self) -> AvoResult<PersistedKeys> {
        let mut rng = thread_rng();

        // Generar claves BLS
        info!("🔐 Generando {} claves BLS...", self.config.bls_key_count);
        let bls_start = Instant::now();
        let mut bls_keys = Vec::new();
        for i in 0..self.config.bls_key_count {
            let (private, public) = BlsKeyGenerator::generate_keypair(&mut rng);
            bls_keys.push((private, public));

            if i % 2 == 0 || i == self.config.bls_key_count - 1 {
                debug!("  BLS progress: {}/{}", i + 1, self.config.bls_key_count);
            }
        }
        let bls_time = bls_start.elapsed();
        info!("✅ BLS keys generadas en {:?}", bls_time);

        // Generar claves VRF
        info!("🎲 Generando {} claves VRF...", self.config.vrf_key_count);
        let vrf_start = Instant::now();
        let mut vrf_keys = Vec::new();
        for i in 0..self.config.vrf_key_count {
            let (private, public) = VrfKeyGenerator::generate_keypair(&mut rng);
            vrf_keys.push((private, public));

            if i % 2 == 0 || i == self.config.vrf_key_count - 1 {
                debug!("  VRF progress: {}/{}", i + 1, self.config.vrf_key_count);
            }
        }
        let vrf_time = vrf_start.elapsed();
        info!("✅ VRF keys generadas en {:?}", vrf_time);

        // Generar claves threshold
        info!(
            "🛡️ Generando claves threshold ({} shares)...",
            self.config.threshold_shares
        );
        let threshold_start = Instant::now();
        let (master_key, shares) = ThresholdKeyGenerator::generate_threshold_keys(
            &mut rng,
            3,                            // threshold
            self.config.threshold_shares, // total_shares
        )?;
        let threshold_time = threshold_start.elapsed();
        info!("✅ Threshold keys generadas en {:?}", threshold_time);

        // Generar parámetros zk-SNARK
        info!(
            "🔬 Generando parámetros zk-SNARK (circuito: {})...",
            self.config.zk_circuit_size
        );
        let zk_start = Instant::now();
        let zk_parameters =
            ZkParameterGenerator::generate_parameters(&mut rng, self.config.zk_circuit_size).map(
                |(proving_key, mut params)| {
                    params.proving_key = proving_key;
                    params
                },
            )?;
        let zk_time = zk_start.elapsed();
        info!("✅ zk-SNARK parámetros generados en {:?}", zk_time);

        let keys = PersistedKeys {
            bls_keys,
            vrf_keys,
            threshold_master: master_key,
            threshold_shares: shares,
            zk_parameters,
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            version: 1,
        };

        info!(
            "🎊 Generación completa: BLS({:?}) + VRF({:?}) + Threshold({:?}) + zk-SNARK({:?})",
            bls_time, vrf_time, threshold_time, zk_time
        );

        Ok(keys)
    }

    /// Guarda claves en el cache
    async fn save_keys_to_cache(&self, keys: &PersistedKeys) -> AvoResult<()> {
        debug!("💾 Guardando claves en cache: {:?}", self.cache_file);

        let data =
            bincode::serialize(keys).map_err(|e| AvoError::SerializationError { source: e })?;

        fs::write(&self.cache_file, &data).map_err(|e| AvoError::IoError { source: e })?;

        info!("💾 Claves guardadas en cache ({} bytes)", data.len());
        Ok(())
    }

    /// Valida que las claves cargadas sean correctas
    fn validate_keys(&self, keys: &PersistedKeys) -> AvoResult<()> {
        // Validar que tengamos suficientes claves
        if keys.bls_keys.len() < self.config.bls_key_count {
            return Err(AvoError::KeyError {
                reason: format!(
                    "Insufficient BLS keys: expected {}, found {}",
                    self.config.bls_key_count,
                    keys.bls_keys.len()
                ),
            });
        }

        if keys.vrf_keys.len() < self.config.vrf_key_count {
            return Err(AvoError::KeyError {
                reason: format!(
                    "Insufficient VRF keys: expected {}, found {}",
                    self.config.vrf_key_count,
                    keys.vrf_keys.len()
                ),
            });
        }

        if keys.threshold_shares.len() < self.config.threshold_shares {
            return Err(AvoError::KeyError {
                reason: format!(
                    "Insufficient threshold shares: expected {}, found {}",
                    self.config.threshold_shares,
                    keys.threshold_shares.len()
                ),
            });
        }

        // Validar versión
        if keys.version != 1 {
            return Err(AvoError::KeyError {
                reason: format!("Unsupported key version: {}", keys.version),
            });
        }

        debug!("✅ Validación de claves exitosa");
        Ok(())
    }

    /// Limpia el cache de claves
    pub async fn clear_cache(&self) -> AvoResult<()> {
        if self.cache_file.exists() {
            fs::remove_file(&self.cache_file).map_err(|e| AvoError::IoError { source: e })?;
            info!("🗑️ Cache de claves limpiado");
        }
        Ok(())
    }

    /// Obtiene información del cache
    pub fn cache_info(&self) -> CacheInfo {
        let exists = self.cache_file.exists();
        let size = if exists {
            fs::metadata(&self.cache_file).map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };

        CacheInfo {
            exists,
            size_bytes: size,
            path: self.cache_file.clone(),
        }
    }
}

/// Información sobre el estado del cache
#[derive(Debug)]
pub struct CacheInfo {
    pub exists: bool,
    pub size_bytes: u64,
    pub path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_key_cache_generation_and_loading() {
        let temp_dir = tempdir().unwrap();

        let config = KeyCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            bls_key_count: 2,
            vrf_key_count: 2,
            threshold_shares: 3,
            zk_circuit_size: 10,
            force_regenerate: false,
        };

        let manager = KeyCacheManager::new(config).unwrap();

        // Primera carga - debe generar claves
        let start = Instant::now();
        let keys1 = manager.load_or_generate_keys().await.unwrap();
        let gen_time = start.elapsed();

        assert_eq!(keys1.bls_keys.len(), 2);
        assert_eq!(keys1.vrf_keys.len(), 2);
        assert_eq!(keys1.threshold_shares.len(), 3);

        // Segunda carga - debe cargar desde cache
        let start = Instant::now();
        let keys2 = manager.load_or_generate_keys().await.unwrap();
        let load_time = start.elapsed();

        // El tiempo de carga debe ser significativamente menor
        assert!(load_time < gen_time);

        // Las claves deben ser idénticas
        assert_eq!(keys1.generated_at, keys2.generated_at);
        assert_eq!(keys1.bls_keys.len(), keys2.bls_keys.len());
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let temp_dir = tempdir().unwrap();

        let config = KeyCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            bls_key_count: 1,
            vrf_key_count: 1,
            threshold_shares: 3,
            zk_circuit_size: 10,
            force_regenerate: false,
        };

        let manager = KeyCacheManager::new(config).unwrap();

        // Generar claves
        let _keys = manager.load_or_generate_keys().await.unwrap();
        assert!(manager.cache_info().exists);

        // Limpiar cache
        manager.clear_cache().await.unwrap();
        assert!(!manager.cache_info().exists);
    }
}
