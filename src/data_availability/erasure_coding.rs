//! # Reed-Solomon Erasure Coding
//!
//! Implementación basada en la librería `reed-solomon-erasure` para ofrecer
//! codificación y recuperación confiable de datos.

use crate::error::AvoError;
use reed_solomon_erasure::{galois_8::ReedSolomon, Error as ReedSolomonError};
use serde::{Deserialize, Serialize};

const SIZE_PREFIX_LEN: usize = 8; // Guardamos longitud original como u64 little-endian
const DEFAULT_DATA_SHARDS: usize = 10;

/// Configuración para Reed-Solomon coding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReedSolomonConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_size: usize,
}

impl ReedSolomonConfig {
    pub fn new(redundancy_ratio: f64, chunk_size: usize) -> Self {
        let data_shards = DEFAULT_DATA_SHARDS.max(2);
        let mut parity_shards = (redundancy_ratio * data_shards as f64).ceil() as usize;
        if parity_shards == 0 {
            parity_shards = 1;
        }

        // Reservar espacio suficiente por shard incluyendo el prefijo de tamaño
        let min_total_bytes = chunk_size + SIZE_PREFIX_LEN;
        let shard_size = ((min_total_bytes + data_shards - 1) / data_shards).max(1);

        Self {
            data_shards,
            parity_shards,
            shard_size,
        }
    }

    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    pub fn min_shards_for_recovery(&self) -> usize {
        self.data_shards
    }
}

#[derive(Debug, Clone)]
pub struct ReedSolomonCoder {
    config: ReedSolomonConfig,
    rs: ReedSolomon,
}

impl ReedSolomonCoder {
    pub fn new(redundancy_ratio: f64, chunk_size: usize) -> Result<Self, AvoError> {
        let config = ReedSolomonConfig::new(redundancy_ratio, chunk_size);
        let rs = ReedSolomon::new(config.data_shards, config.parity_shards)
            .map_err(|e| map_rs_error("initialize", e))?;

        tracing::info!(
            "🧮 Reed-Solomon coder ready: {} data + {} parity shards ({} bytes/shard)",
            config.data_shards,
            config.parity_shards,
            config.shard_size
        );

        Ok(Self { config, rs })
    }

    pub fn data_shards(&self) -> usize {
        self.config.data_shards
    }

    pub fn parity_shards(&self) -> usize {
        self.config.parity_shards
    }

    pub fn get_config(&self) -> &ReedSolomonConfig {
        &self.config
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, AvoError> {
        tracing::debug!(
            "🔧 Encoding {} bytes into {} shards",
            data.len(),
            self.config.total_shards()
        );

        let (padded, shard_len) = self.pad_data(data);
        let total_shards = self.config.total_shards();

        let mut shards: Vec<Vec<u8>> = (0..total_shards).map(|_| vec![0u8; shard_len]).collect();

        for (i, shard) in shards.iter_mut().take(self.config.data_shards).enumerate() {
            let start = i * shard_len;
            let end = start + shard_len;
            shard.copy_from_slice(&padded[start..end]);
        }

        self.rs
            .encode(&mut shards)
            .map_err(|e| map_rs_error("encode", e))?;

        tracing::debug!(
            "✅ Encoded into {} shards of {} bytes",
            total_shards,
            shard_len
        );
        Ok(shards)
    }

    pub fn decode(&self, mut shards: Vec<Option<Vec<u8>>>) -> Result<Vec<u8>, AvoError> {
        if shards.len() != self.config.total_shards() {
            return Err(AvoError::data_availability(format!(
                "Expected {} shards, got {}",
                self.config.total_shards(),
                shards.len()
            )));
        }

        let present: Vec<&Vec<u8>> = shards.iter().filter_map(|s| s.as_ref()).collect();
        if present.len() < self.config.min_shards_for_recovery() {
            return Err(AvoError::data_availability(format!(
                "Insufficient shards for recovery: have {}, need {}",
                present.len(),
                self.config.min_shards_for_recovery()
            )));
        }

        let shard_len = present
            .first()
            .map(|s| s.len())
            .ok_or_else(|| AvoError::data_availability("No shard data provided".to_string()))?;

        if present.iter().any(|shard| shard.len() != shard_len) {
            return Err(AvoError::data_availability(
                "Shard length mismatch detected".to_string(),
            ));
        }

        self.rs
            .reconstruct(&mut shards)
            .map_err(|e| map_rs_error("reconstruct", e))?;

        let mut reconstructed = Vec::with_capacity(self.config.data_shards * shard_len);
        for shard in shards.iter().take(self.config.data_shards) {
            let shard = shard.as_ref().ok_or_else(|| {
                AvoError::data_availability("Missing data shard after reconstruction".to_string())
            })?;
            reconstructed.extend_from_slice(shard);
        }

        let data = self.unpad_data(&reconstructed)?;
        tracing::debug!("✅ Decoded {} bytes after unpadding", data.len());
        Ok(data)
    }

    pub fn verify_shards(&self, shards: &[Option<Vec<u8>>]) -> Result<bool, AvoError> {
        if shards.len() != self.config.total_shards() {
            return Ok(false);
        }

        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < self.config.min_shards_for_recovery() {
            return Ok(false);
        }

        let mut expected_len: Option<usize> = None;
        for shard in shards.iter().filter_map(|s| s.as_ref()) {
            match expected_len {
                None => expected_len = Some(shard.len()),
                Some(len) if len != shard.len() => return Ok(false),
                _ => {}
            }
        }

        Ok(true)
    }

    fn pad_data(&self, data: &[u8]) -> (Vec<u8>, usize) {
        let shard_len = self.required_shard_len(SIZE_PREFIX_LEN + data.len());
        let target_len = shard_len * self.config.data_shards;

        let mut padded = Vec::with_capacity(target_len);
        padded.extend_from_slice(&(data.len() as u64).to_le_bytes());
        padded.extend_from_slice(data);
        padded.resize(target_len, 0u8);

        tracing::trace!(
            "📦 Padded payload: {} bytes ({} bytes/shard)",
            padded.len(),
            shard_len
        );

        (padded, shard_len)
    }

    fn unpad_data(&self, data: &[u8]) -> Result<Vec<u8>, AvoError> {
        if data.len() < SIZE_PREFIX_LEN {
            return Err(AvoError::data_availability(
                "Reconstructed data smaller than size prefix".to_string(),
            ));
        }

        let mut prefix = [0u8; SIZE_PREFIX_LEN];
        prefix.copy_from_slice(&data[..SIZE_PREFIX_LEN]);
        let original_len = u64::from_le_bytes(prefix) as usize;

        if original_len > data.len() - SIZE_PREFIX_LEN {
            return Err(AvoError::data_availability(
                "Invalid padding metadata in reconstructed data".to_string(),
            ));
        }

        Ok(data[SIZE_PREFIX_LEN..SIZE_PREFIX_LEN + original_len].to_vec())
    }

    fn required_shard_len(&self, bytes: usize) -> usize {
        let needed = (bytes + self.config.data_shards - 1) / self.config.data_shards;
        needed.max(self.config.shard_size)
    }
}

fn map_rs_error(context: &str, err: ReedSolomonError) -> AvoError {
    AvoError::data_availability(format!("Reed-Solomon {} error: {}", context, err))
}

#[cfg(all(test, feature = "run-tests"))]
mod tests {
    use super::*;

    fn coder() -> ReedSolomonCoder {
        ReedSolomonCoder::new(0.5, 1024).expect("failed to build coder")
    }

    #[test]
    fn encode_decode_roundtrip() {
        let coder = coder();
        let payload: Vec<u8> = (0..512u16).map(|x| (x % 256) as u8).collect();

        let shards = coder.encode(&payload).expect("encode");
        assert_eq!(shards.len(), coder.get_config().total_shards());

        // Drop a couple of shards to emulate data loss
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shards_opt[1] = None;
        shards_opt[coder.data_shards() + 1] = None;

        let recovered = coder.decode(shards_opt).expect("decode");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn decode_fails_with_insufficient_shards() {
        let coder = coder();
        let shards = coder.encode(&[1, 2, 3, 4]).expect("encode");
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        for shard in shards_opt.iter_mut().skip(coder.data_shards() - 1) {
            *shard = None;
        }

        let err = coder.decode(shards_opt).expect_err("expected failure");
        assert!(format!("{}", err).contains("Insufficient shards"));
    }

    #[test]
    fn verify_shards_basic() {
        let coder = coder();
        let shards = coder.encode(&[42u8; 32]).expect("encode");
        let mut shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shards_opt[2] = None;

        assert!(coder
            .verify_shards(&shards_opt)
            .expect("verification should succeed"));

        // Remove too many shards
        for shard in shards_opt.iter_mut().take(coder.parity_shards() + 1) {
            *shard = None;
        }

        assert!(!coder
            .verify_shards(&shards_opt)
            .expect("verification should succeed"));
    }
}
