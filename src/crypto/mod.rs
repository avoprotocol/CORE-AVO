//! # Módulo Criptográfico de AVO Protocol
//!
//! Implementaciones de todas las primitivas criptográficas necesarias
//! para el protocolo de consenso AVO.

pub mod bls_signatures;
pub mod circuits; // FASE 10.1: Real Groth16 circuits
pub mod key_cache;
pub mod optimized_crypto;
pub mod real_zk_crypto;
pub mod threshold_encryption;
pub mod vrf;
pub mod zk_batch_processor;
pub mod zk_circuits;
pub mod zk_cross_shard;
pub mod zk_proofs;
// Re-enabling ZK modules one by one
pub mod constraint_batching;
pub mod hardware_acceleration;
pub mod plonk_implementation;
pub mod recursive_proofs;
pub mod zk_vm;

// Re-exports para primitivas BLS
pub use bls_signatures::{
    AggregatedBlsSignature, BlsAggregator, BlsConsensusUtils, BlsKeyGenerator, BlsPrivateKey,
    BlsPublicKey, BlsSignature,
};

// Re-exports para VRF
pub use vrf::{
    VrfConsensusUtils, VrfKeyGenerator, VrfOutput, VrfPrivateKey, VrfProof, VrfPublicKey,
    VrfSortition,
};

// Re-exports para Threshold Encryption
pub use threshold_encryption::{
    EncryptedTransaction, ThresholdCiphertext, ThresholdConfig, ThresholdConsensusUtils,
    ThresholdDecryptionShare, ThresholdEncryptionManager, ThresholdKeyGenerator, ThresholdKeyShare,
    ThresholdMasterKey,
};

// Re-exports para zk-SNARKs
pub use zk_proofs::{
    BatchValidationCircuit, BatchValidationProof, ZkParameterGenerator, ZkParameters, ZkProof,
    ZkProofManager, ZkProver, ZkProvingKey, ZkPublicInputs, ZkVerificationKey, ZkVerifier,
};

// Re-exports para optimización zk-SNARK
// pub use zk_optimization::{
//     OptimizedZkManager, OptimizedZkParametersCache, ZkOptimizationConfig,
//     PrecomputedElements, BaseGenerators,
// };

// Re-exports para ZK Cross-Shard
pub use zk_cross_shard::{
    CrossShardValidationCircuit, CrossShardZkProof, ZkCrossShardConfig, ZkCrossShardManager,
    ZkCrossShardStatistics,
};

/// Inicialización completa del sistema criptográfico
pub struct CryptoSystem {
    pub bls_keys: Option<(BlsPrivateKey, BlsPublicKey)>,
    pub vrf_keys: Option<(VrfPrivateKey, VrfPublicKey)>,
    pub threshold_master: Option<ThresholdMasterKey>,
    pub threshold_share: Option<ThresholdKeyShare>,
    pub zk_params: Option<ZkParameters>,
    pub zk_proving_key: Option<ZkProvingKey>,
}

impl CryptoSystem {
    /// Crea un nuevo sistema criptográfico vacío
    pub fn new() -> Self {
        Self {
            bls_keys: None,
            vrf_keys: None,
            threshold_master: None,
            threshold_share: None,
            zk_params: None,
            zk_proving_key: None,
        }
    }

    /// Inicializa todas las primitivas criptográficas para un validador
    pub fn initialize_validator<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        rng: &mut R,
        validator_id: crate::types::ValidatorId,
        total_validators: usize,
        threshold: usize,
    ) -> crate::error::AvoResult<()> {
        // Generar claves BLS
        let (bls_private, bls_public) = BlsKeyGenerator::generate_keypair(rng);
        self.bls_keys = Some((bls_private, bls_public));

        // Generar claves VRF
        let (vrf_private, vrf_public) = VrfKeyGenerator::generate_keypair(rng);
        self.vrf_keys = Some((vrf_private, vrf_public));

        // Generar parámetros zk-SNARK (simplificado - en producción sería compartido)
        let (proving_key, zk_params) = ZkParameterGenerator::generate_parameters(rng, 100)?;
        self.zk_params = Some(zk_params);
        self.zk_proving_key = Some(proving_key);

        // Threshold encryption requiere coordinación - solo generamos placeholder
        if validator_id == 0 {
            // El validador 0 genera las claves threshold (en producción sería una ceremonia)
            let validators: Vec<_> = (0..total_validators as crate::types::ValidatorId).collect();
            let (master_key, validator_keys) =
                ThresholdKeyGenerator::generate_validator_threshold_keys(
                    rng,
                    &validators,
                    threshold,
                )?;

            self.threshold_master = Some(master_key);
            if let Some(share) = validator_keys.get(&validator_id) {
                self.threshold_share = Some(share.clone());
            }
        }

        Ok(())
    }

    /// Verifica que todas las primitivas están inicializadas
    pub fn is_fully_initialized(&self) -> bool {
        self.bls_keys.is_some()
            && self.vrf_keys.is_some()
            && self.zk_params.is_some()
            && self.zk_proving_key.is_some()
        // threshold encryption es opcional para algunos validadores
    }

    /// Obtiene las claves BLS del validador
    pub fn bls_keys(&self) -> Option<&(BlsPrivateKey, BlsPublicKey)> {
        self.bls_keys.as_ref()
    }

    /// Obtiene las claves VRF del validador
    pub fn vrf_keys(&self) -> Option<&(VrfPrivateKey, VrfPublicKey)> {
        self.vrf_keys.as_ref()
    }

    /// Obtiene los parámetros zk-SNARK
    pub fn zk_parameters(&self) -> Option<&ZkParameters> {
        self.zk_params.as_ref()
    }

    /// Obtiene la clave de threshold encryption
    pub fn threshold_share(&self) -> Option<&ThresholdKeyShare> {
        self.threshold_share.as_ref()
    }
}

impl Default for CryptoSystem {
    fn default() -> Self {
        Self::new()
    }
}
