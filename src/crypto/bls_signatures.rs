//! # BLS Signatures para AVO Protocol
//!
//! Implementación de firmas BLS (Boneh-Lynn-Shacham) con agregación
//! para el consenso distribuido y validación eficiente.

use crate::error::{AvoError, AvoResult};
use crate::types::*;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::ff::Field;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use subtle::CtOption;

fn ct_option_to_option<T>(value: CtOption<T>) -> Option<T> {
    if bool::from(value.is_some()) {
        Some(value.unwrap())
    } else {
        None
    }
}

/// Clave privada BLS usando representación de bytes para serialización
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsPrivateKey {
    scalar_bytes: Vec<u8>,
}

/// Clave pública BLS usando representación de bytes para serialización
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsPublicKey {
    point_bytes: Vec<u8>,
}

/// Firma BLS individual usando representación de bytes para serialización
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsSignature {
    point_bytes: Vec<u8>,
}

/// Firma BLS agregada
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedBlsSignature {
    signature: BlsSignature,
    public_keys: Vec<BlsPublicKey>,
    message_hash: [u8; 32],
}

/// Generador de pares de claves BLS
pub struct BlsKeyGenerator;

impl BlsKeyGenerator {
    /// Genera un nuevo par de claves BLS
    pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (BlsPrivateKey, BlsPublicKey) {
        let scalar = Scalar::random(rng);
        let private_key = BlsPrivateKey {
            scalar_bytes: scalar.to_bytes().to_vec(),
        };
        let public_point = (G1Projective::generator() * scalar).into();
        let public_key = BlsPublicKey {
            point_bytes: G1Affine::to_compressed(&public_point).to_vec(),
        };
        (private_key, public_key)
    }

    /// Genera múltiples pares de claves para validadores
    pub fn generate_validator_keys<R: CryptoRng + RngCore>(
        rng: &mut R,
        count: usize,
    ) -> Vec<(ValidatorId, BlsPrivateKey, BlsPublicKey)> {
        (0..count)
            .map(|i| {
                let (private_key, public_key) = Self::generate_keypair(rng);
                (i as ValidatorId, private_key, public_key)
            })
            .collect()
    }

    /// Genera un solo par de claves para un nuevo validador
    pub fn generate_single_keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> (BlsPrivateKey, BlsPublicKey) {
        Self::generate_keypair(rng)
    }

    /// Genera un par de claves para un validador específico con ID
    pub fn generate_single_validator_key<R: CryptoRng + RngCore>(
        rng: &mut R,
        validator_id: ValidatorId,
    ) -> (ValidatorId, BlsPrivateKey, BlsPublicKey) {
        let (private_key, public_key) = Self::generate_keypair(rng);
        (validator_id, private_key, public_key)
    }
}

impl BlsPrivateKey {
    /// Convierte a Scalar para operaciones criptográficas
    pub fn to_scalar(&self) -> AvoResult<Scalar> {
        let scalar_bytes: [u8; 32] = self
            .scalar_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AvoError::crypto("Invalid scalar length"))?;
        ct_option_to_option(Scalar::from_bytes(&scalar_bytes))
            .ok_or_else(|| AvoError::crypto("Invalid scalar bytes"))
    }

    /// Firma un mensaje usando la clave privada
    pub fn sign(&self, message: &[u8]) -> AvoResult<BlsSignature> {
        let scalar = self.to_scalar()?;
        let hash_point = Self::hash_to_curve(message);
        let signature_point = hash_point * scalar;
        Ok(BlsSignature {
            point_bytes: G2Affine::to_compressed(&signature_point.into()).to_vec(),
        })
    }

    /// Obtiene la clave pública correspondiente
    pub fn public_key(&self) -> AvoResult<BlsPublicKey> {
        let scalar = self.to_scalar()?;
        let public_point = (G1Projective::generator() * scalar).into();
        Ok(BlsPublicKey {
            point_bytes: G1Affine::to_compressed(&public_point).to_vec(),
        })
    }

    /// Hash-to-curve para mapear mensajes a puntos de la curva
    fn hash_to_curve(message: &[u8]) -> G2Projective {
        // Implementación simplificada - en producción usar hash-to-curve estándar
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.update(b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_");
        let hash = hasher.finalize();

        // Convertir hash a scalar y multiplicar por generador G2
        let scalar = Scalar::from_bytes_wide(
            &[hash.as_slice().try_into().unwrap_or([0u8; 32]), [0u8; 32]]
                .concat()
                .try_into()
                .unwrap(),
        );

        G2Projective::generator() * scalar
    }
}

impl BlsPublicKey {
    /// Convierte a G1Affine para operaciones criptográficas
    pub fn to_point(&self) -> AvoResult<G1Affine> {
        let point_bytes: [u8; 48] = self
            .point_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AvoError::crypto("Invalid point length"))?;
        ct_option_to_option(G1Affine::from_compressed(&point_bytes))
            .ok_or_else(|| AvoError::crypto("Invalid point bytes"))
    }

    /// Verifica una firma individual
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> AvoResult<bool> {
        let public_point = self.to_point()?;
        let signature_point = signature.to_point()?;
        let hash_point = BlsPrivateKey::hash_to_curve(message);

        // Verificar usando pairing: e(P, H(m)) == e(G, S)
        // Donde P = clave pública, H(m) = hash del mensaje, G = generador, S = firma
        let lhs = bls12_381::pairing(&public_point, &hash_point.into());
        let rhs = bls12_381::pairing(&G1Affine::generator(), &signature_point);

        Ok(lhs == rhs)
    }

    /// Serializa la clave pública a bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.point_bytes.clone()
    }

    /// Deserializa una clave pública desde bytes
    pub fn from_bytes(bytes: &[u8]) -> AvoResult<Self> {
        if bytes.len() != 48 {
            return Err(AvoError::crypto("Invalid public key length"));
        }
        let point_bytes: [u8; 48] = bytes
            .try_into()
            .map_err(|_| AvoError::crypto("Invalid public key length"))?;
        let point = G1Affine::from_compressed(&point_bytes);
        if point.is_some().into() {
            Ok(BlsPublicKey {
                point_bytes: bytes.to_vec(),
            })
        } else {
            Err(AvoError::crypto("Invalid BLS public key bytes"))
        }
    }

    /// Agrega múltiples claves públicas BLS en una sola
    pub fn aggregate_public_keys(public_keys: &[BlsPublicKey]) -> AvoResult<BlsPublicKey> {
        BlsAggregator::aggregate_public_keys(public_keys)
    }
}

impl BlsSignature {
    /// Convierte a G2Affine para operaciones criptográficas
    pub fn to_point(&self) -> AvoResult<G2Affine> {
        let point_bytes: [u8; 96] = self
            .point_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AvoError::crypto("Invalid signature length"))?;
        ct_option_to_option(G2Affine::from_compressed(&point_bytes))
            .ok_or_else(|| AvoError::crypto("Invalid signature bytes"))
    }

    /// Serializa la firma a bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.point_bytes.clone()
    }

    /// Deserializa una firma desde bytes
    pub fn from_bytes(bytes: &[u8]) -> AvoResult<Self> {
        if bytes.len() != 96 {
            return Err(AvoError::crypto("Invalid signature length"));
        }
        let point_bytes: [u8; 96] = bytes
            .try_into()
            .map_err(|_| AvoError::crypto("Invalid signature length"))?;
        let point = G2Affine::from_compressed(&point_bytes);
        if point.is_some().into() {
            Ok(BlsSignature {
                point_bytes: bytes.to_vec(),
            })
        } else {
            Err(AvoError::crypto("Invalid BLS signature bytes"))
        }
    }

    /// Agrega múltiples firmas BLS en una sola (método estático)
    pub fn aggregate(signatures: &[BlsSignature]) -> AvoResult<BlsSignature> {
        BlsAggregator::aggregate_signatures(signatures)
    }

    /// Creates a mock signature for testing purposes
    #[cfg(test)]
    pub fn mock_signature() -> Self {
        BlsSignature {
            point_bytes: vec![0u8; 96],
        }
    }
}

/// Agregador de firmas BLS
pub struct BlsAggregator;

impl BlsAggregator {
    /// Agrega múltiples firmas BLS en una sola
    pub fn aggregate_signatures(signatures: &[BlsSignature]) -> AvoResult<BlsSignature> {
        if signatures.is_empty() {
            return Err(AvoError::crypto("Cannot aggregate empty signature set"));
        }

        let mut aggregated = G2Projective::identity();
        for signature in signatures {
            let point = signature.to_point()?;
            aggregated += G2Projective::from(point);
        }

        Ok(BlsSignature {
            point_bytes: G2Affine::to_compressed(&aggregated.into()).to_vec(),
        })
    }

    /// Agrega múltiples claves públicas
    pub fn aggregate_public_keys(public_keys: &[BlsPublicKey]) -> AvoResult<BlsPublicKey> {
        if public_keys.is_empty() {
            return Err(AvoError::crypto("Cannot aggregate empty public key set"));
        }

        let mut aggregated = G1Projective::identity();
        for public_key in public_keys {
            let point = public_key.to_point()?;
            aggregated += G1Projective::from(point);
        }

        Ok(BlsPublicKey {
            point_bytes: G1Affine::to_compressed(&aggregated.into()).to_vec(),
        })
    }

    /// Verifica una firma agregada
    pub fn verify_aggregated(
        aggregated_public_key: &BlsPublicKey,
        message: &[u8],
        aggregated_signature: &BlsSignature,
    ) -> AvoResult<bool> {
        aggregated_public_key.verify(message, aggregated_signature)
    }

    /// Crea una firma agregada completa con metadatos
    pub fn create_aggregated_signature(
        signatures: Vec<BlsSignature>,
        public_keys: Vec<BlsPublicKey>,
        message: &[u8],
    ) -> AvoResult<AggregatedBlsSignature> {
        if signatures.len() != public_keys.len() {
            return Err(AvoError::crypto("Signature and public key count mismatch"));
        }

        let aggregated_signature = Self::aggregate_signatures(&signatures)?;
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let message_hash = hasher.finalize().into();

        Ok(AggregatedBlsSignature {
            signature: aggregated_signature,
            public_keys,
            message_hash,
        })
    }
}

impl AggregatedBlsSignature {
    /// Verifica la firma agregada
    pub fn verify(&self, message: &[u8]) -> AvoResult<bool> {
        // Verificar que el hash del mensaje coincida
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        let computed_hash: [u8; 32] = hasher.finalize().into();

        if computed_hash != self.message_hash {
            return Ok(false);
        }

        // Agregar claves públicas y verificar
        let aggregated_public_key = BlsAggregator::aggregate_public_keys(&self.public_keys)?;
        BlsAggregator::verify_aggregated(&aggregated_public_key, message, &self.signature)
    }

    /// Obtiene el número de firmantes
    pub fn signer_count(&self) -> usize {
        self.public_keys.len()
    }

    /// Serializa la firma agregada
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes.extend_from_slice(&self.message_hash);
        bytes.extend_from_slice(&(self.public_keys.len() as u32).to_le_bytes());

        for public_key in &self.public_keys {
            bytes.extend_from_slice(&public_key.to_bytes());
        }

        bytes
    }
}

/// Utilidades para el consenso BLS
pub struct BlsConsensusUtils;

impl BlsConsensusUtils {
    /// Crea un set de firmas para un bloque de consenso
    pub fn create_consensus_signatures(
        validators: &[(ValidatorId, BlsPrivateKey)],
        block_hash: &BlockId,
    ) -> AvoResult<HashMap<ValidatorId, BlsSignature>> {
        let mut signatures = HashMap::new();
        for (validator_id, private_key) in validators {
            let signature = private_key.sign(&block_hash.0)?;
            signatures.insert(*validator_id, signature);
        }
        Ok(signatures)
    }

    /// Valida que un conjunto de firmas alcance el quorum necesario
    pub fn validate_quorum(
        signatures: &HashMap<ValidatorId, BlsSignature>,
        public_keys: &HashMap<ValidatorId, BlsPublicKey>,
        required_threshold: usize,
        message: &[u8],
    ) -> AvoResult<bool> {
        if signatures.len() < required_threshold {
            return Ok(false);
        }

        // Verificar cada firma individual
        for (validator_id, signature) in signatures {
            if let Some(public_key) = public_keys.get(validator_id) {
                if !public_key.verify(message, signature)? {
                    return Ok(false);
                }
            } else {
                return Err(AvoError::crypto("Unknown validator in signature set"));
            }
        }

        Ok(true)
    }

    /// Crea una firma agregada para el consenso final
    pub fn create_consensus_proof(
        signatures: HashMap<ValidatorId, BlsSignature>,
        public_keys: &HashMap<ValidatorId, BlsPublicKey>,
        message: &[u8],
    ) -> AvoResult<AggregatedBlsSignature> {
        let sig_vec: Vec<BlsSignature> = signatures.values().cloned().collect();
        let pub_key_vec: Vec<BlsPublicKey> = signatures
            .keys()
            .filter_map(|id| public_keys.get(id).cloned())
            .collect();

        BlsAggregator::create_aggregated_signature(sig_vec, pub_key_vec, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_bls_key_generation() {
        let mut rng = thread_rng();
        let (private_key, public_key) = BlsKeyGenerator::generate_keypair(&mut rng);

        // La clave pública derivada debe coincidir
        assert_eq!(private_key.public_key().unwrap(), public_key);
    }

    #[test]
    fn test_bls_signature_verification() {
        let mut rng = thread_rng();
        let (private_key, public_key) = BlsKeyGenerator::generate_keypair(&mut rng);

        let message = b"test message for BLS signature";
        let signature = private_key.sign(message).unwrap();

        // La firma debe ser válida
        assert!(public_key.verify(message, &signature).unwrap());

        // La firma debe fallar con un mensaje diferente
        assert!(!public_key.verify(b"different message", &signature).unwrap());
    }

    #[test]
    fn test_signature_aggregation() {
        let mut rng = thread_rng();
        let message = b"consensus block hash";

        // Generar múltiples validadores
        let validators = BlsKeyGenerator::generate_validator_keys(&mut rng, 5);

        // Cada validador firma el mismo mensaje
        let signatures: Result<Vec<BlsSignature>, _> = validators
            .iter()
            .map(|(_, private_key, _)| private_key.sign(message))
            .collect();
        let signatures = signatures.unwrap();

        let public_keys: Vec<BlsPublicKey> = validators
            .iter()
            .map(|(_, _, public_key)| public_key.clone())
            .collect();

        // Agregar firmas
        let aggregated_signature =
            BlsAggregator::create_aggregated_signature(signatures, public_keys, message).unwrap();

        // Verificar firma agregada
        assert!(aggregated_signature.verify(message).unwrap());
        assert_eq!(aggregated_signature.signer_count(), 5);
    }
}

/// Manager for BLS signature operations used in benchmarks
pub struct BlsSignatureManager {
    // For benchmarks, we'll use a simple implementation
}

impl BlsSignatureManager {
    pub async fn new() -> Result<Self, AvoError> {
        Ok(Self {})
    }

    pub async fn aggregate_signatures(&self, signatures: &[Vec<u8>]) -> Result<Vec<u8>, AvoError> {
        // Simple aggregation simulation for benchmarks
        if signatures.is_empty() {
            return Ok(Vec::new());
        }

        // In a real implementation, this would aggregate BLS signatures
        // For benchmarks, we'll just concatenate them as a placeholder
        let mut aggregated = Vec::new();
        for sig in signatures {
            aggregated.extend_from_slice(sig);
        }

        Ok(aggregated)
    }
}
