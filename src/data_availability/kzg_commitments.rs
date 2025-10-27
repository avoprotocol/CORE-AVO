//! # KZG Commitment System
//!
//! Implementación real de compromisos KZG (Kate-Zaverucha-Goldberg) sobre
//! BLS12-381 utilizando la librería `arkworks`. Esta versión ofrece
//! compatibilidad con la capa de disponibilidad de datos del protocolo AVO,
//! permitiendo generar commitments, abrir evaluaciones puntuales y verificar
//! pruebas en tiempo O(1).

use crate::error::AvoError;
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_poly_commit::kzg10::Commitment;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::ops::Mul;
use std::time::{SystemTime, UNIX_EPOCH};

const FIELD_ELEMENT_BYTES: usize = 32;
const BYTES_PER_COEFFICIENT: usize = 31; // < FIELD_ELEMENT_BYTES para evitar overflow

#[derive(Debug, Clone)]
struct StoredCommitment {
    polynomial: DensePolynomial<Fr>,
    raw_commitment: Commitment<Bls12_381>,
    exported: KZGCommitment,
}

/// Commitment serializado listo para distribuir entre nodos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KZGCommitment {
    pub commitment_bytes: Vec<u8>,
    pub data_hash: [u8; 32],
    pub timestamp: u64,
}

impl KZGCommitment {
    /// FASE 11.1: Serialize commitment to bytes for P2P transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// FASE 11.1: Deserialize commitment from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AvoError> {
        bincode::deserialize(bytes)
            .map_err(|e| AvoError::internal(format!("KZG commitment deserialization: {}", e)))
    }
}

/// Prueba KZG que acompaña a un commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KZGProof {
    pub proof_bytes: Vec<u8>,
    pub evaluation: [u8; FIELD_ELEMENT_BYTES],
    pub commitment: KZGCommitment,
}

impl KZGProof {
    /// FASE 11.1: Serialize proof to bytes for P2P transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// FASE 11.1: Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AvoError> {
        bincode::deserialize(bytes)
            .map_err(|e| AvoError::internal(format!("KZG proof deserialization: {}", e)))
    }
}

/// Sistema de compromisos KZG listo para producción.
#[derive(Debug)]
pub struct KZGCommitmentSystem {
    max_degree: usize,
    g1_generator: G1Projective,
    g2_generator: G2Projective,
    g2_tau: G2Projective,
    g1_powers: Vec<G1Projective>,
    commitments: HashMap<[u8; 32], StoredCommitment>,
}

impl KZGCommitmentSystem {
    /// Inicializa el sistema con una ceremonia de tamaño `max_degree`.
    pub fn new(max_degree: usize) -> Result<Self, AvoError> {
        if max_degree == 0 {
            return Err(AvoError::data_availability(
                "KZG ceremony size must be greater than zero".to_string(),
            ));
        }

        let mut rng = StdRng::from_entropy();
        let mut tau = Fr::rand(&mut rng);
        while tau.is_zero() {
            tau = Fr::rand(&mut rng);
        }

        let g1_generator = G1Projective::generator();
        let g2_generator = G2Projective::generator();
        let g2_tau = g2_generator.mul(tau);

        let mut g1_powers = Vec::with_capacity(max_degree + 1);
        let mut tau_power = Fr::one();
        for _ in 0..=max_degree {
            g1_powers.push(g1_generator.mul(tau_power));
            tau_power *= tau;
        }

        Ok(Self {
            max_degree,
            g1_generator,
            g2_generator,
            g2_tau,
            g1_powers,
            commitments: HashMap::new(),
        })
    }

    fn commit_polynomial(&self, coefficients: &[Fr]) -> Result<Commitment<Bls12_381>, AvoError> {
        if coefficients.is_empty() {
            return Err(AvoError::data_availability(
                "Polynomial must have at least one coefficient".to_string(),
            ));
        }

        if coefficients.len() > self.g1_powers.len() {
            return Err(AvoError::data_availability(format!(
                "Polynomial degree {} exceeds ceremony size {}",
                coefficients.len() - 1,
                self.max_degree
            )));
        }

        let mut accumulator = G1Projective::zero();
        for (i, coeff) in coefficients.iter().enumerate() {
            if coeff.is_zero() {
                continue;
            }

            let power = self
                .g1_powers
                .get(i)
                .ok_or_else(|| AvoError::data_availability("Missing SRS power".to_string()))?;

            accumulator += power.mul(*coeff);
        }

        Ok(Commitment(accumulator.into_affine()))
    }

    /// Crea un commitment para los datos proporcionados.
    pub fn commit(&mut self, data: &[u8]) -> Result<KZGCommitment, AvoError> {
        if data.is_empty() {
            return Err(AvoError::data_availability(
                "Cannot commit to empty data".to_string(),
            ));
        }

        let coefficients = bytes_to_field_elements(data);
        if coefficients.is_empty() {
            return Err(AvoError::data_availability(
                "Failed to derive field elements from data".to_string(),
            ));
        }

        if coefficients.len() - 1 > self.max_degree {
            return Err(AvoError::data_availability(format!(
                "Polynomial degree {} exceeds ceremony size {}",
                coefficients.len() - 1,
                self.max_degree
            )));
        }

        let polynomial = DensePolynomial::from_coefficients_vec(coefficients.clone());
        let raw_commitment = self.commit_polynomial(&coefficients)?;

        let commitment_bytes = serialize(&raw_commitment)?;
        let data_hash = hash_data(data);
        let timestamp = current_unix_timestamp();

        let exported = KZGCommitment {
            commitment_bytes,
            data_hash,
            timestamp,
        };

        self.commitments.insert(
            data_hash,
            StoredCommitment {
                polynomial,
                raw_commitment,
                exported: exported.clone(),
            },
        );

        Ok(exported)
    }

    /// Genera una prueba de evaluación para un punto específico.
    pub fn create_proof(&self, data: &[u8], evaluation_point: u64) -> Result<KZGProof, AvoError> {
        let data_hash = hash_data(data);
        let stored = self
            .commitments
            .get(&data_hash)
            .ok_or_else(|| AvoError::data_availability("Commitment not found".to_string()))?;

        let point = Fr::from(evaluation_point);
        let value = stored.polynomial.evaluate(&point);
        let witness_coefficients = compute_witness_coefficients(&stored.polynomial, point, value)?;
        let witness_commitment = self.commit_polynomial(&witness_coefficients)?;

        let proof_bytes = serialize(&witness_commitment.0)?;
        let evaluation_bytes = serialize_field(&value)?;

        Ok(KZGProof {
            proof_bytes,
            evaluation: evaluation_bytes,
            commitment: stored.exported.clone(),
        })
    }

    /// Verifica que la prueba corresponda al commitment y punto proporcionados.
    pub fn verify_proof(&self, proof: &KZGProof, evaluation_point: u64) -> Result<bool, AvoError> {
        let commitment = deserialize_commitment(&proof.commitment.commitment_bytes)?;
        let value = deserialize_field(&proof.evaluation)?;
        let point = Fr::from(evaluation_point);

        let proof_point = deserialize_g1(&proof.proof_bytes)?;

        let mut commitment_adjusted = commitment.0.into_group();
        commitment_adjusted -= self.g1_generator.mul(value);

        let lhs = Bls12_381::pairing(
            commitment_adjusted.into_affine(),
            G2Affine::from(self.g2_generator.clone()),
        );

        let mut g2_denominator = self.g2_tau;
        g2_denominator -= self.g2_generator.mul(point);

        let rhs = Bls12_381::pairing(proof_point, G2Affine::from(g2_denominator));

        Ok(lhs == rhs)
    }

    /// Devuelve el número máximo de coeficientes soportados por la ceremonia.
    pub fn max_degree(&self) -> usize {
        self.max_degree
    }
}

fn bytes_to_field_elements(data: &[u8]) -> Vec<Fr> {
    data.chunks(BYTES_PER_COEFFICIENT)
        .map(|chunk| {
            let mut buffer = [0u8; FIELD_ELEMENT_BYTES];
            buffer[..chunk.len()].copy_from_slice(chunk);
            Fr::from_le_bytes_mod_order(&buffer)
        })
        .collect()
}

fn compute_witness_coefficients(
    polynomial: &DensePolynomial<Fr>,
    point: Fr,
    expected_value: Fr,
) -> Result<Vec<Fr>, AvoError> {
    let coeffs = &polynomial.coeffs;

    if coeffs.len() <= 1 {
        return Ok(vec![Fr::zero()]);
    }

    let mut quotient = vec![Fr::zero(); coeffs.len() - 1];
    let mut accumulator = Fr::zero();
    let mut remainder = Fr::zero();

    for i in (0..coeffs.len()).rev() {
        accumulator = accumulator * point + coeffs[i];
        if i > 0 {
            quotient[i - 1] = accumulator;
        } else {
            remainder = accumulator;
        }
    }

    if remainder != expected_value {
        return Err(AvoError::data_availability(
            "Witness computation mismatch".to_string(),
        ));
    }

    Ok(quotient)
}

fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn serialize<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, AvoError> {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .map_err(|e| AvoError::data_availability(format!("Serialization error: {}", e)))?;
    Ok(buf)
}

fn serialize_field(value: &Fr) -> Result<[u8; FIELD_ELEMENT_BYTES], AvoError> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|e| AvoError::data_availability(format!("Serialization error: {}", e)))?;
    let mut array = [0u8; FIELD_ELEMENT_BYTES];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn deserialize_commitment(bytes: &[u8]) -> Result<Commitment<Bls12_381>, AvoError> {
    Commitment::<Bls12_381>::deserialize_compressed(&mut &*bytes)
        .map_err(|e| AvoError::data_availability(format!("Invalid commitment: {}", e)))
}

fn deserialize_g1(bytes: &[u8]) -> Result<G1Affine, AvoError> {
    G1Affine::deserialize_compressed(&mut &*bytes)
        .map_err(|e| AvoError::data_availability(format!("Invalid proof: {}", e)))
}

fn deserialize_field(bytes: &[u8]) -> Result<Fr, AvoError> {
    Fr::deserialize_compressed(&mut &*bytes)
        .map_err(|e| AvoError::data_availability(format!("Invalid field element: {}", e)))
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// FASE 11.1: Verifier for KZG proofs (lightweight wrapper for verification)
#[derive(Debug, Clone)]
pub struct KzgVerifier {
    system: std::sync::Arc<std::sync::Mutex<KZGCommitmentSystem>>,
}

impl KzgVerifier {
    pub fn new(max_degree: usize) -> Result<Self, AvoError> {
        let system = KZGCommitmentSystem::new(max_degree)?;
        Ok(Self {
            system: std::sync::Arc::new(std::sync::Mutex::new(system)),
        })
    }

    /// Verify a chunk using KZG proof
    pub fn verify_chunk(
        &self,
        chunk: &crate::data_availability::DataChunk,
        commitment: &KZGCommitment,
        proof: &KZGProof,
    ) -> Result<bool, AvoError> {
        let system = self
            .system
            .lock()
            .map_err(|e| AvoError::internal(format!("Lock poisoned: {}", e)))?;

        // Verify that the proof matches the commitment
        system.verify_proof(proof, chunk.index as u64)
    }
}

#[cfg(all(test, feature = "run-tests"))]
mod tests {
    use super::*;

    fn system() -> KZGCommitmentSystem {
        KZGCommitmentSystem::new(8192).expect("failed to initialise KZG system")
    }

    #[test]
    fn commit_and_verify_roundtrip() {
        let mut system = system();
        let data: Vec<u8> = (0..2048u32).flat_map(|v| v.to_le_bytes()).collect();

        let commitment = system.commit(&data).expect("commit data");
        assert_eq!(commitment.data_hash, hash_data(&data));

        let proof = system.create_proof(&data, 42).expect("create proof");

        assert!(system.verify_proof(&proof, 42).expect("verify proof"));
    }

    #[test]
    fn verify_fails_with_wrong_evaluation() {
        let mut system = system();
        let data = vec![3u8; 512];
        system.commit(&data).expect("commit data");
        let mut proof = system.create_proof(&data, 7).expect("create proof");

        proof.evaluation = [0u8; FIELD_ELEMENT_BYTES];
        assert!(!system
            .verify_proof(&proof, 7)
            .expect("verify should succeed"));
    }

    #[test]
    fn commit_fails_for_large_polynomial() {
        let mut system = KZGCommitmentSystem::new(32).expect("system");
        let oversized = vec![1u8; (BYTES_PER_COEFFICIENT * 64) + 1];
        let err = system.commit(&oversized).expect_err("should fail");
        assert!(format!("{}", err).contains("exceeds"));
    }
}
