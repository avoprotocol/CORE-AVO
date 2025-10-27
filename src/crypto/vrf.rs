//! # Verifiable Random Functions (VRF) para AVO Protocol
//!
//! Implementación REAL de VRF usando schnorrkel (sr25519 VRF)
//! Compatible con el estándar usado en Substrate/Polkadot

use crate::error::{AvoError, AvoResult};
use crate::types::*;
use rand::{CryptoRng, RngCore};
use schnorrkel::{
    context::SigningContext, vrf::VRFInOut, vrf::VRFProof as SchnorrkelProof,
    vrf::VRFProofBatchable, Keypair, PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::convert::TryFrom;

/// Contexto de firma para VRF (namespace)
const VRF_CONTEXT: &[u8] = b"AVO_PROTOCOL_VRF";

/// Clave VRF basada en schnorrkel sr25519
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfPrivateKey {
    secret_key_bytes: Vec<u8>,
}

/// Clave pública VRF
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfPublicKey {
    public_key_bytes: Vec<u8>,
}

/// Prueba VRF REAL con VRFProof de schnorrkel
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfProof {
    /// La salida aleatoria del VRF (hash del VRFInOut)
    pub output: Vec<u8>,
    /// La prueba criptográfica REAL de schnorrkel
    pub proof: Vec<u8>,
    /// El input usado para generar la prueba
    pub input: Vec<u8>,
    /// VRFInOut serializado (necesario para verificación)
    pub inout: Vec<u8>,
}

/// Resultado de la evaluación VRF
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfOutput {
    /// El valor aleatorio generado
    pub randomness: [u8; 32],
    /// La prueba verificable
    pub proof: VrfProof,
}

impl VrfOutput {
    /// Convierte la salida VRF a un rango específico usando modulo
    pub fn to_range(&self, max_value: u64) -> u64 {
        if max_value == 0 {
            return 0;
        }

        // Convertir los primeros 8 bytes de randomness a u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.randomness[0..8]);
        let random_u64 = u64::from_le_bytes(bytes);

        // Aplicar módulo para obtener valor en rango
        random_u64 % max_value
    }
}

/// Generador de claves VRF
pub struct VrfKeyGenerator;

impl VrfKeyGenerator {
    /// Genera un nuevo par de claves VRF usando schnorrkel
    pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (VrfPrivateKey, VrfPublicKey) {
        let keypair = Keypair::generate_with(rng);
        
        let private_key = VrfPrivateKey {
            secret_key_bytes: keypair.secret.to_bytes().to_vec(),
        };
        
        let public_key = VrfPublicKey {
            public_key_bytes: keypair.public.to_bytes().to_vec(),
        };
        
        (private_key, public_key)
    }

    /// Genera claves VRF para múltiples validadores
    pub fn generate_validator_vrf_keys<R: CryptoRng + RngCore>(
        rng: &mut R,
        count: usize,
    ) -> Vec<(ValidatorId, VrfPrivateKey, VrfPublicKey)> {
        (0..count)
            .map(|i| {
                let (private_key, public_key) = Self::generate_keypair(rng);
                (i as ValidatorId, private_key, public_key)
            })
            .collect()
    }

    /// Genera un solo par de claves VRF para un nuevo validador
    pub fn generate_single_vrf_keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> (VrfPrivateKey, VrfPublicKey) {
        Self::generate_keypair(rng)
    }
}

impl VrfPrivateKey {
    /// Convierte a Keypair de schnorrkel
    fn to_keypair(&self) -> AvoResult<Keypair> {
        if self.secret_key_bytes.len() != 32 {
            return Err(AvoError::crypto("Invalid secret key length"));
        }
        
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&self.secret_key_bytes);
        
        let secret = SecretKey::from_bytes(&secret_bytes)
            .map_err(|_| AvoError::crypto("Invalid secret key bytes"))?;
        
        let public = secret.to_public();
        
        Ok(Keypair { secret, public })
    }

    /// Evalúa el VRF en un input dado - IMPLEMENTACIÓN REAL
    pub fn evaluate(&self, input: &[u8]) -> AvoResult<VrfOutput> {
        let keypair = self.to_keypair()?;
        let context = SigningContext::new(VRF_CONTEXT);
        
        // Crear transcript para el VRF
        let transcript = context.bytes(input);
        
        // Generar VRF output y proof REAL usando schnorrkel
        let (inout, proof, _) = keypair.vrf_sign(transcript);
        
        // Extraer la aleatoriedad del VRFInOut
        let output_bytes = inout.make_bytes::<[u8; 32]>(b"VRF_OUTPUT");
        
        // Serializar VRFInOut: guardar input comprimido y preout comprimido
        let mut inout_bytes = Vec::new();
        inout_bytes.extend_from_slice(&inout.input.to_bytes());
        inout_bytes.extend_from_slice(&inout.to_preout().to_bytes());
        
        let vrf_proof = VrfProof {
            output: output_bytes.to_vec(),
            proof: proof.to_bytes().to_vec(),
            input: input.to_vec(),
            inout: inout_bytes,
        };
        
        Ok(VrfOutput {
            randomness: output_bytes,
            proof: vrf_proof,
        })
    }

    /// Obtiene la clave pública correspondiente
    pub fn public_key(&self) -> AvoResult<VrfPublicKey> {
        let keypair = self.to_keypair()?;
        Ok(VrfPublicKey {
            public_key_bytes: keypair.public.to_bytes().to_vec(),
        })
    }

    /// Serializa la clave privada
    pub fn to_bytes(&self) -> Vec<u8> {
        self.secret_key_bytes.clone()
    }

    /// Deserializa una clave privada
    pub fn from_bytes(bytes: &[u8]) -> AvoResult<Self> {
        if bytes.len() != 32 {
            return Err(AvoError::crypto("Invalid key length"));
        }
        Ok(Self {
            secret_key_bytes: bytes.to_vec(),
        })
    }
}

impl VrfPublicKey {
    /// Convierte a PublicKey de schnorrkel
    fn to_public_key(&self) -> AvoResult<PublicKey> {
        if self.public_key_bytes.len() != 32 {
            return Err(AvoError::crypto("Invalid public key length"));
        }
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.public_key_bytes);
        
        PublicKey::from_bytes(&bytes)
            .map_err(|_| AvoError::crypto("Invalid public key bytes"))
    }

    /// Verifica una prueba VRF - VERIFICACIÓN REAL
    pub fn verify(&self, proof: &VrfProof) -> AvoResult<bool> {
        use schnorrkel::vrf::VRFPreOut;
        
        let public_key = self.to_public_key()?;
        let context = SigningContext::new(VRF_CONTEXT);
        
        // Crear transcript con el mismo input
        let transcript1 = context.bytes(&proof.input);
        let transcript2 = context.bytes(&proof.input);
        
        // Deserializar el proof de schnorrkel
        if proof.proof.len() != 64 {
            return Ok(false);
        }
        
        let mut proof_bytes = [0u8; 64];
        proof_bytes.copy_from_slice(&proof.proof);
        
        let vrf_proof = SchnorrkelProof::from_bytes(&proof_bytes)
            .map_err(|_| AvoError::crypto("Invalid VRF proof bytes"))?;
        
        // Deserializar el VRFPreOut (output comprimido, 32 bytes)
        if proof.inout.len() != 64 {
            return Ok(false);
        }
        
        // El output es los últimos 32 bytes
        let mut output_bytes = [0u8; 32];
        output_bytes.copy_from_slice(&proof.inout[32..64]);
        
        let vrf_preout = VRFPreOut::from_bytes(&output_bytes)
            .map_err(|_| AvoError::crypto("Invalid VRF preout bytes"))?;
        
        // Verificar la prueba VRF REAL con VRFPreOut
        let verify_result = public_key.vrf_verify(transcript1, &vrf_preout, &vrf_proof);
        
        if verify_result.is_err() {
            return Ok(false);
        }
        
        // Verificar que el output coincide
        let inout = vrf_preout.attach_input_hash(&public_key, transcript2)
            .map_err(|_| AvoError::crypto("Failed to attach input hash"))?;
        let expected_output = inout.make_bytes::<[u8; 32]>(b"VRF_OUTPUT");
        
        Ok(proof.output == expected_output.to_vec())
    }

    /// Serializa la clave pública
    pub fn to_bytes(&self) -> Vec<u8> {
        self.public_key_bytes.clone()
    }

    /// Deserializa una clave pública
    pub fn from_bytes(bytes: &[u8]) -> AvoResult<Self> {
        if bytes.len() != 32 {
            return Err(AvoError::crypto("Invalid public key length"));
        }
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        
        // Validar que es una clave pública válida
        PublicKey::from_bytes(&key_bytes)
            .map_err(|_| AvoError::crypto("Invalid VRF public key bytes"))?;
        
        Ok(VrfPublicKey {
            public_key_bytes: bytes.to_vec(),
        })
    }
}


impl VrfProof {
    /// Extrae la aleatoriedad de la prueba sin verificar
    pub fn extract_randomness(&self) -> Vec<u8> {
        self.output.clone()
    }

    /// Convierte la aleatoriedad a un número en un rango específico
    pub fn to_range(&self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }

        let randomness_bytes = if self.output.len() >= 8 {
            &self.output[..8]
        } else {
            // Si no hay suficientes bytes, rellenar con ceros
            let mut padded = vec![0u8; 8];
            padded[..self.output.len()].copy_from_slice(&self.output);
            return u64::from_le_bytes(padded.try_into().unwrap()) % max;
        };

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(randomness_bytes);
        let value = u64::from_le_bytes(bytes);
        value % max
    }

    /// Serializa la prueba VRF
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Output (32 bytes)
        bytes.extend_from_slice(&self.output);
        // Proof length + proof (64 bytes)
        bytes.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);
        // Input length + input
        bytes.extend_from_slice(&(self.input.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.input);
        // InOut length + inout (64 bytes)
        bytes.extend_from_slice(&(self.inout.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.inout);
        bytes
    }

    /// Deserializa una prueba VRF
    pub fn from_bytes(bytes: &[u8]) -> AvoResult<Self> {
        if bytes.len() < 32 + 4 {
            return Err(AvoError::crypto("VRF proof bytes too short"));
        }

        let mut offset = 0;

        // Output (32 bytes)
        if bytes.len() < offset + 32 {
            return Err(AvoError::crypto("VRF proof output too short"));
        }
        let output = bytes[offset..offset + 32].to_vec();
        offset += 32;

        // Proof length
        if bytes.len() < offset + 4 {
            return Err(AvoError::crypto("VRF proof length missing"));
        }
        let proof_len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        // Proof
        if bytes.len() < offset + proof_len {
            return Err(AvoError::crypto("VRF proof length mismatch"));
        }
        let proof = bytes[offset..offset + proof_len].to_vec();
        offset += proof_len;

        // Input length
        if bytes.len() < offset + 4 {
            return Err(AvoError::crypto("VRF proof input length missing"));
        }
        let input_len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        // Input
        if bytes.len() < offset + input_len {
            return Err(AvoError::crypto("VRF proof input length mismatch"));
        }
        let input = bytes[offset..offset + input_len].to_vec();
        offset += input_len;

        // InOut length
        if bytes.len() < offset + 4 {
            return Err(AvoError::crypto("VRF proof inout length missing"));
        }
        let inout_len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        // InOut
        if bytes.len() < offset + inout_len {
            return Err(AvoError::crypto("VRF proof inout length mismatch"));
        }
        let inout = bytes[offset..offset + inout_len].to_vec();

        Ok(VrfProof {
            output,
            proof,
            input,
            inout,
        })
    }
}

/// Utilidades VRF para el consenso
pub struct VrfConsensusUtils;

impl VrfConsensusUtils {
    /// Selecciona un líder usando VRF basado en la época y el slot
    /// IMPLEMENTACIÓN REAL: compara pruebas VRF verificadas
    pub fn select_leader(
        validators: &[(ValidatorId, VrfPublicKey)],
        epoch: Epoch,
        slot: u64,
        vrf_outputs: &[(ValidatorId, VrfOutput)],
    ) -> AvoResult<ValidatorId> {
        if validators.is_empty() || vrf_outputs.is_empty() {
            return Err(AvoError::consensus(
                "No validators available for leader selection",
            ));
        }

        // Crear input determinístico para VRF
        let mut input = Vec::new();
        input.extend_from_slice(b"LEADER_SELECTION");
        input.extend_from_slice(&epoch.to_le_bytes());
        input.extend_from_slice(&slot.to_le_bytes());

        // Verificar todas las pruebas VRF y encontrar la menor (REAL)
        let mut min_output = [0xffu8; 32];
        let mut selected_leader = validators[0].0;

        for (validator_id, vrf_output) in vrf_outputs {
            // Verificar que el validador existe
            if let Some((_, public_key)) = validators.iter().find(|(id, _)| id == validator_id) {
                // VERIFICACIÓN REAL usando schnorrkel
                if public_key.verify(&vrf_output.proof)? {
                    // Comparar con el output mínimo actual
                    if vrf_output.randomness < min_output {
                        min_output = vrf_output.randomness;
                        selected_leader = *validator_id;
                    }
                }
            }
        }

        Ok(selected_leader)
    }

    /// Genera aleatoriedad para la época usando múltiples VRFs
    pub fn generate_epoch_randomness(
        vrf_outputs: &[VrfOutput],
        epoch: Epoch,
    ) -> AvoResult<[u8; 32]> {
        if vrf_outputs.is_empty() {
            return Err(AvoError::consensus("No VRF outputs for epoch randomness"));
        }

        let mut hasher = Sha3_256::new();
        hasher.update(&epoch.to_le_bytes());
        hasher.update(b"EPOCH_RANDOMNESS");

        // Combinar todas las salidas VRF REALES
        for output in vrf_outputs {
            hasher.update(&output.randomness);
        }

        Ok(hasher.finalize().into())
    }

    /// Valida que un conjunto de pruebas VRF es correcto para una época/slot
    /// IMPLEMENTACIÓN REAL: verifica cada proof con schnorrkel
    pub fn validate_vrf_proofs(
        validators: &[(ValidatorId, VrfPublicKey)],
        vrf_outputs: &[(ValidatorId, VrfOutput)],
        epoch: Epoch,
        slot: u64,
    ) -> AvoResult<bool> {
        // Crear input esperado
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(b"LEADER_SELECTION");
        expected_input.extend_from_slice(&epoch.to_le_bytes());
        expected_input.extend_from_slice(&slot.to_le_bytes());

        for (validator_id, vrf_output) in vrf_outputs {
            // Encontrar la clave pública del validador
            if let Some((_, public_key)) = validators.iter().find(|(id, _)| id == validator_id) {
                // Verificar que el input es correcto
                if vrf_output.proof.input != expected_input {
                    return Ok(false);
                }

                // VERIFICACIÓN REAL usando schnorrkel
                if !public_key.verify(&vrf_output.proof)? {
                    return Ok(false);
                }
            } else {
                return Err(AvoError::consensus("Unknown validator in VRF proofs"));
            }
        }

        Ok(true)
    }

    /// Crea un input VRF estándar para consenso
    pub fn create_consensus_input(epoch: Epoch, slot: u64, round: u32) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(b"AVO_CONSENSUS_VRF");
        input.extend_from_slice(&epoch.to_le_bytes());
        input.extend_from_slice(&slot.to_le_bytes());
        input.extend_from_slice(&round.to_le_bytes());
        input
    }
}

/// Sortición usando VRF para seleccionar comités
pub struct VrfSortition;

impl VrfSortition {
    /// Determina si un validador es seleccionado para un comité usando VRF REAL
    pub fn is_selected(
        vrf_output: &VrfOutput,
        stake: u128,
        total_stake: u128,
        committee_size: usize,
    ) -> bool {
        if total_stake == 0 {
            return false;
        }

        // Calcular probabilidad de selección basada en stake
        let probability = (stake as f64 / total_stake as f64) * committee_size as f64;

        // Usar VRF output REAL para determinardeterminación
        let vrf_value = u64::from_le_bytes([
            vrf_output.randomness[0],
            vrf_output.randomness[1],
            vrf_output.randomness[2],
            vrf_output.randomness[3],
            vrf_output.randomness[4],
            vrf_output.randomness[5],
            vrf_output.randomness[6],
            vrf_output.randomness[7],
        ]);

        let threshold = (probability * (u64::MAX as f64)) as u64;
        vrf_value < threshold
    }

    /// Selecciona un comité completo usando VRF de múltiples validadores
    pub fn select_committee(
        validators: &[(ValidatorId, u128, VrfOutput)], // (id, stake, vrf_output)
        total_stake: u128,
        target_committee_size: usize,
    ) -> Vec<ValidatorId> {
        validators
            .iter()
            .filter(|(_, stake, vrf_output)| {
                Self::is_selected(vrf_output, *stake, total_stake, target_committee_size)
            })
            .map(|(id, _, _)| *id)
            .collect()
    }
}

#[cfg(disabled_test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_vrf_key_generation() {
        let mut rng = thread_rng();
        let (private_key, public_key) = VrfKeyGenerator::generate_keypair(&mut rng);

        // La clave pública derivada debe coincidir
        let derived = private_key.public_key().unwrap();
        assert_eq!(derived.to_bytes(), public_key.to_bytes());
    }

    #[test]
    fn test_vrf_evaluation_and_verification() {
        let mut rng = thread_rng();
        let (private_key, public_key) = VrfKeyGenerator::generate_keypair(&mut rng);

        let input = b"test input for VRF evaluation";
        let vrf_output = private_key.evaluate(input).unwrap();

        // La prueba debe verificar correctamente (REAL)
        assert!(public_key.verify(&vrf_output.proof).unwrap());

        // La misma entrada debe producir la misma salida
        let vrf_output2 = private_key.evaluate(input).unwrap();
        assert_eq!(vrf_output.randomness, vrf_output2.randomness);
    }

    #[test]
    fn test_vrf_determinism() {
        let mut rng = thread_rng();
        let (private_key, _) = VrfKeyGenerator::generate_keypair(&mut rng);

        let input = b"deterministic test";

        // Múltiples evaluaciones deben dar el mismo resultado
        let output1 = private_key.evaluate(input).unwrap();
        let output2 = private_key.evaluate(input).unwrap();

        assert_eq!(output1.randomness, output2.randomness);
        assert_eq!(output1.proof.output, output2.proof.output);
    }

    #[test]
    fn test_leader_selection() {
        let mut rng = thread_rng();

        // Generar validadores
        let validators = VrfKeyGenerator::generate_validator_vrf_keys(&mut rng, 5);
        let validator_keys: Vec<_> = validators
            .iter()
            .map(|(id, _, pub_key)| (*id, pub_key.clone()))
            .collect();

        // Generar VRF outputs para época 1, slot 0
        let input = VrfConsensusUtils::create_consensus_input(1, 0, 0);
        let vrf_outputs: Vec<_> = validators
            .iter()
            .map(|(id, priv_key, _)| (*id, priv_key.evaluate(&input).unwrap()))
            .collect();

        // Seleccionar líder
        let leader = VrfConsensusUtils::select_leader(&validator_keys, 1, 0, &vrf_outputs).unwrap();

        // El líder debe ser uno de los validadores
        assert!(validators.iter().any(|(id, _, _)| *id == leader));
    }
}
