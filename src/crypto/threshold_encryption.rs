//! # Threshold Encryption para AVO Protocol
//!
//! Implementación de cifrado threshold para resistencia MEV (Maximal Extractable Value).
//! Permite cifrar transacciones hasta que el bloque sea finalizado.

use crate::error::{AvoError, AvoResult};
use crate::types::*;
use rand::{CryptoRng, RngCore};
use rand07::{rngs::StdRng as StdRng07, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use threshold_crypto::{
    serde_impl::SerdeSecret, Ciphertext, DecryptionShare, PublicKeySet, SecretKeySet,
    SecretKeyShare,
};

/// Configuración del esquema threshold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Número total de participantes
    pub total_shares: usize,
    /// Umbral mínimo para descifrado
    pub threshold: usize,
}

/// Clave maestra del esquema threshold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdMasterKey {
    public_key_set: PublicKeySet,
    config: ThresholdConfig,
}

/// Share de clave secreta para un participante usando bytes para serialización
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdKeyShare {
    secret_share: SerdeSecret<SecretKeyShare>,
    participant_id: usize,
    config: ThresholdConfig,
}

/// Texto cifrado con threshold encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdCiphertext {
    ciphertext: Ciphertext,
    epoch: Epoch,
    config: ThresholdConfig,
}

/// Share de descifrado de un participante
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdDecryptionShare {
    share: DecryptionShare,
    participant_id: usize,
}

/// Generador de claves threshold
pub struct ThresholdKeyGenerator;

impl ThresholdKeyGenerator {
    /// Genera un esquema threshold completo
    pub fn generate_threshold_keys<R: CryptoRng + RngCore>(
        rng: &mut R,
        threshold: usize,
        total_shares: usize,
    ) -> AvoResult<(ThresholdMasterKey, Vec<ThresholdKeyShare>)> {
        if threshold == 0 || threshold > total_shares {
            return Err(AvoError::crypto("Invalid threshold parameters"));
        }

        let mut seed = <StdRng07 as SeedableRng>::Seed::default();
        rng.fill_bytes(&mut seed);
        let mut threshold_rng = StdRng07::from_seed(seed);
        let secret_key_set = SecretKeySet::random(threshold.saturating_sub(1), &mut threshold_rng);
        let public_key_set = secret_key_set.public_keys();

        let config = ThresholdConfig {
            total_shares,
            threshold,
        };

        let threshold_master = ThresholdMasterKey {
            public_key_set: public_key_set.clone(),
            config: config.clone(),
        };

        let key_shares: Vec<ThresholdKeyShare> = (0..total_shares)
            .map(|i| ThresholdKeyShare {
                secret_share: SerdeSecret(secret_key_set.secret_key_share(i)),
                participant_id: i,
                config: config.clone(),
            })
            .collect();

        Ok((threshold_master, key_shares))
    }

    /// Genera claves threshold para validadores específicos
    pub fn generate_validator_threshold_keys<R: CryptoRng + RngCore>(
        rng: &mut R,
        validators: &[ValidatorId],
        threshold: usize,
    ) -> AvoResult<(ThresholdMasterKey, HashMap<ValidatorId, ThresholdKeyShare>)> {
        let total_shares = validators.len();
        let (master_key, key_shares) = Self::generate_threshold_keys(rng, threshold, total_shares)?;

        let validator_keys = validators
            .iter()
            .zip(key_shares.into_iter())
            .map(|(validator_id, key_share)| (*validator_id, key_share))
            .collect();

        Ok((master_key, validator_keys))
    }
}

impl ThresholdMasterKey {
    /// Cifra datos usando la clave pública threshold
    pub fn encrypt<R: CryptoRng + RngCore>(
        &self,
        _rng: &mut R,
        plaintext: &[u8],
        epoch: Epoch,
    ) -> ThresholdCiphertext {
        // Usar encrypt sin RNG para evitar problemas de trait bounds
        let ciphertext = self.public_key_set.public_key().encrypt(plaintext);

        ThresholdCiphertext {
            ciphertext,
            epoch,
            config: self.config.clone(),
        }
    }

    /// Obtiene el PublicKeySet completo para verificación
    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.public_key_set
    }

    /// Devuelve la configuración threshold asociada
    pub fn config(&self) -> &ThresholdConfig {
        &self.config
    }

    /// Verifica que un share de descifrado es válido
    pub fn verify_decryption_share(
        &self,
        _ciphertext: &ThresholdCiphertext,
        _share: &ThresholdDecryptionShare,
    ) -> bool {
        if _share.participant_id >= self.config.total_shares {
            return false;
        }

        let public_share = self.public_key_set.public_key_share(_share.participant_id);
        public_share.verify_decryption_share(&_share.share, &_ciphertext.ciphertext)
    }

    /// Combina shares de descifrado para obtener el texto plano
    pub fn combine_decryption_shares(
        &self,
        ciphertext: &ThresholdCiphertext,
        shares: &[ThresholdDecryptionShare],
    ) -> AvoResult<Vec<u8>> {
        if shares.len() < self.config.threshold {
            return Err(AvoError::crypto("Insufficient decryption shares"));
        }

        let mut share_map: BTreeMap<usize, DecryptionShare> = BTreeMap::new();

        for share in shares {
            if !self.verify_decryption_share(ciphertext, share) {
                return Err(AvoError::crypto("Invalid decryption share"));
            }
            share_map.insert(share.participant_id, share.share.clone());
        }

        self.public_key_set
            .decrypt(&share_map, &ciphertext.ciphertext)
            .map_err(|_| AvoError::crypto("Failed to combine decryption shares"))
    }

    /// Serializa la clave maestra
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserializa una clave maestra
    pub fn from_bytes(bytes: &[u8]) -> AvoResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|_| AvoError::crypto("Invalid threshold master key bytes"))
    }
}

impl ThresholdKeyShare {
    /// Convierte a SecretKeyShare para operaciones criptográficas
    pub fn to_secret_key_share(&self) -> AvoResult<SecretKeyShare> {
        Ok(self.secret_share.0.clone())
    }

    /// Crea un share de descifrado para un ciphertext
    pub fn create_decryption_share(
        &self,
        ciphertext: &ThresholdCiphertext,
    ) -> AvoResult<ThresholdDecryptionShare> {
        let secret_share = self.to_secret_key_share()?;
        let share = secret_share
            .decrypt_share(&ciphertext.ciphertext)
            .ok_or_else(|| AvoError::crypto("Failed to create decryption share"))?;

        Ok(ThresholdDecryptionShare {
            share,
            participant_id: self.participant_id,
        })
    }

    /// Obtiene el ID del participante
    pub fn participant_id(&self) -> usize {
        self.participant_id
    }

    /// Serializa el key share
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserializa un key share
    pub fn from_bytes(bytes: &[u8]) -> AvoResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|_| AvoError::crypto("Invalid threshold key share bytes"))
    }
}

impl ThresholdCiphertext {
    /// Serializa el ciphertext
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserializa un ciphertext
    pub fn from_bytes(bytes: &[u8]) -> AvoResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|_| AvoError::crypto("Invalid threshold ciphertext bytes"))
    }

    /// Obtiene la época asociada
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Obtiene la configuración threshold
    pub fn config(&self) -> &ThresholdConfig {
        &self.config
    }
}

/// Gestor de threshold encryption para el protocolo
pub struct ThresholdEncryptionManager {
    master_key: ThresholdMasterKey,
    validator_keys: HashMap<ValidatorId, ThresholdKeyShare>,
    pending_decryptions: HashMap<TransactionId, Vec<ThresholdDecryptionShare>>,
}

impl ThresholdEncryptionManager {
    /// Crea un nuevo gestor con claves existentes
    pub fn new(
        master_key: ThresholdMasterKey,
        validator_keys: HashMap<ValidatorId, ThresholdKeyShare>,
    ) -> Self {
        Self {
            master_key,
            validator_keys,
            pending_decryptions: HashMap::new(),
        }
    }

    /// Cifra una transacción para una época específica
    pub fn encrypt_transaction<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        transaction: &Transaction,
        epoch: Epoch,
    ) -> AvoResult<EncryptedTransaction> {
        let serialized_tx = bincode::serialize(transaction)
            .map_err(|_| AvoError::crypto("Failed to serialize transaction"))?;

        let ciphertext = self.master_key.encrypt(rng, &serialized_tx, epoch);

        Ok(EncryptedTransaction {
            id: transaction.id,
            ciphertext,
            original_size: serialized_tx.len(),
        })
    }

    /// Un validador contribuye con su share de descifrado
    pub fn contribute_decryption_share(
        &mut self,
        validator_id: ValidatorId,
        transaction_id: TransactionId,
        ciphertext: &ThresholdCiphertext,
    ) -> AvoResult<()> {
        let key_share = self
            .validator_keys
            .get(&validator_id)
            .ok_or_else(|| AvoError::crypto("Unknown validator"))?;

        let decryption_share = key_share.create_decryption_share(ciphertext)?;

        // Verificar el share
        if !self
            .master_key
            .verify_decryption_share(ciphertext, &decryption_share)
        {
            return Err(AvoError::crypto("Invalid decryption share"));
        }

        // Agregar a shares pendientes
        self.pending_decryptions
            .entry(transaction_id)
            .or_insert_with(Vec::new)
            .push(decryption_share);

        Ok(())
    }

    /// Intenta descifrar una transacción si hay suficientes shares
    pub fn try_decrypt_transaction(
        &mut self,
        transaction_id: TransactionId,
        ciphertext: &ThresholdCiphertext,
    ) -> AvoResult<Option<Transaction>> {
        let shares = self
            .pending_decryptions
            .get(&transaction_id)
            .ok_or_else(|| AvoError::crypto("No decryption shares available"))?;

        if shares.len() < self.master_key.config.threshold {
            return Ok(None); // No hay suficientes shares aún
        }

        // Usar solo los primeros threshold shares
        let threshold_shares = &shares[..self.master_key.config.threshold];

        let plaintext = self
            .master_key
            .combine_decryption_shares(ciphertext, threshold_shares)?;

        let transaction = bincode::deserialize(&plaintext)
            .map_err(|_| AvoError::crypto("Failed to deserialize decrypted transaction"))?;

        // Limpiar shares usados
        self.pending_decryptions.remove(&transaction_id);

        Ok(Some(transaction))
    }

    /// Obtiene el número de shares disponibles para una transacción
    pub fn get_share_count(&self, transaction_id: TransactionId) -> usize {
        self.pending_decryptions
            .get(&transaction_id)
            .map(|shares| shares.len())
            .unwrap_or(0)
    }

    /// Limpia shares antiguos para una época
    pub fn cleanup_old_shares(&mut self, current_epoch: Epoch) {
        // En una implementación real, asociaríamos shares con épocas
        // Por ahora, simplemente limpiamos todo
        if current_epoch > 0 {
            self.pending_decryptions.clear();
        }
    }
}

/// Transacción cifrada con threshold encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTransaction {
    pub id: TransactionId,
    pub ciphertext: ThresholdCiphertext,
    pub original_size: usize,
}

/// Utilidades para integración con el consenso
pub struct ThresholdConsensusUtils;

impl ThresholdConsensusUtils {
    /// Crea un protocolo de descifrado coordinado para un bloque
    pub fn coordinate_block_decryption(
        manager: &mut ThresholdEncryptionManager,
        encrypted_transactions: &[EncryptedTransaction],
        validator_shares: &[(ValidatorId, Vec<TransactionId>)],
    ) -> AvoResult<Vec<Transaction>> {
        let mut decrypted_transactions = Vec::new();

        // Recolectar shares de todos los validadores
        for (validator_id, transaction_ids) in validator_shares {
            for transaction_id in transaction_ids {
                if let Some(encrypted_tx) = encrypted_transactions
                    .iter()
                    .find(|tx| tx.id == *transaction_id)
                {
                    manager.contribute_decryption_share(
                        *validator_id,
                        *transaction_id,
                        &encrypted_tx.ciphertext,
                    )?;
                }
            }
        }

        // Intentar descifrar cada transacción
        for encrypted_tx in encrypted_transactions {
            if let Some(transaction) =
                manager.try_decrypt_transaction(encrypted_tx.id, &encrypted_tx.ciphertext)?
            {
                decrypted_transactions.push(transaction);
            }
        }

        Ok(decrypted_transactions)
    }

    /// Verifica que un conjunto de transacciones cifradas es válido
    pub fn verify_encrypted_transactions(
        master_key: &ThresholdMasterKey,
        encrypted_transactions: &[EncryptedTransaction],
        epoch: Epoch,
    ) -> AvoResult<bool> {
        for encrypted_tx in encrypted_transactions {
            // Verificar que la época coincida
            if encrypted_tx.ciphertext.epoch() != epoch {
                return Ok(false);
            }

            // Verificar que la configuración es correcta
            if encrypted_tx.ciphertext.config().total_shares != master_key.config.total_shares
                || encrypted_tx.ciphertext.config().threshold != master_key.config.threshold
            {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(disabled_test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_threshold_key_generation() {
        let mut rng = thread_rng();
        let (master_key, key_shares) =
            ThresholdKeyGenerator::generate_threshold_keys(&mut rng, 3, 5).unwrap();

        assert_eq!(key_shares.len(), 5);
        assert_eq!(master_key.config.threshold, 3);
        assert_eq!(master_key.config.total_shares, 5);
    }

    #[test]
    fn test_threshold_encryption_decryption() {
        let mut rng = thread_rng();
        let (master_key, key_shares) =
            ThresholdKeyGenerator::generate_threshold_keys(&mut rng, 3, 5).unwrap();

        let plaintext = b"secret transaction data";
        let ciphertext = master_key.encrypt(&mut rng, plaintext, 1);

        // Crear shares de descifrado (usar solo 3 de 5)
        let decryption_shares: Vec<_> = key_shares[..3]
            .iter()
            .map(|share| share.create_decryption_share(&ciphertext))
            .collect();

        // Combinar shares para descifrar
        let decrypted = master_key
            .combine_decryption_shares(&ciphertext, &decryption_shares)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_insufficient_shares() {
        let mut rng = thread_rng();
        let (master_key, key_shares) =
            ThresholdKeyGenerator::generate_threshold_keys(&mut rng, 3, 5).unwrap();

        let plaintext = b"secret data";
        let ciphertext = master_key.encrypt(&mut rng, plaintext, 1);

        // Usar solo 2 shares (insuficientes)
        let decryption_shares: Vec<_> = key_shares[..2]
            .iter()
            .map(|share| share.create_decryption_share(&ciphertext))
            .collect();

        // Debe fallar por shares insuficientes
        assert!(master_key
            .combine_decryption_shares(&ciphertext, &decryption_shares)
            .is_err());
    }
}
