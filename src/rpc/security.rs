//! # RPC Security Module
//! 
//! Implementa medidas de seguridad para operaciones RPC críticas:
//! - Verificación de firmas Ed25519
//! - Sistema de nonces anti-replay
//! - Rate limiting por IP/address

use crate::error::AvoError;
use crate::AvoResult;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, SIGNATURE_LENGTH, PUBLIC_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

// Global storage para nonces y rate limiting
lazy_static::lazy_static! {
    static ref NONCE_STORE: Mutex<NonceStore> = Mutex::new(NonceStore::new());
    static ref RATE_LIMITER: Mutex<RateLimiter> = Mutex::new(RateLimiter::new());
}

/// Estructura para almacenar nonces usados (anti-replay)
#[derive(Debug)]
pub struct NonceStore {
    /// Mapa de address -> último nonce usado
    used_nonces: HashMap<String, u64>,
    /// Timestamp de limpieza de nonces antiguos
    last_cleanup: u64,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            used_nonces: HashMap::new(),
            last_cleanup: Self::current_timestamp(),
        }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Verificar y registrar un nonce
    pub fn verify_and_use_nonce(&mut self, address: &str, nonce: u64) -> AvoResult<()> {
        // Limpiar nonces antiguos cada hora
        let now = Self::current_timestamp();
        if now - self.last_cleanup > 3600 {
            self.cleanup_old_nonces();
            self.last_cleanup = now;
        }

        // Obtener el último nonce usado para esta address
        let last_nonce = self.used_nonces.get(address).copied().unwrap_or(0);

        // El nonce debe ser mayor que el último usado
        if nonce <= last_nonce {
            warn!(
                "🚨 [SECURITY] Nonce replay detected! Address: {}, nonce: {}, last_nonce: {}",
                address, nonce, last_nonce
            );
            return Err(AvoError::validation(&format!(
                "Invalid nonce. Expected > {}, got {}",
                last_nonce, nonce
            )));
        }

        // Registrar el nuevo nonce
        self.used_nonces.insert(address.to_string(), nonce);
        debug!("✅ [SECURITY] Nonce {} accepted for {}", nonce, address);

        Ok(())
    }

    /// Limpiar nonces de addresses inactivas (> 24h sin actividad)
    fn cleanup_old_nonces(&mut self) {
        // Por ahora, mantener todos los nonces
        // En producción, podrías limpiar basado en timestamp de última actividad
        debug!("🧹 [SECURITY] Nonce cleanup triggered");
    }

    /// Obtener el siguiente nonce válido para una address
    pub fn get_next_nonce(&self, address: &str) -> u64 {
        self.used_nonces.get(address).copied().unwrap_or(0) + 1
    }
}

/// Rate limiter para prevenir ataques de fuerza bruta
#[derive(Debug)]
pub struct RateLimiter {
    /// Mapa de address -> lista de timestamps de intentos
    attempts: HashMap<String, Vec<u64>>,
    /// Ventana de tiempo para rate limiting (segundos)
    window_secs: u64,
    /// Máximo número de intentos en la ventana
    max_attempts: usize,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            window_secs: 60, // 1 minuto
            max_attempts: 5, // 5 intentos por minuto
        }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Verificar si una address puede hacer una operación (no excede rate limit)
    pub fn check_rate_limit(&mut self, address: &str) -> AvoResult<()> {
        let now = Self::current_timestamp();
        let window_start = now.saturating_sub(self.window_secs);

        // Obtener o crear lista de intentos para esta address
        let attempts = self.attempts.entry(address.to_string()).or_insert_with(Vec::new);

        // Filtrar intentos dentro de la ventana de tiempo
        attempts.retain(|&timestamp| timestamp > window_start);

        // Verificar si excede el límite
        if attempts.len() >= self.max_attempts {
            warn!(
                "🚨 [SECURITY] Rate limit exceeded for {}! {} attempts in {} seconds",
                address,
                attempts.len(),
                self.window_secs
            );
            return Err(AvoError::validation(&format!(
                "Rate limit exceeded. Max {} attempts per {} seconds",
                self.max_attempts, self.window_secs
            )));
        }

        // Registrar el nuevo intento
        attempts.push(now);
        debug!(
            "✅ [SECURITY] Rate limit OK for {} ({}/{} attempts)",
            address,
            attempts.len(),
            self.max_attempts
        );

        Ok(())
    }

    /// Resetear contador para una address (ej: después de operación exitosa)
    pub fn reset(&mut self, address: &str) {
        self.attempts.remove(address);
        debug!("🔄 [SECURITY] Rate limit reset for {}", address);
    }
}

/// Estructura para datos firmados
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    pub address: String,
    pub nonce: u64,
    pub operation: String,
    pub data: String,
    pub timestamp: u64,
}

impl SignedMessage {
    /// Crear mensaje para firmar
    pub fn new(address: String, nonce: u64, operation: String, data: String) -> Self {
        Self {
            address,
            nonce,
            operation,
            data,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Serializar para firma (formato determinístico)
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        format!(
            "AVO_PROTOCOL\nAddress: {}\nNonce: {}\nOperation: {}\nData: {}\nTimestamp: {}",
            self.address, self.nonce, self.operation, self.data, self.timestamp
        )
        .into_bytes()
    }

    /// Verificar que el timestamp no está expirado (5 minutos)
    pub fn verify_timestamp(&self) -> AvoResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let age = now.saturating_sub(self.timestamp);
        
        if age > 300 {
            // 5 minutos
            warn!(
                "🚨 [SECURITY] Expired message! Age: {} seconds",
                age
            );
            return Err(AvoError::validation(&format!(
                "Message expired. Age: {} seconds, max: 300",
                age
            )));
        }

        Ok(())
    }
}

/// Verificar firma Ed25519 completa
pub fn verify_signature(
    message: &SignedMessage,
    signature_hex: &str,
    public_key_hex: &str,
) -> AvoResult<()> {
    debug!("🔐 [SECURITY] Verifying Ed25519 signature");

    // 1. Verificar timestamp
    message.verify_timestamp()?;

    // 2. Decodificar firma (hex -> bytes)
    let sig_bytes = hex::decode(signature_hex.trim_start_matches("0x")).map_err(|e| {
        AvoError::validation(&format!("Invalid signature hex: {}", e))
    })?;

    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(AvoError::validation(&format!(
            "Invalid signature length: expected {}, got {}",
            SIGNATURE_LENGTH,
            sig_bytes.len()
        )));
    }

    // 3. Decodificar public key (hex -> bytes)
    let pubkey_bytes = hex::decode(public_key_hex.trim_start_matches("0x")).map_err(|e| {
        AvoError::validation(&format!("Invalid public key hex: {}", e))
    })?;

    if pubkey_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(AvoError::validation(&format!(
            "Invalid public key length: expected {}, got {}",
            PUBLIC_KEY_LENGTH,
            pubkey_bytes.len()
        )));
    }

    // 4. Crear objetos de firma y verifying key
    let sig_array: [u8; SIGNATURE_LENGTH] = sig_bytes
        .try_into()
        .map_err(|_| AvoError::validation("Invalid signature length"))?;
    
    let signature = Signature::from_bytes(&sig_array);

    let pubkey_array: [u8; PUBLIC_KEY_LENGTH] = pubkey_bytes
        .try_into()
        .map_err(|_| AvoError::validation("Invalid public key length"))?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_array).map_err(|e| {
        AvoError::validation(&format!("Invalid public key format: {}", e))
    })?;

    // 5. Verificar firma
    let message_bytes = message.to_signing_bytes();
    
    verifying_key
        .verify(&message_bytes, &signature)
        .map_err(|e| {
            warn!("🚨 [SECURITY] Signature verification failed: {}", e);
            AvoError::validation("Invalid signature: verification failed")
        })?;

    debug!("✅ [SECURITY] Signature verified successfully");
    Ok(())
}

/// Función principal de verificación de seguridad para operaciones críticas
pub fn verify_operation_security(
    address: &str,
    nonce: u64,
    operation: &str,
    data: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> AvoResult<()> {
    debug!(
        "🔐 [SECURITY] Starting security verification for {} operation by {}",
        operation, address
    );

    // 1. Verificar rate limit
    {
        let mut rate_limiter = RATE_LIMITER.lock().unwrap();
        rate_limiter.check_rate_limit(address)?;
    }

    // 2. Crear mensaje firmado
    let message = SignedMessage::new(
        address.to_string(),
        nonce,
        operation.to_string(),
        data.to_string(),
    );

    // 3. Verificar firma
    verify_signature(&message, signature_hex, public_key_hex)?;

    // 4. Verificar y consumir nonce
    {
        let mut nonce_store = NONCE_STORE.lock().unwrap();
        nonce_store.verify_and_use_nonce(address, nonce)?;
    }

    // 5. Resetear rate limit en operación exitosa
    {
        let mut rate_limiter = RATE_LIMITER.lock().unwrap();
        rate_limiter.reset(address);
    }

    debug!("✅ [SECURITY] All security checks passed for {}", address);
    Ok(())
}

/// Obtener el siguiente nonce para una address
pub fn get_next_nonce(address: &str) -> u64 {
    let nonce_store = NONCE_STORE.lock().unwrap();
    nonce_store.get_next_nonce(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_sequential() {
        let mut store = NonceStore::new();
        
        // Nonce 1 debe pasar
        assert!(store.verify_and_use_nonce("0x123", 1).is_ok());
        
        // Nonce 2 debe pasar
        assert!(store.verify_and_use_nonce("0x123", 2).is_ok());
        
        // Nonce 1 debe fallar (replay)
        assert!(store.verify_and_use_nonce("0x123", 1).is_err());
        
        // Nonce 2 debe fallar (replay)
        assert!(store.verify_and_use_nonce("0x123", 2).is_err());
        
        // Nonce 5 debe pasar (salto permitido)
        assert!(store.verify_and_use_nonce("0x123", 5).is_ok());
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new();
        limiter.max_attempts = 3; // Bajar para test
        
        // Primeros 3 intentos deben pasar
        assert!(limiter.check_rate_limit("0x123").is_ok());
        assert!(limiter.check_rate_limit("0x123").is_ok());
        assert!(limiter.check_rate_limit("0x123").is_ok());
        
        // Cuarto intento debe fallar
        assert!(limiter.check_rate_limit("0x123").is_err());
        
        // Resetear debe permitir de nuevo
        limiter.reset("0x123");
        assert!(limiter.check_rate_limit("0x123").is_ok());
    }
}
