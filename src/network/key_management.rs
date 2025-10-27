//! # Sistema de gestión de claves criptográficas para AVO Protocol
//!
//! Maneja la generación, almacenamiento y uso de claves para:
//! - Identidad de nodo (Ed25519)  
//! - Firma de mensajes (BLS)
//! - Derivación de KademliaId

use crate::error::*;
use crate::network::kademlia_dht::KademliaId;
use crate::types::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{debug, error, info, warn};

/// Conjunto de claves para un nodo P2P
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeKeyPair {
    /// Clave secreta Ed25519
    pub secret_key: [u8; 32],
    /// Clave pública Ed25519  
    pub public_key: [u8; 32],
    /// ID Kademlia derivado de la clave pública
    pub kademlia_id: KademliaId,
    /// Timestamp de creación
    pub created_at: u64,
}

impl NodeKeyPair {
    /// Generar nuevo par de claves
    pub fn generate() -> AvoResult<Self> {
        let _csprng = OsRng {};
        let secret_key_bytes: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);

        let secret_key = signing_key.to_bytes();
        let public_key = signing_key.verifying_key().to_bytes();

        // Derivar KademliaId de la clave pública
        let kademlia_id = Self::derive_kademlia_id(&public_key);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Self {
            secret_key,
            public_key,
            kademlia_id,
            created_at,
        })
    }

    /// Derivar KademliaId de clave pública
    fn derive_kademlia_id(public_key: &[u8; 32]) -> KademliaId {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AVO_KADEMLIA_ID:");
        hasher.update(public_key);
        let result = hasher.finalize();
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&result[..]);
        KademliaId::new(id_bytes)
    }

    /// Firmar mensaje
    pub fn sign(&self, message: &[u8]) -> AvoResult<[u8; 64]> {
        let signing_key = SigningKey::from_bytes(&self.secret_key);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    /// Verificar firma
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        if let Ok(verifying_key) = VerifyingKey::from_bytes(&self.public_key) {
            let sig = Signature::from_bytes(signature);
            return verifying_key.verify(message, &sig).is_ok();
        }
        false
    }

    /// Verificar firma con clave pública externa
    pub fn verify_external(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        if let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) {
            let sig = Signature::from_bytes(signature);
            return verifying_key.verify(message, &sig).is_ok();
        }
        false
    }

    /// Cargar desde archivo
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> AvoResult<Self> {
        let data = fs::read_to_string(path)
            .map_err(|e| AvoError::network(format!("Failed to read key file: {}", e)))?;

        let keypair: Self = serde_json::from_str(&data)
            .map_err(|e| AvoError::crypto(format!("Failed to parse key file: {}", e)))?;

        // Verificar que el KademliaId coincida con la clave pública
        let expected_id = Self::derive_kademlia_id(&keypair.public_key);
        if keypair.kademlia_id.as_bytes() != expected_id.as_bytes() {
            return Err(AvoError::crypto("KademliaId mismatch in key file"));
        }

        info!(
            "🔑 Loaded node keypair with ID: {}",
            keypair.kademlia_id.to_hex()
        );
        Ok(keypair)
    }

    /// Guardar en archivo
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> AvoResult<()> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| AvoError::crypto(format!("Failed to serialize keypair: {}", e)))?;

        // Crear directorio si no existe
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AvoError::network(format!("Failed to create key directory: {}", e)))?;
        }

        fs::write(path, data)
            .map_err(|e| AvoError::network(format!("Failed to write key file: {}", e)))?;

        info!("💾 Saved node keypair to file");
        Ok(())
    }
}

/// Manager de claves para múltiples propósitos
#[derive(Debug)]
pub struct KeyManager {
    /// Clave principal del nodo
    node_keypair: NodeKeyPair,
    /// Claves de sesión temporales
    session_keys: HashMap<String, NodeKeyPair>,
}

impl KeyManager {
    /// Crear nuevo manager con clave existente
    pub fn new(node_keypair: NodeKeyPair) -> Self {
        info!(
            "🔐 Initializing Key Manager for node: {}",
            node_keypair.kademlia_id.to_hex()
        );
        Self {
            node_keypair,
            session_keys: HashMap::new(),
        }
    }

    /// Crear manager generando nueva clave
    pub fn generate() -> AvoResult<Self> {
        let keypair = NodeKeyPair::generate()?;
        Ok(Self::new(keypair))
    }

    /// Cargar manager desde archivo
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> AvoResult<Self> {
        let keypair = NodeKeyPair::load_from_file(path)?;
        Ok(Self::new(keypair))
    }

    /// Cargar o generar si no existe
    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> AvoResult<Self> {
        match Self::load_from_file(&path) {
            Ok(manager) => {
                info!("🔑 Loaded existing keypair");
                Ok(manager)
            }
            Err(_) => {
                info!("🆕 Generating new keypair");
                let manager = Self::generate()?;
                manager.node_keypair.save_to_file(path)?;
                Ok(manager)
            }
        }
    }

    /// Obtener clave pública del nodo
    pub fn public_key(&self) -> &[u8; 32] {
        &self.node_keypair.public_key
    }

    /// Obtener la clave secreta del nodo (solo para integraciones de transporte)
    pub fn secret_key(&self) -> [u8; 32] {
        self.node_keypair.secret_key
    }

    /// Obtener KademliaId del nodo
    pub fn kademlia_id(&self) -> KademliaId {
        self.node_keypair.kademlia_id
    }

    /// Firmar mensaje con clave del nodo
    pub fn sign_message(&self, message: &[u8]) -> AvoResult<[u8; 64]> {
        self.node_keypair.sign(message)
    }

    /// Verificar firma con clave del nodo
    pub fn verify_message(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.node_keypair.verify(message, signature)
    }

    /// Crear clave de sesión temporal
    pub fn create_session_key(&mut self, session_id: String) -> AvoResult<KademliaId> {
        let session_keypair = NodeKeyPair::generate()?;
        let session_kademlia_id = session_keypair.kademlia_id;

        self.session_keys
            .insert(session_id.clone(), session_keypair);
        debug!(
            "🔄 Created session key: {} -> {}",
            session_id,
            session_kademlia_id.to_hex()
        );

        Ok(session_kademlia_id)
    }

    /// Firmar con clave de sesión
    pub fn sign_with_session(&self, session_id: &str, message: &[u8]) -> AvoResult<[u8; 64]> {
        let session_key = self
            .session_keys
            .get(session_id)
            .ok_or_else(|| AvoError::crypto("Session key not found"))?;

        session_key.sign(message)
    }

    /// Limpiar claves de sesión expiradas
    pub fn cleanup_expired_sessions(&mut self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.session_keys.retain(|session_id, keypair| {
            let is_valid = (now - keypair.created_at) < max_age_secs;
            if !is_valid {
                debug!("🧹 Removed expired session key: {}", session_id);
            }
            is_valid
        });
    }

    /// Obtener estadísticas del manager
    pub fn get_stats(&self) -> KeyManagerStats {
        KeyManagerStats {
            node_id: self.node_keypair.kademlia_id,
            active_sessions: self.session_keys.len(),
            node_key_age: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - self.node_keypair.created_at,
        }
    }
}

/// Estadísticas del Key Manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagerStats {
    pub node_id: KademliaId,
    pub active_sessions: usize,
    pub node_key_age: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = NodeKeyPair::generate().unwrap();
        assert_eq!(keypair.public_key.len(), 32);
        assert_eq!(keypair.secret_key.len(), 32);
    }

    #[test]
    fn test_signature_verification() {
        let keypair = NodeKeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature));

        // Verificar con mensaje diferente
        let wrong_message = b"wrong message";
        assert!(!keypair.verify(wrong_message, &signature));
    }

    #[test]
    fn test_kademlia_id_derivation() {
        let keypair1 = NodeKeyPair::generate().unwrap();
        let keypair2 = NodeKeyPair::generate().unwrap();

        // IDs diferentes para claves diferentes
        assert_ne!(
            keypair1.kademlia_id.as_bytes(),
            keypair2.kademlia_id.as_bytes()
        );

        // ID consistente para la misma clave
        let derived_id = NodeKeyPair::derive_kademlia_id(&keypair1.public_key);
        assert_eq!(keypair1.kademlia_id.as_bytes(), derived_id.as_bytes());
    }

    #[test]
    fn test_key_manager() {
        let mut manager = KeyManager::generate().unwrap();
        let message = b"test message";

        // Firmar y verificar con clave principal
        let signature = manager.sign_message(message).unwrap();
        assert!(manager.verify_message(message, &signature));

        // Crear clave de sesión
        let session_id = manager
            .create_session_key("test_session".to_string())
            .unwrap();
        assert!(manager.session_keys.contains_key("test_session"));

        // Firmar con clave de sesión
        let session_signature = manager.sign_with_session("test_session", message).unwrap();
        // Note: La verificación sería con la clave pública de la sesión
    }
}
