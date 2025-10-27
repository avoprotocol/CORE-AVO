//! # Implementación DHT Kademlia para AVO Protocol
//!
//! Distributed Hash Table basada en Kademlia con las siguientes características:
//! - Métrica de distancia XOR
//! - K-buckets con reputación de peers
//! - Scoring basado en stake y uptime
//! - Resistencia a ataques eclipse

use crate::error::*;
use crate::types::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Tamaño de cada k-bucket (número máximo de peers por bucket)
const K: usize = 20;

/// Número de bits en el ID del nodo (256 bits para SHA3-256)
const ID_BITS: usize = 256;

/// Timeout para queries DHT
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuración para DHT Kademlia
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KademliaDHTConfig {
    /// Mínimo stake requerido para bootstrap nodes
    pub min_bootstrap_stake: u64,
    /// Número máximo de peers por k-bucket
    pub k_bucket_size: usize,
    /// Timeout para queries DHT
    pub query_timeout_secs: u64,
    /// Intervalo de limpieza de peers inactivos
    pub cleanup_interval_secs: u64,
}

impl Default for KademliaDHTConfig {
    fn default() -> Self {
        Self {
            min_bootstrap_stake: 10_000, // 10K tokens - stake económicamente viable para descentralización
            k_bucket_size: K,
            query_timeout_secs: 10,
            cleanup_interval_secs: 300, // 5 minutos
        }
    }
}

/// ID de nodo Kademlia (256 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KademliaId([u8; 32]);

impl KademliaId {
    /// Crear nuevo ID desde bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Crear ID desde string
    pub fn from_str(s: &str) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Generar ID random
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = rand::random();
        }
        Self(bytes)
    }

    /// Calcular distancia XOR entre dos IDs
    pub fn distance(&self, other: &KademliaId) -> KademliaDistance {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i] ^ other.0[i];
        }
        KademliaDistance(result)
    }

    /// Convertir a bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convertir a string hex
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// Distancia XOR entre nodos
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KademliaDistance([u8; 32]);

impl KademliaDistance {
    /// Calcular el bucket index (posición del bit más significativo)
    pub fn bucket_index(&self) -> Option<usize> {
        for (byte_idx, &byte) in self.0.iter().enumerate() {
            if byte != 0 {
                for bit_idx in 0..8 {
                    if byte & (0x80 >> bit_idx) != 0 {
                        return Some(byte_idx * 8 + bit_idx);
                    }
                }
            }
        }
        None // Distancia cero
    }

    /// Obtener distancia como u64 para comparaciones rápidas
    pub fn as_u64(&self) -> u64 {
        u64::from_be_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
        ])
    }
}

/// Información del peer con métricas de reputación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: KademliaId,
    pub addr: SocketAddr,
    pub stake: u64,
    pub uptime: Duration,
    pub last_seen: SystemTime,
    pub invalid_messages: u32,
    pub successful_queries: u32,
    pub failed_queries: u32,
    pub is_bootstrap: bool,
    pub reputation_score: f64,
}

impl PeerInfo {
    /// Crear nuevo peer
    pub fn new(id: KademliaId, addr: SocketAddr, stake: u64) -> Self {
        Self {
            id,
            addr,
            stake,
            uptime: Duration::from_secs(0),
            last_seen: SystemTime::now(),
            invalid_messages: 0,
            successful_queries: 0,
            failed_queries: 0,
            is_bootstrap: false, // Se determinará basado en config
            reputation_score: 0.0,
        }
    }

    /// Calcular score de reputación
    /// S(p) = α·stake(p) + β·uptime(p) - γ·invalid_msgs(p)
    pub fn calculate_reputation(&mut self) {
        const ALPHA: f64 = 0.4; // Peso del stake
        const BETA: f64 = 0.3; // Peso del uptime
        const GAMMA: f64 = 0.3; // Penalización por mensajes inválidos

        let stake_score = (self.stake as f64) / 1_000_000.0; // Normalizar stake
        let uptime_score = self.uptime.as_secs() as f64 / (24.0 * 3600.0); // Uptime en días
        let penalty = self.invalid_messages as f64;

        self.reputation_score = ALPHA * stake_score + BETA * uptime_score - GAMMA * penalty;

        // Asegurar que el score esté entre 0 y 100
        self.reputation_score = self.reputation_score.max(0.0).min(100.0);
    }

    /// Marcar mensaje inválido
    pub fn mark_invalid_message(&mut self) {
        self.invalid_messages += 1;
        self.calculate_reputation();
    }

    /// Marcar query exitoso
    pub fn mark_successful_query(&mut self) {
        self.successful_queries += 1;
        self.last_seen = SystemTime::now();
        self.calculate_reputation();
    }

    /// Marcar query fallido
    pub fn mark_failed_query(&mut self) {
        self.failed_queries += 1;
        self.calculate_reputation();
    }

    /// Verificar si el peer está activo
    pub fn is_active(&self) -> bool {
        self.last_seen.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(300)
        // 5 minutos
    }
}

/// K-bucket con reputación
#[derive(Debug, Clone)]
pub struct KBucket {
    peers: Vec<PeerInfo>,
    last_updated: Instant,
}

impl KBucket {
    /// Crear nuevo k-bucket
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            last_updated: Instant::now(),
        }
    }

    /// Agregar peer al bucket
    pub fn add_peer(&mut self, peer: PeerInfo) -> bool {
        // Si el peer ya existe, actualizar info
        if let Some(existing) = self.peers.iter_mut().find(|p| p.id == peer.id) {
            *existing = peer;
            self.last_updated = Instant::now();
            return true;
        }

        // Si hay espacio, agregar directamente
        if self.peers.len() < K {
            self.peers.push(peer);
            self.last_updated = Instant::now();
            return true;
        }

        // Si está lleno, reemplazar peer con menor reputación si el nuevo es mejor
        if let Some(worst_idx) = self.find_worst_peer() {
            let worst_score = self.peers[worst_idx].reputation_score;
            if peer.reputation_score > worst_score {
                self.peers[worst_idx] = peer;
                self.last_updated = Instant::now();
                return true;
            }
        }

        false
    }

    /// Encontrar peer con peor reputación
    fn find_worst_peer(&self) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.reputation_score.partial_cmp(&b.reputation_score).unwrap())
            .map(|(idx, _)| idx)
    }

    /// Obtener peers ordenados por reputación
    pub fn get_best_peers(&self, count: usize) -> Vec<PeerInfo> {
        let mut peers = self.peers.clone();
        peers.sort_by(|a, b| b.reputation_score.partial_cmp(&a.reputation_score).unwrap());
        peers.into_iter().take(count).collect()
    }

    /// Remover peer inactivo
    pub fn remove_inactive_peers(&mut self) {
        self.peers.retain(|peer| peer.is_active());
    }

    /// Verificar si el bucket está lleno
    pub fn is_full(&self) -> bool {
        self.peers.len() >= K
    }

    /// Obtener número de peers
    pub fn len(&self) -> usize {
        self.peers.len()
    }
}

/// Query DHT para buscar nodos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindNodeQuery {
    pub target: KademliaId,
    pub requester: KademliaId,
    pub timestamp: u64,
}

/// Respuesta a query DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindNodeResponse {
    pub peers: Vec<PeerInfo>,
    pub responder: KademliaId,
    pub timestamp: u64,
}

/// DHT Kademlia principal
#[derive(Debug)]
pub struct KademliaDHT {
    /// ID de este nodo
    local_id: KademliaId,
    /// Configuración de la DHT
    config: KademliaDHTConfig,
    /// K-buckets indexados por distancia
    buckets: Vec<KBucket>,
    /// Bootstrap nodes con proof-of-stake
    bootstrap_nodes: HashMap<KademliaId, PeerInfo>,
    /// Queries activos
    active_queries: HashMap<KademliaId, Instant>,
    /// Métricas
    metrics: DHTMetrics,
}

/// Métricas de la DHT
#[derive(Debug, Default)]
pub struct DHTMetrics {
    pub total_peers: usize,
    pub bootstrap_peers: usize,
    pub successful_queries: u64,
    pub failed_queries: u64,
    pub average_reputation: f64,
    pub bucket_distribution: Vec<usize>,
}

impl KademliaDHT {
    /// Crear nueva DHT
    pub fn new(local_id: KademliaId) -> Self {
        Self::with_config(local_id, KademliaDHTConfig::default())
    }

    /// Crear nueva DHT con configuración personalizada
    pub fn with_config(local_id: KademliaId, config: KademliaDHTConfig) -> Self {
        info!(
            "🌐 Inicializando DHT Kademlia con ID: {}",
            local_id.to_hex()
        );
        info!("⚙️ Min bootstrap stake: {} AVO", config.min_bootstrap_stake);

        Self {
            local_id,
            buckets: (0..ID_BITS).map(|_| KBucket::new()).collect(),
            bootstrap_nodes: HashMap::new(),
            active_queries: HashMap::new(),
            metrics: DHTMetrics::default(),
            config,
        }
    }

    /// Agregar bootstrap node con verificación de stake
    pub fn add_bootstrap_node(&mut self, mut peer: PeerInfo) -> AvoResult<()> {
        if peer.stake < self.config.min_bootstrap_stake {
            return Err(AvoError::network(format!(
                "Bootstrap node stake {} below minimum {}",
                peer.stake, self.config.min_bootstrap_stake
            )));
        }

        peer.is_bootstrap = true;
        info!(
            "🔗 Agregando bootstrap node: {} (stake: {} AVO)",
            peer.id.to_hex(),
            peer.stake
        );
        self.bootstrap_nodes.insert(peer.id, peer.clone());
        self.add_peer(peer)?;
        Ok(())
    }

    /// Agregar peer a la DHT
    pub fn add_peer(&mut self, mut peer: PeerInfo) -> AvoResult<()> {
        peer.calculate_reputation();

        let distance = self.local_id.distance(&peer.id);
        if let Some(bucket_idx) = distance.bucket_index() {
            if bucket_idx < self.buckets.len() {
                let added = self.buckets[bucket_idx].add_peer(peer.clone());
                if added {
                    debug!(
                        "✅ Peer agregado al bucket {}: {}",
                        bucket_idx,
                        peer.id.to_hex()
                    );
                    self.update_metrics();
                }
            }
        }
        Ok(())
    }

    /// Buscar los K nodos más cercanos a un target
    pub fn find_closest_peers(&self, target: &KademliaId, count: usize) -> Vec<PeerInfo> {
        let mut candidates: Vec<(KademliaDistance, PeerInfo)> = Vec::new();

        // Recopilar peers de todos los buckets
        for bucket in &self.buckets {
            for peer in &bucket.peers {
                let distance = target.distance(&peer.id);
                candidates.push((distance, peer.clone()));
            }
        }

        // Ordenar por distancia y tomar los mejores
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        candidates
            .into_iter()
            .take(count)
            .map(|(_, peer)| peer)
            .collect()
    }

    /// Realizar query FIND_NODE en la DHT local
    pub async fn find_node(&mut self, target: KademliaId) -> AvoResult<Vec<PeerInfo>> {
        info!("🔍 Ejecutando FIND_NODE para target: {}", target.to_hex());

        let query_id = KademliaId::random();
        self.active_queries.insert(query_id, Instant::now());

        // Obtener los K peers más cercanos del estado actual de la DHT
        let closest_peers = self.find_closest_peers(&target, K);

        self.active_queries.remove(&query_id);
        info!(
            "✅ FIND_NODE completado, encontrados {} peers",
            closest_peers.len()
        );

        Ok(closest_peers)
    }

    /// Actualizar métricas
    fn update_metrics(&mut self) {
        self.metrics.total_peers = self.buckets.iter().map(|b| b.len()).sum();
        self.metrics.bootstrap_peers = self.bootstrap_nodes.len();

        let mut total_reputation = 0.0;
        let mut peer_count = 0;

        self.metrics.bucket_distribution.clear();
        for bucket in &self.buckets {
            self.metrics.bucket_distribution.push(bucket.len());
            for peer in &bucket.peers {
                total_reputation += peer.reputation_score;
                peer_count += 1;
            }
        }

        if peer_count > 0 {
            self.metrics.average_reputation = total_reputation / peer_count as f64;
        }
    }

    /// Limpiar peers inactivos
    pub fn cleanup_inactive_peers(&mut self) {
        for bucket in &mut self.buckets {
            bucket.remove_inactive_peers();
        }
        self.update_metrics();
    }

    /// Obtener métricas actuales
    pub fn get_metrics(&self) -> &DHTMetrics {
        &self.metrics
    }

    /// Verificar salud de la DHT
    pub fn health_check(&self) -> DHTHealthReport {
        let total_peers = self.metrics.total_peers;
        let bootstrap_coverage = if self.bootstrap_nodes.is_empty() {
            0.0
        } else {
            self.bootstrap_nodes.len() as f64 / 10.0 // Asumiendo 10 bootstrap nodes ideales
        };

        let bucket_coverage = self
            .buckets
            .iter()
            .enumerate()
            .filter(|(_, bucket)| bucket.len() > 0)
            .count() as f64
            / ID_BITS as f64;

        DHTHealthReport {
            total_peers,
            bootstrap_coverage,
            bucket_coverage,
            average_reputation: self.metrics.average_reputation,
            is_healthy: total_peers > 10 && bootstrap_coverage > 0.5 && bucket_coverage > 0.1,
        }
    }
}

/// Reporte de salud de la DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTHealthReport {
    pub total_peers: usize,
    pub bootstrap_coverage: f64,
    pub bucket_coverage: f64,
    pub average_reputation: f64,
    pub is_healthy: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kademlia_distance() {
        let id1 = KademliaId::from_str("node1");
        let id2 = KademliaId::from_str("node2");
        let distance = id1.distance(&id2);

        // La distancia debe ser simétrica
        assert_eq!(distance, id2.distance(&id1));
    }

    #[test]
    fn test_peer_reputation() {
        let mut peer = PeerInfo::new(
            KademliaId::from_str("test_peer"),
            "127.0.0.1:8080".parse().unwrap(),
            5_000_000,
        );

        peer.calculate_reputation();
        assert!(peer.reputation_score >= 0.0);

        peer.mark_invalid_message();
        let old_score = peer.reputation_score;
        peer.mark_invalid_message();
        assert!(peer.reputation_score < old_score);
    }

    #[tokio::test]
    async fn test_dht_operations() {
        let mut dht = KademliaDHT::new(KademliaId::from_str("local_node"));

        // Agregar bootstrap node
        let bootstrap_peer = PeerInfo::new(
            KademliaId::from_str("bootstrap"),
            "127.0.0.1:8081".parse().unwrap(),
            dht.config.min_bootstrap_stake,
        );

        assert!(dht.add_bootstrap_node(bootstrap_peer).is_ok());

        // Buscar nodos
        let target = KademliaId::from_str("target_node");
        let result = dht.find_node(target).await;
        assert!(result.is_ok());
    }
}
