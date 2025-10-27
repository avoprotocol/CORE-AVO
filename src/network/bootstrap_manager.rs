//! # Proof-of-Stake Bootstrap Node System for AVO Protocol
//!
//! Implements a robust system of bootstrap nodes that require proof-of-stake
//! to prevent Eclipse attacks and ensure network reliability.
use crate::error::*;
use crate::network::gossip_scoring::{GossipScorer, GossipScoringConfig};
use crate::network::kademlia_dht::{KademliaId, PeerInfo};
use crate::types::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Configuración para bootstrap nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// Stake mínimo requerido para ser bootstrap node (tokens)
    pub min_stake: u64,
    /// Número mínimo de bootstrap nodes requeridos
    pub min_bootstrap_nodes: usize,
    /// Número máximo de bootstrap nodes activos
    pub max_bootstrap_nodes: usize,
    /// Tiempo de uptime mínimo requerido (segundos)
    pub min_uptime: u64,
    /// Intervalo de verificación de stake (segundos)
    pub stake_verification_interval: u64,
    /// Tiempo de gracia antes de remover un node (segundos)
    pub grace_period: u64,
    /// Penalty por downtime (factor multiplicativo)
    pub downtime_penalty: f64,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            min_stake: 10_000, // 10K tokens - democratización del acceso a infraestructura
            min_bootstrap_nodes: 5,
            max_bootstrap_nodes: 15,
            min_uptime: 3600 * 24,            // 24 horas
            stake_verification_interval: 300, // 5 minutos
            grace_period: 1800,               // 30 minutos
            downtime_penalty: 0.9,
        }
    }
}

/// Información de stake de un nodo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeInfo {
    /// Cantidad de stake total
    pub total_stake: u64,
    /// Stake efectivo (después de penalties)
    pub effective_stake: u64,
    /// Timestamp de cuando se hizo el stake
    pub staked_at: SystemTime,
    /// Último tiempo de verificación
    pub last_verified: SystemTime,
    /// Historial de penalties
    pub penalties: Vec<StakePenalty>,
    /// Estado del stake
    pub status: StakeStatus,
}

/// Penalty aplicado al stake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakePenalty {
    /// Razón del penalty
    pub reason: PenaltyReason,
    /// Factor de penalty (0.0 - 1.0)
    pub factor: f64,
    /// Timestamp del penalty
    pub applied_at: SystemTime,
    /// Duración del penalty
    pub duration: Duration,
}

/// Razones para penalties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PenaltyReason {
    /// Nodo offline por mucho tiempo
    ExtendedDowntime,
    /// Comportamiento malicioso detectado
    MaliciousBehavior,
    /// Respuestas inválidas o tardías
    InvalidResponses,
    /// Falta de recursos (bandwidth, storage)
    InsufficientResources,
    /// Violación de protocol
    ProtocolViolation,
}

/// Estado del stake
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StakeStatus {
    /// Stake activo y válido
    Active,
    /// Stake en período de gracia
    Grace { until: SystemTime },
    /// Stake suspendido temporalmente
    Suspended { until: SystemTime },
    /// Stake removido permanentemente
    Slashed,
}

/// Bootstrap node con proof-of-stake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNode {
    /// Información básica del peer
    pub peer_info: PeerInfo,
    /// Información de stake
    pub stake_info: StakeInfo,
    /// Métricas de performance
    pub performance: BootstrapNodeMetrics,
    /// Estado actual
    pub status: BootstrapNodeStatus,
    /// Última actualización de estado
    pub last_updated: SystemTime,
}

/// Métricas de performance de bootstrap node
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapNodeMetrics {
    /// Tiempo total online
    pub uptime: Duration,
    /// Número de peers conectados exitosamente
    pub successful_connections: u64,
    /// Número de conexiones fallidas
    pub failed_connections: u64,
    /// Queries DHT respondidas
    pub dht_queries_answered: u64,
    /// Latencia promedio de respuesta (ms)
    pub average_response_time: f64,
    /// Bandwidth utilizado (bytes)
    pub bandwidth_usage: u64,
    /// Número de peers referidos exitosamente
    pub successful_referrals: u64,
}

/// Estado de un bootstrap node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BootstrapNodeStatus {
    /// Nodo activo y funcionando
    Active,
    /// Nodo en evaluación
    Evaluating,
    /// Nodo suspendido temporalmente
    Suspended { reason: String, until: SystemTime },
    /// Nodo removido de la lista
    Removed { reason: String },
}

/// Manager de bootstrap nodes
#[derive(Debug)]
pub struct BootstrapManager {
    /// Configuración
    config: BootstrapConfig,
    /// Bootstrap nodes activos
    bootstrap_nodes: HashMap<KademliaId, BootstrapNode>,
    /// Candidatos a bootstrap node
    candidates: HashMap<KademliaId, BootstrapNode>,
    /// Scoring system integrado
    scorer: GossipScorer,
    /// Última verificación de stakes
    last_stake_verification: SystemTime,
    /// Métricas globales
    metrics: BootstrapManagerMetrics,
}

/// Métricas del manager
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BootstrapManagerMetrics {
    pub active_bootstrap_nodes: usize,
    pub total_candidates: usize,
    pub total_stake_locked: u64,
    pub average_uptime: f64,
    pub network_reliability: f64,
    pub last_bootstrap_change: Option<SystemTime>,
}

impl BootstrapManager {
    /// Crear nuevo manager
    pub fn new(config: BootstrapConfig, scoring_config: GossipScoringConfig) -> Self {
        info!(
            "🔗 Inicializando Bootstrap Manager con min_stake: {} tokens",
            config.min_stake
        );

        Self {
            config,
            bootstrap_nodes: HashMap::new(),
            candidates: HashMap::new(),
            scorer: GossipScorer::new(scoring_config),
            last_stake_verification: SystemTime::now(),
            metrics: BootstrapManagerMetrics::default(),
        }
    }

    /// Registrar candidato a bootstrap node
    pub fn register_candidate(&mut self, peer_info: PeerInfo, stake_amount: u64) -> AvoResult<()> {
        if stake_amount < self.config.min_stake {
            return Err(AvoError::network(format!(
                "Insufficient stake: {} < {}",
                stake_amount, self.config.min_stake
            )));
        }

        let stake_info = StakeInfo {
            total_stake: stake_amount,
            effective_stake: stake_amount,
            staked_at: SystemTime::now(),
            last_verified: SystemTime::now(),
            penalties: Vec::new(),
            status: StakeStatus::Active,
        };

        let bootstrap_node = BootstrapNode {
            peer_info: peer_info.clone(),
            stake_info,
            performance: BootstrapNodeMetrics::default(),
            status: BootstrapNodeStatus::Evaluating,
            last_updated: SystemTime::now(),
        };

        info!(
            "📋 Registering bootstrap candidate: {} (stake: {})",
            peer_info.id.to_hex(),
            stake_amount
        );

        self.candidates.insert(peer_info.id, bootstrap_node);
        self.scorer.update_peer_info(peer_info);

        Ok(())
    }

    /// Promover candidato a bootstrap node activo
    pub fn promote_candidate(&mut self, peer_id: KademliaId) -> AvoResult<()> {
        let candidate = self
            .candidates
            .remove(&peer_id)
            .ok_or_else(|| AvoError::network("Candidate not found"))?;

        // Verificar requisitos
        if !self.meets_bootstrap_requirements(&candidate) {
            return Err(AvoError::network("Candidate does not meet requirements"));
        }

        // Verificar capacidad
        if self.bootstrap_nodes.len() >= self.config.max_bootstrap_nodes {
            // Remover el bootstrap node con menor performance
            if let Some(worst_id) = self.find_worst_bootstrap_node() {
                self.demote_bootstrap_node(worst_id)?;
            } else {
                return Err(AvoError::network("Too many bootstrap nodes"));
            }
        }

        let mut bootstrap_node = candidate;
        bootstrap_node.status = BootstrapNodeStatus::Active;
        bootstrap_node.last_updated = SystemTime::now();

        info!(
            "⬆️ Promoting candidate to bootstrap node: {}",
            peer_id.to_hex()
        );
        self.bootstrap_nodes.insert(peer_id, bootstrap_node);
        self.update_metrics();

        Ok(())
    }

    /// Verificar si un candidato cumple los requisitos
    fn meets_bootstrap_requirements(&self, candidate: &BootstrapNode) -> bool {
        // Verificar stake efectivo
        if candidate.stake_info.effective_stake < self.config.min_stake {
            return false;
        }

        // Verificar estado del stake
        if candidate.stake_info.status != StakeStatus::Active {
            return false;
        }

        // Verificar uptime mínimo
        if candidate.performance.uptime.as_secs() < self.config.min_uptime {
            return false;
        }

        // Verificar score en el gossip system
        if let Some(score) = self.scorer.get_peer_score(&candidate.peer_info.id) {
            if score < 0.0 {
                // Score mínimo
                return false;
            }
        }

        true
    }

    /// Encontrar el bootstrap node con peor performance
    fn find_worst_bootstrap_node(&self) -> Option<KademliaId> {
        self.bootstrap_nodes
            .iter()
            .filter(|(_, node)| node.status == BootstrapNodeStatus::Active)
            .min_by(|(_, a), (_, b)| {
                let score_a = self.calculate_bootstrap_score(a);
                let score_b = self.calculate_bootstrap_score(b);
                score_a.partial_cmp(&score_b).unwrap()
            })
            .map(|(id, _)| *id)
    }

    /// Calcular score de bootstrap node
    fn calculate_bootstrap_score(&self, node: &BootstrapNode) -> f64 {
        let stake_score = node.stake_info.effective_stake as f64 / 1_000_000.0;
        let uptime_score = node.performance.uptime.as_secs() as f64 / (24.0 * 3600.0);
        let reliability_score = if node.performance.successful_connections > 0 {
            node.performance.successful_connections as f64
                / (node.performance.successful_connections + node.performance.failed_connections)
                    as f64
        } else {
            0.0
        };

        stake_score * 0.4 + uptime_score * 0.3 + reliability_score * 0.3
    }

    /// Degradar bootstrap node a candidato
    pub fn demote_bootstrap_node(&mut self, peer_id: KademliaId) -> AvoResult<()> {
        let mut bootstrap_node = self
            .bootstrap_nodes
            .remove(&peer_id)
            .ok_or_else(|| AvoError::network("Bootstrap node not found"))?;

        bootstrap_node.status = BootstrapNodeStatus::Suspended {
            reason: "Performance degradation".to_string(),
            until: SystemTime::now() + Duration::from_secs(self.config.grace_period),
        };

        info!("⬇️ Demoting bootstrap node: {}", peer_id.to_hex());
        self.candidates.insert(peer_id, bootstrap_node);
        self.update_metrics();

        Ok(())
    }

    /// Verificar stakes de todos los bootstrap nodes
    pub async fn verify_stakes(&mut self) -> AvoResult<()> {
        let now = SystemTime::now();

        // Solo verificar si ha pasado suficiente tiempo
        if now
            .duration_since(self.last_stake_verification)
            .unwrap_or(Duration::MAX)
            < Duration::from_secs(self.config.stake_verification_interval)
        {
            return Ok(());
        }

        info!("🔍 Verificando stakes de bootstrap nodes...");

        let mut nodes_to_remove = Vec::new();
        let mut nodes_to_update = Vec::new();

        // First pass: collect verification results without borrowing conflicts
        for (peer_id, node) in &self.bootstrap_nodes {
            // Simular verificación de stake (en implementación real sería query al blockchain)
            let stake_valid = self.verify_node_stake(node).await?;

            if !stake_valid {
                warn!(
                    "❌ Stake verification failed for node: {}",
                    peer_id.to_hex()
                );
                nodes_to_remove.push(*peer_id);
            } else {
                nodes_to_update.push(*peer_id);
            }
        }

        // Second pass: update verified nodes
        for peer_id in nodes_to_update {
            if let Some(node) = self.bootstrap_nodes.get_mut(&peer_id) {
                node.stake_info.last_verified = now;
            }
        }

        // Remover nodos con stake inválido
        for peer_id in nodes_to_remove {
            self.slash_bootstrap_node(peer_id, "Invalid stake verification".to_string())?;
        }

        self.last_stake_verification = now;
        Ok(())
    }

    /// Verificar stake de un nodo específico (simulado)
    async fn verify_node_stake(&self, node: &BootstrapNode) -> AvoResult<bool> {
        // Simular latencia de verificación
        tokio::time::sleep(Duration::from_millis(100)).await;

        // En implementación real, esto consultaría el smart contract de staking
        // Por ahora, simular que el 95% de las verificaciones son exitosas
        Ok(rand::random::<f64>() > 0.05)
    }

    /// Aplicar slashing a un bootstrap node
    pub fn slash_bootstrap_node(&mut self, peer_id: KademliaId, reason: String) -> AvoResult<()> {
        if let Some(mut node) = self.bootstrap_nodes.remove(&peer_id) {
            node.stake_info.status = StakeStatus::Slashed;
            node.status = BootstrapNodeStatus::Removed {
                reason: reason.clone(),
            };

            error!(
                "⚔️ Slashing bootstrap node {}: {}",
                peer_id.to_hex(),
                reason
            );

            // En implementación real, aquí se ejecutaría el slashing en el smart contract
            self.update_metrics();
        }

        Ok(())
    }

    /// Obtener lista de bootstrap nodes activos
    pub fn get_active_bootstrap_nodes(&self) -> Vec<PeerInfo> {
        self.bootstrap_nodes
            .values()
            .filter(|node| node.status == BootstrapNodeStatus::Active)
            .map(|node| node.peer_info.clone())
            .collect()
    }

    /// Obtener bootstrap nodes ordenados por score
    pub fn get_top_bootstrap_nodes(&self, count: usize) -> Vec<PeerInfo> {
        let mut nodes: Vec<_> = self
            .bootstrap_nodes
            .values()
            .filter(|node| node.status == BootstrapNodeStatus::Active)
            .map(|node| (node, self.calculate_bootstrap_score(node)))
            .collect();

        nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        nodes
            .into_iter()
            .take(count)
            .map(|(node, _)| node.peer_info.clone())
            .collect()
    }

    /// Manejar métricas de performance de un nodo
    pub fn update_node_performance(
        &mut self,
        peer_id: KademliaId,
        metrics_update: PerformanceUpdate,
    ) {
        if let Some(node) = self.bootstrap_nodes.get_mut(&peer_id) {
            match metrics_update {
                PerformanceUpdate::ConnectionSuccess => {
                    node.performance.successful_connections += 1;
                }
                PerformanceUpdate::ConnectionFailure => {
                    node.performance.failed_connections += 1;
                }
                PerformanceUpdate::DHTQuery { response_time } => {
                    node.performance.dht_queries_answered += 1;
                    // Actualizar latencia promedio
                    let total_queries = node.performance.dht_queries_answered as f64;
                    node.performance.average_response_time =
                        (node.performance.average_response_time * (total_queries - 1.0)
                            + response_time)
                            / total_queries;
                }
                PerformanceUpdate::BandwidthUsage { bytes } => {
                    node.performance.bandwidth_usage += bytes;
                }
            }

            node.last_updated = SystemTime::now();
        }
    }

    /// Actualizar métricas globales
    fn update_metrics(&mut self) {
        self.metrics.active_bootstrap_nodes = self.bootstrap_nodes.len();
        self.metrics.total_candidates = self.candidates.len();

        self.metrics.total_stake_locked = self
            .bootstrap_nodes
            .values()
            .map(|node| node.stake_info.effective_stake)
            .sum();

        if !self.bootstrap_nodes.is_empty() {
            let total_uptime: u64 = self
                .bootstrap_nodes
                .values()
                .map(|node| node.performance.uptime.as_secs())
                .sum();

            self.metrics.average_uptime = total_uptime as f64 / self.bootstrap_nodes.len() as f64;
        }

        // Calcular confiabilidad de la red
        let active_nodes = self
            .bootstrap_nodes
            .values()
            .filter(|node| node.status == BootstrapNodeStatus::Active)
            .count();

        self.metrics.network_reliability = if active_nodes >= self.config.min_bootstrap_nodes {
            (active_nodes as f64 / self.config.max_bootstrap_nodes as f64).min(1.0)
        } else {
            active_nodes as f64 / self.config.min_bootstrap_nodes as f64
        };

        self.metrics.last_bootstrap_change = Some(SystemTime::now());
    }

    /// Obtener métricas actuales
    pub fn get_metrics(&self) -> &BootstrapManagerMetrics {
        &self.metrics
    }

    /// Generar reporte de estado completo
    pub fn generate_status_report(&self) -> BootstrapStatusReport {
        BootstrapStatusReport {
            active_nodes: self.get_active_bootstrap_nodes(),
            total_candidates: self.candidates.len(),
            metrics: self.metrics.clone(),
            config: self.config.clone(),
            network_health: self.assess_network_health(),
            timestamp: SystemTime::now(),
        }
    }

    /// Evaluar salud de la red
    fn assess_network_health(&self) -> NetworkHealthStatus {
        let active_count = self
            .bootstrap_nodes
            .values()
            .filter(|node| node.status == BootstrapNodeStatus::Active)
            .count();

        if active_count >= self.config.min_bootstrap_nodes * 2 {
            NetworkHealthStatus::Excellent
        } else if active_count >= self.config.min_bootstrap_nodes {
            NetworkHealthStatus::Good
        } else if active_count >= self.config.min_bootstrap_nodes / 2 {
            NetworkHealthStatus::Warning
        } else {
            NetworkHealthStatus::Critical
        }
    }
}

/// Updates de performance para nodos
#[derive(Debug, Clone)]
pub enum PerformanceUpdate {
    ConnectionSuccess,
    ConnectionFailure,
    DHTQuery { response_time: f64 },
    BandwidthUsage { bytes: u64 },
}

/// Estado de salud de la red
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkHealthStatus {
    Excellent,
    Good,
    Warning,
    Critical,
}

impl Default for NetworkHealthStatus {
    fn default() -> Self {
        NetworkHealthStatus::Warning
    }
}

/// Reporte de estado del sistema de bootstrap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapStatusReport {
    pub active_nodes: Vec<PeerInfo>,
    pub total_candidates: usize,
    pub metrics: BootstrapManagerMetrics,
    pub config: BootstrapConfig,
    pub network_health: NetworkHealthStatus,
    pub timestamp: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::gossip_scoring::GossipScoringConfig;

    #[tokio::test]
    async fn test_bootstrap_manager() {
        let config = BootstrapConfig::default();
        let scoring_config = GossipScoringConfig::default();
        let mut manager = BootstrapManager::new(config, scoring_config);

        // Crear peer con suficiente stake
        let peer_info = PeerInfo::new(
            KademliaId::from_str("test_bootstrap"),
            "127.0.0.1:8080".parse().unwrap(),
            15_000_000, // Suficiente stake
        );

        // Registrar candidato
        assert!(manager
            .register_candidate(peer_info.clone(), 15_000_000)
            .is_ok());

        // Verificar que está en candidatos
        assert!(manager.candidates.contains_key(&peer_info.id));
    }

    #[test]
    fn test_stake_requirements() {
        let config = BootstrapConfig::default();
        let scoring_config = GossipScoringConfig::default();
        let mut manager = BootstrapManager::new(config, scoring_config);

        let peer_info = PeerInfo::new(
            KademliaId::from_str("insufficient_stake"),
            "127.0.0.1:8081".parse().unwrap(),
            5_000, // Insuficiente stake
        );

        // Debe fallar por stake insuficiente
        assert!(manager.register_candidate(peer_info, 5_000).is_err());
    }
}
