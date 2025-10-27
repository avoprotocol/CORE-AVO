//! # Scoring System for GossipSub on AVO Protocol
//!
//! Implements advanced peer scoring for the gossip protocol with:
//! - Scoring based on stake, uptime, and behavior
//! - Spam and malicious behavior detection
//! - Bandwidth tracking and rate limiting
//! - Integration with DHT Kademlia

use crate::error::*;
use crate::network::kademlia_dht::{KademliaId, PeerInfo};
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, error, info, warn};

/// Configuración del sistema de scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipScoringConfig {
    /// Peso del stake en el score total
    pub stake_weight: f64,
    /// Peso del uptime en el score total  
    pub uptime_weight: f64,
    /// Penalización por mensajes inválidos
    pub invalid_message_penalty: f64,
    /// Penalización por spam
    pub spam_penalty: f64,
    /// Threshold para considerar un peer como spammer
    pub spam_threshold: u32,
    /// Ventana de tiempo para rate limiting (segundos)
    pub rate_limit_window: u64,
    /// Máximo de mensajes por ventana
    pub max_messages_per_window: u32,
    /// Score mínimo para mantener conexión
    pub min_score_threshold: f64,
    /// Score para graylisting temporal
    pub graylist_threshold: f64,
}

impl Default for GossipScoringConfig {
    fn default() -> Self {
        Self {
            stake_weight: 0.4,
            uptime_weight: 0.3,
            invalid_message_penalty: 0.2,
            spam_penalty: 0.1,
            spam_threshold: 10,
            rate_limit_window: 60, // 1 minuto
            max_messages_per_window: 100,
            min_score_threshold: -50.0,
            graylist_threshold: -20.0,
        }
    }
}

/// Métricas de comportamiento de un peer
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerBehaviorMetrics {
    /// Mensajes válidos recibidos
    pub valid_messages: u64,
    /// Mensajes inválidos recibidos
    pub invalid_messages: u64,
    /// Mensajes de spam detectados
    pub spam_messages: u64,
    /// Bandwidth utilizado (bytes)
    pub bandwidth_used: u64,
    /// Tiempo de primera conexión
    pub first_seen: Option<SystemTime>,
    /// Tiempo de última actividad
    pub last_activity: Option<SystemTime>,
    /// Latencia promedio (ms)
    pub average_latency: f64,
    /// Número de desconexiones
    pub disconnections: u32,
    /// Tópicos suscritos
    pub subscribed_topics: std::collections::HashSet<String>,
}

/// Rate limiting por peer
#[derive(Debug, Clone)]
struct RateLimitTracker {
    /// Timestamps de mensajes en la ventana actual
    message_timestamps: VecDeque<Instant>,
    /// Número de mensajes en la ventana
    current_count: u32,
    /// Última actualización
    last_reset: Instant,
}

impl RateLimitTracker {
    fn new() -> Self {
        Self {
            message_timestamps: VecDeque::new(),
            current_count: 0,
            last_reset: Instant::now(),
        }
    }

    /// Verificar si el peer puede enviar un mensaje
    fn can_send_message(&mut self, config: &GossipScoringConfig) -> bool {
        let now = Instant::now();
        let window_duration = Duration::from_secs(config.rate_limit_window);

        // Limpiar mensajes fuera de la ventana
        while let Some(&front_time) = self.message_timestamps.front() {
            if now.duration_since(front_time) > window_duration {
                self.message_timestamps.pop_front();
                self.current_count = self.current_count.saturating_sub(1);
            } else {
                break;
            }
        }

        // Verificar límite
        self.current_count < config.max_messages_per_window
    }

    /// Registrar nuevo mensaje
    fn record_message(&mut self) {
        let now = Instant::now();
        self.message_timestamps.push_back(now);
        self.current_count += 1;
    }
}

/// Score de un peer en el sistema gossip
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerGossipScore {
    /// ID del peer
    pub peer_id: KademliaId,
    /// Score total actual
    pub total_score: f64,
    /// Componentes del score
    pub stake_score: f64,
    pub uptime_score: f64,
    pub behavior_score: f64,
    pub reputation_score: f64,
    /// Estado del peer
    pub status: PeerStatus,
    /// Última actualización del score
    pub last_updated: SystemTime,
}

/// Estado de un peer en el sistema
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PeerStatus {
    /// Peer en buen estado
    Good,
    /// Peer en lista gris (comportamiento sospechoso)
    Graylisted,
    /// Peer bloqueado temporalmente
    Blocked { until: SystemTime },
    /// Peer baneado permanentemente
    Banned,
}

/// Sistema de scoring para GossipSub
#[derive(Debug)]
pub struct GossipScorer {
    /// Configuración del scoring
    config: GossipScoringConfig,
    /// Scores de peers
    peer_scores: HashMap<KademliaId, PeerGossipScore>,
    /// Métricas de comportamiento
    peer_metrics: HashMap<KademliaId, PeerBehaviorMetrics>,
    /// Rate limiting por peer
    rate_limiters: HashMap<KademliaId, RateLimitTracker>,
    /// Información base de peers (desde DHT)
    peer_info: HashMap<KademliaId, PeerInfo>,
    /// Métricas globales del sistema
    global_metrics: GlobalScoringMetrics,
}

/// Métricas globales del sistema de scoring
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GlobalScoringMetrics {
    pub total_peers: usize,
    pub good_peers: usize,
    pub graylisted_peers: usize,
    pub blocked_peers: usize,
    pub banned_peers: usize,
    pub average_score: f64,
    pub messages_processed: u64,
    pub spam_detected: u64,
    pub rate_limit_violations: u64,
}

impl GossipScorer {
    /// Crear nuevo sistema de scoring
    pub fn new(config: GossipScoringConfig) -> Self {
        info!("🎯 Inicializando GossipSub scoring system");

        Self {
            config,
            peer_scores: HashMap::new(),
            peer_metrics: HashMap::new(),
            rate_limiters: HashMap::new(),
            peer_info: HashMap::new(),
            global_metrics: GlobalScoringMetrics::default(),
        }
    }

    /// Agregar o actualizar información de peer
    pub fn update_peer_info(&mut self, peer: PeerInfo) {
        self.peer_info.insert(peer.id, peer.clone());

        // Crear score inicial si no existe
        if !self.peer_scores.contains_key(&peer.id) {
            let initial_score = self.calculate_initial_score(&peer);
            self.peer_scores.insert(peer.id, initial_score);
        }

        // Crear métricas si no existen
        if !self.peer_metrics.contains_key(&peer.id) {
            let mut metrics = PeerBehaviorMetrics::default();
            metrics.first_seen = Some(SystemTime::now());
            self.peer_metrics.insert(peer.id, metrics);
        }

        // Crear rate limiter si no existe
        if !self.rate_limiters.contains_key(&peer.id) {
            self.rate_limiters.insert(peer.id, RateLimitTracker::new());
        }
    }

    /// Calcular score inicial basado en stake y reputación
    fn calculate_initial_score(&self, peer: &PeerInfo) -> PeerGossipScore {
        let stake_score = (peer.stake as f64 / 1_000_000.0).min(50.0); // Max 50 puntos por stake
        let reputation_score = peer.reputation_score;

        let total_score = stake_score + reputation_score;

        PeerGossipScore {
            peer_id: peer.id,
            total_score,
            stake_score,
            uptime_score: 0.0,
            behavior_score: 0.0,
            reputation_score,
            status: PeerStatus::Good,
            last_updated: SystemTime::now(),
        }
    }

    /// Procesar mensaje recibido de un peer
    pub fn process_message(
        &mut self,
        peer_id: KademliaId,
        message_size: usize,
        is_valid: bool,
        topic: &str,
    ) -> MessageProcessingResult {
        // Verificar rate limiting
        if let Some(rate_limiter) = self.rate_limiters.get_mut(&peer_id) {
            if !rate_limiter.can_send_message(&self.config) {
                self.global_metrics.rate_limit_violations += 1;
                warn!("⚠️ Rate limit violation from peer: {}", peer_id.to_hex());
                return MessageProcessingResult::RateLimited;
            }
            rate_limiter.record_message();
        }

        // Actualizar métricas del peer
        if let Some(metrics) = self.peer_metrics.get_mut(&peer_id) {
            metrics.bandwidth_used += message_size as u64;
            metrics.last_activity = Some(SystemTime::now());
            metrics.subscribed_topics.insert(topic.to_string());

            if is_valid {
                metrics.valid_messages += 1;
            } else {
                metrics.invalid_messages += 1;
                info!("❌ Invalid message from peer: {}", peer_id.to_hex());
            }
        }

        // Detectar spam
        let is_spam = self.detect_spam(peer_id, message_size, topic);
        if is_spam {
            if let Some(metrics) = self.peer_metrics.get_mut(&peer_id) {
                metrics.spam_messages += 1;
            }
            self.global_metrics.spam_detected += 1;
        }

        // Actualizar score
        self.update_peer_score(peer_id, is_valid, is_spam);
        self.global_metrics.messages_processed += 1;

        if is_spam {
            MessageProcessingResult::Spam
        } else if is_valid {
            MessageProcessingResult::Valid
        } else {
            MessageProcessingResult::Invalid
        }
    }

    /// Detectar spam básico
    fn detect_spam(&self, peer_id: KademliaId, message_size: usize, _topic: &str) -> bool {
        if let Some(metrics) = self.peer_metrics.get(&peer_id) {
            // Detectar mensajes demasiado grandes
            if message_size > 1_000_000 {
                // 1MB
                return true;
            }

            // Detectar demasiados mensajes inválidos
            let total_messages = metrics.valid_messages + metrics.invalid_messages;
            if total_messages > 10 {
                let invalid_ratio = metrics.invalid_messages as f64 / total_messages as f64;
                if invalid_ratio > 0.5 {
                    // Más del 50% inválidos
                    return true;
                }
            }
        }

        false
    }

    /// Actualizar score de un peer
    fn update_peer_score(&mut self, peer_id: KademliaId, is_valid: bool, is_spam: bool) {
        if let Some(score) = self.peer_scores.get_mut(&peer_id) {
            let mut score_delta = 0.0;

            // Bonificación por mensaje válido
            if is_valid {
                score_delta += 0.1;
            } else {
                score_delta -= self.config.invalid_message_penalty;
            }

            // Penalización por spam
            if is_spam {
                score_delta -= self.config.spam_penalty;
            }

            // Actualizar score de comportamiento
            score.behavior_score += score_delta;

            // Calcular uptime score
            if let Some(peer_info) = self.peer_info.get(&peer_id) {
                score.uptime_score = peer_info.uptime.as_secs() as f64 / (24.0 * 3600.0);
                // Días
            }

            // Recalcular score total
            let total_score = self.config.stake_weight * score.stake_score
                + self.config.uptime_weight * score.uptime_score
                + score.behavior_score
                + score.reputation_score;

            // Actualizar estado basado en score
            score.total_score = total_score;
            score.status = if total_score >= 80.0 {
                PeerStatus::Good
            } else if total_score >= 50.0 {
                PeerStatus::Good
            } else if total_score >= 20.0 {
                PeerStatus::Graylisted
            } else {
                PeerStatus::Banned
            };
            score.last_updated = SystemTime::now();

            debug!(
                "📊 Updated score for peer {}: {:.2}",
                peer_id.to_hex(),
                score.total_score
            );
        }
    }

    /// Determinar estado del peer basado en score
    fn determine_peer_status(&self, score: f64) -> PeerStatus {
        if score < self.config.min_score_threshold {
            PeerStatus::Banned
        } else if score < self.config.graylist_threshold {
            PeerStatus::Graylisted
        } else {
            PeerStatus::Good
        }
    }

    /// Obtener score de un peer
    pub fn get_peer_score(&self, peer_id: &KademliaId) -> Option<f64> {
        self.peer_scores.get(peer_id).map(|s| s.total_score)
    }

    /// Verificar si un peer está permitido
    pub fn is_peer_allowed(&self, peer_id: &KademliaId) -> bool {
        match self.peer_scores.get(peer_id) {
            Some(score) => !matches!(
                score.status,
                PeerStatus::Banned | PeerStatus::Blocked { .. }
            ),
            None => true, // Permitir peers nuevos inicialmente
        }
    }

    /// Obtener lista de peers ordenados por score
    pub fn get_top_peers(&self, count: usize) -> Vec<(KademliaId, f64)> {
        let mut peers: Vec<_> = self
            .peer_scores
            .iter()
            .filter(|(_, score)| matches!(score.status, PeerStatus::Good))
            .map(|(id, score)| (*id, score.total_score))
            .collect();

        peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        peers.into_iter().take(count).collect()
    }

    /// Limpiar peers inactivos
    pub fn cleanup_inactive_peers(&mut self) {
        let now = SystemTime::now();
        let inactive_threshold = Duration::from_secs(3600); // 1 hora

        let inactive_peers: Vec<KademliaId> = self
            .peer_metrics
            .iter()
            .filter(|(_, metrics)| {
                if let Some(last_activity) = metrics.last_activity {
                    now.duration_since(last_activity).unwrap_or(Duration::MAX) > inactive_threshold
                } else {
                    true
                }
            })
            .map(|(id, _)| *id)
            .collect();

        for peer_id in inactive_peers {
            info!("🧹 Removing inactive peer: {}", peer_id.to_hex());
            self.peer_scores.remove(&peer_id);
            self.peer_metrics.remove(&peer_id);
            self.rate_limiters.remove(&peer_id);
            self.peer_info.remove(&peer_id);
        }

        self.update_global_metrics();
    }

    /// Actualizar métricas globales
    fn update_global_metrics(&mut self) {
        self.global_metrics.total_peers = self.peer_scores.len();
        self.global_metrics.good_peers = 0;
        self.global_metrics.graylisted_peers = 0;
        self.global_metrics.blocked_peers = 0;
        self.global_metrics.banned_peers = 0;

        let mut total_score = 0.0;
        for score in self.peer_scores.values() {
            total_score += score.total_score;
            match score.status {
                PeerStatus::Good => self.global_metrics.good_peers += 1,
                PeerStatus::Graylisted => self.global_metrics.graylisted_peers += 1,
                PeerStatus::Blocked { .. } => self.global_metrics.blocked_peers += 1,
                PeerStatus::Banned => self.global_metrics.banned_peers += 1,
            }
        }

        if !self.peer_scores.is_empty() {
            self.global_metrics.average_score = total_score / self.peer_scores.len() as f64;
        }
    }

    /// Obtener métricas globales
    pub fn get_global_metrics(&self) -> &GlobalScoringMetrics {
        &self.global_metrics
    }

    /// Generar reporte de estado
    pub fn generate_status_report(&self) -> GossipScoringReport {
        GossipScoringReport {
            total_peers: self.peer_scores.len(),
            top_peers: self.get_top_peers(10),
            global_metrics: self.global_metrics.clone(),
            config: self.config.clone(),
            timestamp: SystemTime::now(),
        }
    }
}

/// Resultado del procesamiento de un mensaje
#[derive(Debug, Clone, PartialEq)]
pub enum MessageProcessingResult {
    Valid,
    Invalid,
    Spam,
    RateLimited,
}

/// Reporte de estado del sistema de scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipScoringReport {
    pub total_peers: usize,
    pub top_peers: Vec<(KademliaId, f64)>,
    pub global_metrics: GlobalScoringMetrics,
    pub config: GossipScoringConfig,
    pub timestamp: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::kademlia_dht::PeerInfo;
    use std::net::SocketAddr;

    #[test]
    fn test_rate_limiting() {
        let mut tracker = RateLimitTracker::new();
        let config = GossipScoringConfig {
            max_messages_per_window: 2,
            rate_limit_window: 60,
            ..Default::default()
        };

        // Primeros dos mensajes deben pasar
        assert!(tracker.can_send_message(&config));
        tracker.record_message();
        assert!(tracker.can_send_message(&config));
        tracker.record_message();

        // Tercer mensaje debe ser bloqueado
        assert!(!tracker.can_send_message(&config));
    }

    #[test]
    fn test_peer_scoring() {
        let config = GossipScoringConfig::default();
        let mut scorer = GossipScorer::new(config);

        let peer_id = KademliaId::from_str("test_peer");
        let peer_info = PeerInfo::new(peer_id, "127.0.0.1:8080".parse().unwrap(), 5_000_000);

        scorer.update_peer_info(peer_info);

        // Procesar mensaje válido
        let result = scorer.process_message(peer_id, 1000, true, "test_topic");
        assert_eq!(result, MessageProcessingResult::Valid);

        // Procesar mensaje inválido
        let result = scorer.process_message(peer_id, 1000, false, "test_topic");
        assert_eq!(result, MessageProcessingResult::Invalid);

        // Score debe haber cambiado
        let score = scorer.get_peer_score(&peer_id).unwrap();
        assert!(score != 0.0);
    }

    #[test]
    fn test_spam_detection() {
        let config = GossipScoringConfig::default();
        let mut scorer = GossipScorer::new(config);

        let peer_id = KademliaId::from_str("spam_peer");
        let peer_info = PeerInfo::new(peer_id, "127.0.0.1:8081".parse().unwrap(), 1_000_000);

        scorer.update_peer_info(peer_info);

        // Mensaje demasiado grande debe ser detectado como spam
        let result = scorer.process_message(peer_id, 2_000_000, true, "test_topic");
        assert_eq!(result, MessageProcessingResult::Spam);
    }
}
