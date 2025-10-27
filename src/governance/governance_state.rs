//! # Estado Global de Gobernanza - AVO Protocol
//!
//! Sistema centralizado para gestionar el estado completo del sistema de gobernanza,
//! incluyendo propuestas, votaciones, delegaciones y métricas del sistema.
//!
//! ## Características
//! - **Estado Unificado**: Vista consolidada de toda la gobernanza
//! - **Métricas en Tiempo Real**: Estadísticas de participación y rendimiento
//! - **Sincronización**: Coherencia entre módulos de gobernanza
//! - **Auditoría**: Registro completo de actividades

use crate::error::{AvoError, AvoResult};
use crate::governance::{
    DelegationId, DelegationManager, ProposalId, ProposalManager, ProposalStatus, ProposalType,
    TokenAmount, Treasury, VotingPower, VotingSystem,
};
use crate::state::storage::AvocadoStorage;
use crate::types::{Hash, NodeId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Estado global consolidado del sistema de gobernanza
#[derive(Debug)]
pub struct GovernanceState {
    /// Gestor de propuestas
    proposal_manager: Arc<ProposalManager>,
    /// Sistema de votación
    voting_system: Arc<VotingSystem>,
    /// Gestor de delegaciones
    delegation_manager: Arc<DelegationManager>,
    /// Tesoro del protocolo
    treasury: Arc<Treasury>,
    /// Métricas del sistema
    metrics: Arc<RwLock<GovernanceMetrics>>,
    /// Configuración global
    config: GovernanceGlobalConfig,
    /// Estado de epochs de gobernanza
    epoch_state: Arc<RwLock<EpochState>>,
    /// Registro de actividades
    activity_log: Arc<RwLock<Vec<GovernanceActivity>>>,
    /// Storage para persistencia en RocksDB
    storage: Arc<AvocadoStorage>,
}

/// Configuración global del sistema de gobernanza
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceGlobalConfig {
    /// Duración de epoch en bloques
    pub epoch_duration: u64,
    /// Quorum mínimo para propuestas
    pub minimum_quorum: VotingPower,
    /// Threshold para aprobación de propuestas
    pub approval_threshold: f64, // 0.0 - 1.0
    /// Máximo de propuestas activas simultáneas
    pub max_active_proposals: u32,
    /// Tiempo mínimo entre propuestas del mismo tipo
    pub proposal_cooldown: u64,
    /// Habilitación de delegación automática
    pub auto_delegation_enabled: bool,
    /// Límite de poder de voto por entidad
    pub max_voting_power_per_entity: Option<VotingPower>,
}

/// Estado de un epoch de gobernanza
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochState {
    pub current_epoch: u64,
    pub epoch_start_block: u64,
    pub epoch_end_block: u64,
    pub active_proposals: HashSet<ProposalId>,
    pub completed_proposals: HashSet<ProposalId>,
    pub total_votes_cast: u64,
    pub total_voting_power: VotingPower,
    pub participation_rate: f64,
    pub top_delegates: Vec<(NodeId, VotingPower)>,
}

/// Métricas consolidadas del sistema de gobernanza
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceMetrics {
    /// Métricas de propuestas
    pub proposal_metrics: ProposalMetrics,
    /// Métricas de votación
    pub voting_metrics: VotingMetrics,
    /// Métricas de delegación
    pub delegation_metrics: DelegationMetrics,
    /// Métricas del tesoro
    pub treasury_metrics: TreasuryMetrics,
    /// Métricas de participación
    pub participation_metrics: ParticipationMetrics,
    /// Última actualización
    pub last_updated: Timestamp,
}

/// Métricas específicas de propuestas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalMetrics {
    pub total_proposals: u64,
    pub active_proposals: u64,
    pub passed_proposals: u64,
    pub rejected_proposals: u64,
    pub executed_proposals: u64,
    pub proposals_by_type: HashMap<String, u64>,
    pub average_voting_duration: f64,
    pub success_rate: f64,
}

/// Métricas de votación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingMetrics {
    pub total_votes_cast: u64,
    pub unique_voters: u64,
    pub average_participation_rate: f64,
    pub voting_power_distribution: VotingPowerDistribution,
    pub vote_timing_statistics: VoteTimingStats,
}

/// Distribución del poder de voto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingPowerDistribution {
    pub gini_coefficient: f64,    // Medida de desigualdad
    pub top_1_percent_power: f64, // % del poder total
    pub top_10_percent_power: f64,
    pub median_voting_power: VotingPower,
    pub voting_power_percentiles: HashMap<u8, VotingPower>, // P10, P25, P50, P75, P90, P95, P99
}

/// Estadísticas de timing de votos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteTimingStats {
    pub average_response_time: f64, // En bloques
    pub median_response_time: f64,
    pub early_voters_percentage: f64,      // Votan en primeras 24h
    pub last_minute_votes_percentage: f64, // Votan en últimas 2h
}

/// Métricas de delegación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationMetrics {
    pub total_delegations: u64,
    pub active_delegations: u64,
    pub delegation_participation_rate: f64,
    pub average_delegation_size: VotingPower,
    pub top_delegates: Vec<DelegateRanking>,
    pub delegation_concentration: f64, // Índice de concentración
}

/// Ranking de delegados
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateRanking {
    pub node_id: NodeId,
    pub delegated_power: VotingPower,
    pub delegation_count: u64,
    pub performance_score: f64,
    pub rank: u32,
}

/// Métricas del tesoro
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryMetrics {
    pub total_balance: TokenAmount,
    pub monthly_inflow: TokenAmount,
    pub monthly_outflow: TokenAmount,
    pub burn_rate: f64, // Meses de runway restantes
    pub approved_spending: TokenAmount,
    pub pending_spending: TokenAmount,
}

/// Métricas de participación general
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationMetrics {
    pub active_governance_participants: u64,
    pub voter_retention_rate: f64,
    pub new_participants_per_epoch: u64,
    pub governance_health_score: f64, // 0.0 - 1.0
    pub decentralization_index: f64,  // 0.0 - 1.0
}

/// Registro de actividad en el sistema de gobernanza
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceActivity {
    pub id: u64,
    pub timestamp: Timestamp,
    pub activity_type: ActivityType,
    pub actor: NodeId,
    pub details: serde_json::Value,
    pub block_number: u64,
    pub transaction_hash: Option<Hash>,
}

/// Tipos de actividades en gobernanza
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityType {
    ProposalCreated {
        proposal_id: ProposalId,
    },
    VoteCast {
        proposal_id: ProposalId,
        choice: String,
    },
    DelegationCreated {
        delegation_id: DelegationId,
    },
    DelegationRevoked {
        delegation_id: DelegationId,
    },
    ProposalExecuted {
        proposal_id: ProposalId,
    },
    TreasuryTransfer {
        amount: TokenAmount,
        recipient: NodeId,
    },
    ParameterChanged {
        parameter: String,
        old_value: String,
        new_value: String,
    },
    EmergencyAction {
        action: String,
    },
}

/// Estado cacheado para optimización
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedState {
    pub data: serde_json::Value,
    pub computed_at: Timestamp,
    pub expires_at: Timestamp,
    pub dependencies: Vec<String>, // Claves de dependencias
}

impl GovernanceState {
    /// Crear nuevo estado de gobernanza
    pub async fn new(
        proposal_manager: Arc<ProposalManager>,
        voting_system: Arc<VotingSystem>,
        delegation_manager: Arc<DelegationManager>,
        treasury: Arc<Treasury>,
        config: GovernanceGlobalConfig,
        storage: Arc<AvocadoStorage>,
    ) -> AvoResult<Self> {
        let initial_metrics = GovernanceMetrics {
            proposal_metrics: ProposalMetrics {
                total_proposals: 0,
                active_proposals: 0,
                passed_proposals: 0,
                rejected_proposals: 0,
                executed_proposals: 0,
                proposals_by_type: HashMap::new(),
                average_voting_duration: 0.0,
                success_rate: 0.0,
            },
            voting_metrics: VotingMetrics {
                total_votes_cast: 0,
                unique_voters: 0,
                average_participation_rate: 0.0,
                voting_power_distribution: VotingPowerDistribution {
                    gini_coefficient: 0.0,
                    top_1_percent_power: 0.0,
                    top_10_percent_power: 0.0,
                    median_voting_power: 0,
                    voting_power_percentiles: HashMap::new(),
                },
                vote_timing_statistics: VoteTimingStats {
                    average_response_time: 0.0,
                    median_response_time: 0.0,
                    early_voters_percentage: 0.0,
                    last_minute_votes_percentage: 0.0,
                },
            },
            delegation_metrics: DelegationMetrics {
                total_delegations: 0,
                active_delegations: 0,
                delegation_participation_rate: 0.0,
                average_delegation_size: 0,
                top_delegates: Vec::new(),
                delegation_concentration: 0.0,
            },
            treasury_metrics: TreasuryMetrics {
                total_balance: 0,
                monthly_inflow: 0,
                monthly_outflow: 0,
                burn_rate: 0.0,
                approved_spending: 0,
                pending_spending: 0,
            },
            participation_metrics: ParticipationMetrics {
                active_governance_participants: 0,
                voter_retention_rate: 0.0,
                new_participants_per_epoch: 0,
                governance_health_score: 0.0,
                decentralization_index: 0.0,
            },
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let initial_epoch = EpochState {
            current_epoch: 1,
            epoch_start_block: 0,
            epoch_end_block: config.epoch_duration,
            active_proposals: HashSet::new(),
            completed_proposals: HashSet::new(),
            total_votes_cast: 0,
            total_voting_power: 0,
            participation_rate: 0.0,
            top_delegates: Vec::new(),
        };

        Ok(Self {
            proposal_manager,
            voting_system,
            delegation_manager,
            treasury,
            metrics: Arc::new(RwLock::new(initial_metrics)),
            config,
            epoch_state: Arc::new(RwLock::new(initial_epoch)),
            activity_log: Arc::new(RwLock::new(Vec::new())),
            storage,
        })
    }

    /// Actualizar métricas del sistema
    pub async fn update_metrics(&self) -> AvoResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Recopilar métricas de todos los subsistemas
        let proposal_metrics = self.collect_proposal_metrics().await?;
        let voting_metrics = self.collect_voting_metrics().await?;
        let delegation_metrics = self.collect_delegation_metrics().await?;
        let treasury_metrics = self.collect_treasury_metrics().await?;
        let participation_metrics = self.calculate_participation_metrics().await?;

        // Actualizar métricas consolidadas
        let mut metrics = self.metrics.write().await;
        *metrics = GovernanceMetrics {
            proposal_metrics,
            voting_metrics,
            delegation_metrics,
            treasury_metrics,
            participation_metrics,
            last_updated: now,
        };

        // Invalidar cache relacionado
        self.invalidate_cache(&["metrics", "health_score", "distribution"])
            .await;

        Ok(())
    }

    /// Avanzar al siguiente epoch
    pub async fn advance_epoch(&self, current_block: u64) -> AvoResult<()> {
        let mut epoch_state = self.epoch_state.write().await;

        // Finalizar epoch actual
        self.finalize_current_epoch(&epoch_state).await?;

        // Crear nuevo epoch
        epoch_state.current_epoch += 1;
        epoch_state.epoch_start_block = current_block;
        epoch_state.epoch_end_block = current_block + self.config.epoch_duration;
        epoch_state.active_proposals.clear();
        epoch_state.completed_proposals.clear();
        epoch_state.total_votes_cast = 0;
        epoch_state.total_voting_power = 0;
        epoch_state.participation_rate = 0.0;
        epoch_state.top_delegates.clear();

        // Registrar actividad
        self.log_activity(
            ActivityType::ParameterChanged {
                parameter: "current_epoch".to_string(),
                old_value: (epoch_state.current_epoch - 1).to_string(),
                new_value: epoch_state.current_epoch.to_string(),
            },
            NodeId::from("system"),
            current_block,
            None,
        )
        .await;

        Ok(())
    }

    /// Obtener resumen de salud del sistema de gobernanza
    pub async fn get_governance_health(&self) -> GovernanceHealthReport {
        let metrics = self.metrics.read().await;
        let epoch_state = self.epoch_state.read().await;

        // Calcular score de salud basado en múltiples factores
        let participation_score = (metrics.participation_metrics.governance_health_score * 0.3)
            + (metrics.voting_metrics.average_participation_rate * 0.2)
            + (metrics.delegation_metrics.delegation_participation_rate * 0.1);

        let decentralization_score = metrics.participation_metrics.decentralization_index * 0.2;

        let activity_score = if metrics.proposal_metrics.total_proposals > 0 {
            (metrics.proposal_metrics.success_rate * 0.1)
                + ((epoch_state.active_proposals.len() as f64
                    / self.config.max_active_proposals as f64)
                    .min(1.0)
                    * 0.1)
        } else {
            0.0
        };

        let overall_health = participation_score + decentralization_score + activity_score;

        GovernanceHealthReport {
            overall_health_score: overall_health.min(1.0),
            participation_health: participation_score,
            decentralization_health: decentralization_score,
            activity_health: activity_score,
            current_epoch: epoch_state.current_epoch,
            active_proposals_count: epoch_state.active_proposals.len() as u64,
            recommendations: self
                .generate_health_recommendations(&metrics, overall_health)
                .await,
            metrics_snapshot: metrics.clone(),
        }
    }

    /// Obtener estado consolidado para una vista específica
    pub async fn get_consolidated_view(&self, view_type: &str) -> AvoResult<serde_json::Value> {
        // Verificar cache primero
        if let Some(cached) = self.get_cached_state(view_type).await {
            return Ok(cached.data);
        }

        let result = match view_type {
            "dashboard" => self.create_dashboard_view().await?,
            "proposals" => self.create_proposals_view().await?,
            "voting" => self.create_voting_view().await?,
            "delegations" => self.create_delegations_view().await?,
            "treasury" => self.create_treasury_view().await?,
            "metrics" => serde_json::to_value(self.metrics.read().await.clone())?,
            _ => {
                return Err(AvoError::InvalidInput(format!(
                    "Unknown view type: {}",
                    view_type
                )))
            }
        };

        // Cache el resultado
        self.cache_state(view_type, &result, 300).await; // 5 minutos TTL

        Ok(result)
    }

    /// Registrar una nueva actividad
    pub async fn log_activity(
        &self,
        activity_type: ActivityType,
        actor: NodeId,
        block_number: u64,
        transaction_hash: Option<Hash>,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut log = self.activity_log.write().await;
        let activity_id = log.len() as u64 + 1;

        let activity = GovernanceActivity {
            id: activity_id,
            timestamp: now,
            activity_type,
            actor,
            details: serde_json::Value::Null, // TODO: Agregar detalles específicos
            block_number,
            transaction_hash,
        };

        log.push(activity);

        // Mantener solo las últimas 10000 actividades
        if log.len() > 10000 {
            log.drain(0..1000);
        }
    }

    /// Obtener historial de actividades
    pub async fn get_activity_history(
        &self,
        limit: Option<usize>,
        activity_type_filter: Option<&str>,
        actor_filter: Option<&NodeId>,
    ) -> Vec<GovernanceActivity> {
        let log = self.activity_log.read().await;

        let filtered: Vec<GovernanceActivity> = log
            .iter()
            .rev() // Más recientes primero
            .filter(|activity| {
                if let Some(type_filter) = activity_type_filter {
                    // Simplificada verificación de tipo
                    match (&activity.activity_type, type_filter) {
                        (ActivityType::ProposalCreated { .. }, "proposal") => true,
                        (ActivityType::VoteCast { .. }, "vote") => true,
                        (ActivityType::DelegationCreated { .. }, "delegation") => true,
                        (ActivityType::DelegationRevoked { .. }, "delegation") => true,
                        _ => false,
                    }
                } else {
                    true
                }
            })
            .filter(|activity| {
                if let Some(actor_filter) = actor_filter {
                    &activity.actor == actor_filter
                } else {
                    true
                }
            })
            .take(limit.unwrap_or(100))
            .cloned()
            .collect();

        filtered
    }

    // Métodos privados de utilidad

    async fn collect_proposal_metrics(&self) -> AvoResult<ProposalMetrics> {
        // TODO: Implementar recolección desde ProposalManager
        Ok(ProposalMetrics {
            total_proposals: 0,
            active_proposals: 0,
            passed_proposals: 0,
            rejected_proposals: 0,
            executed_proposals: 0,
            proposals_by_type: HashMap::new(),
            average_voting_duration: 0.0,
            success_rate: 0.0,
        })
    }

    async fn collect_voting_metrics(&self) -> AvoResult<VotingMetrics> {
        // TODO: Implementar recolección desde VotingSystem
        Ok(VotingMetrics {
            total_votes_cast: 0,
            unique_voters: 0,
            average_participation_rate: 0.0,
            voting_power_distribution: VotingPowerDistribution {
                gini_coefficient: 0.0,
                top_1_percent_power: 0.0,
                top_10_percent_power: 0.0,
                median_voting_power: 0,
                voting_power_percentiles: HashMap::new(),
            },
            vote_timing_statistics: VoteTimingStats {
                average_response_time: 0.0,
                median_response_time: 0.0,
                early_voters_percentage: 0.0,
                last_minute_votes_percentage: 0.0,
            },
        })
    }

    async fn collect_delegation_metrics(&self) -> AvoResult<DelegationMetrics> {
        let stats = self.delegation_manager.get_delegation_statistics().await;

        Ok(DelegationMetrics {
            total_delegations: stats.total_delegations,
            active_delegations: stats.total_delegations, // Asumimos todas activas por simplicidad
            delegation_participation_rate: if stats.total_delegators > 0 {
                stats.total_delegations as f64 / stats.total_delegators as f64
            } else {
                0.0
            },
            average_delegation_size: stats.average_delegation_size,
            top_delegates: Vec::new(),     // TODO: Implementar ranking
            delegation_concentration: 0.0, // TODO: Calcular concentración
        })
    }

    async fn collect_treasury_metrics(&self) -> AvoResult<TreasuryMetrics> {
        // TODO: Implementar recolección desde Treasury
        Ok(TreasuryMetrics {
            total_balance: 0,
            monthly_inflow: 0,
            monthly_outflow: 0,
            burn_rate: 0.0,
            approved_spending: 0,
            pending_spending: 0,
        })
    }

    async fn calculate_participation_metrics(&self) -> AvoResult<ParticipationMetrics> {
        // TODO: Implementar cálculo de participación
        Ok(ParticipationMetrics {
            active_governance_participants: 0,
            voter_retention_rate: 0.0,
            new_participants_per_epoch: 0,
            governance_health_score: 0.75, // Valor por defecto optimista
            decentralization_index: 0.8,   // Valor por defecto
        })
    }

    async fn finalize_current_epoch(&self, epoch_state: &EpochState) -> AvoResult<()> {
        // TODO: Finalizar propuestas del epoch, calcular estadísticas finales
        Ok(())
    }

    async fn generate_health_recommendations(
        &self,
        metrics: &GovernanceMetrics,
        health_score: f64,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if health_score < 0.5 {
            recommendations.push(
                "⚠️ Governance health is critically low. Consider emergency measures.".to_string(),
            );
        }

        if metrics.voting_metrics.average_participation_rate < 0.3 {
            recommendations
                .push("📈 Low voter participation. Consider incentive programs.".to_string());
        }

        if metrics.participation_metrics.decentralization_index < 0.6 {
            recommendations
                .push("🌐 Improve decentralization. Power is too concentrated.".to_string());
        }

        if metrics.proposal_metrics.success_rate < 0.4 {
            recommendations.push(
                "🎯 Many proposals failing. Review proposal quality and criteria.".to_string(),
            );
        }

        if recommendations.is_empty() {
            recommendations
                .push("✅ Governance system is healthy. Continue monitoring.".to_string());
        }

        recommendations
    }

    async fn create_dashboard_view(&self) -> AvoResult<serde_json::Value> {
        let metrics = self.metrics.read().await;
        let epoch_state = self.epoch_state.read().await;

        Ok(serde_json::json!({
            "epoch": epoch_state.current_epoch,
            "active_proposals": epoch_state.active_proposals.len(),
            "participation_rate": metrics.voting_metrics.average_participation_rate,
            "health_score": metrics.participation_metrics.governance_health_score,
            "treasury_balance": metrics.treasury_metrics.total_balance,
            "total_delegations": metrics.delegation_metrics.total_delegations
        }))
    }

    async fn create_proposals_view(&self) -> AvoResult<serde_json::Value> {
        // TODO: Implementar vista de propuestas
        Ok(serde_json::json!({}))
    }

    async fn create_voting_view(&self) -> AvoResult<serde_json::Value> {
        // TODO: Implementar vista de votación
        Ok(serde_json::json!({}))
    }

    async fn create_delegations_view(&self) -> AvoResult<serde_json::Value> {
        // TODO: Implementar vista de delegaciones
        Ok(serde_json::json!({}))
    }

    async fn create_treasury_view(&self) -> AvoResult<serde_json::Value> {
        // TODO: Implementar vista del tesoro
        Ok(serde_json::json!({}))
    }

    async fn get_cached_state(&self, key: &str) -> Option<CachedState> {
        let cache_key = format!("gov_cache_{}", key);
        if let Ok(Some(data)) = self.storage.get_governance_state(&cache_key).await {
            if let Ok(cached) = serde_json::from_slice::<CachedState>(&data) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if now < cached.expires_at {
                    return Some(cached);
                }
            }
        }
        None
    }

    async fn cache_state(&self, key: &str, data: &serde_json::Value, ttl_seconds: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cached_state = CachedState {
            data: data.clone(),
            computed_at: now,
            expires_at: now + ttl_seconds,
            dependencies: Vec::new(),
        };

        let cache_key = format!("gov_cache_{}", key);
        if let Ok(serialized) = serde_json::to_vec(&cached_state) {
            let _ = self
                .storage
                .store_governance_state(&cache_key, &serialized)
                .await;
        }
    }

    async fn invalidate_cache(&self, keys: &[&str]) {
        // Para simplificar, ya no mantenemos caché en memoria
        // RocksDB maneja la persistencia directamente
    }
}

/// Reporte de salud del sistema de gobernanza
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceHealthReport {
    pub overall_health_score: f64,
    pub participation_health: f64,
    pub decentralization_health: f64,
    pub activity_health: f64,
    pub current_epoch: u64,
    pub active_proposals_count: u64,
    pub recommendations: Vec<String>,
    pub metrics_snapshot: GovernanceMetrics,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{AvoError, AvoResult};
    use crate::governance::{
        DelegationConfig, DelegationManager, GovernanceConfig, ProposalManager, Treasury,
        TreasuryConfig, VotingConfig, VotingSystem,
    };
    use crate::state::storage::{AvocadoStorage, StorageConfig};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn temp_storage() -> AvoResult<(tempfile::TempDir, Arc<AvocadoStorage>)> {
        let dir = tempfile::tempdir().map_err(|e| AvoError::StorageError {
            reason: format!("Failed to create temp dir: {}", e),
        })?;
        let mut storage_config = StorageConfig::with_path(dir.path().to_path_buf());
        storage_config.enable_wal = false;
        let storage = Arc::new(AvocadoStorage::new(storage_config)?);
        Ok((dir, storage))
    }

    fn sample_delegation_config() -> DelegationConfig {
        DelegationConfig {
            max_delegation_depth: 3,
            min_delegation_amount: 100,
            max_fee_percentage: 10.0,
            delegation_cooldown: 3600,
            auto_expiry_enabled: true,
            verification_required: false,
        }
    }

    fn sample_treasury_config() -> TreasuryConfig {
        TreasuryConfig {
            multi_sig_threshold: 2,
            authorized_signers: vec![],
            automatic_transfers: HashMap::new(),
            fee_distribution: crate::governance::FeeDistribution::default(),
            reporting_frequency: 24 * 60 * 60,
            audit_frequency: 7 * 24 * 60 * 60,
        }
    }

    fn sample_global_config() -> GovernanceGlobalConfig {
        GovernanceGlobalConfig {
            epoch_duration: 7200,
            minimum_quorum: 1_000,
            approval_threshold: 0.6,
            max_active_proposals: 10,
            proposal_cooldown: 3600,
            auto_delegation_enabled: true,
            max_voting_power_per_entity: Some(100_000),
        }
    }

    async fn build_governance_state() -> AvoResult<(GovernanceState, tempfile::TempDir)> {
        let (temp_dir, storage) = temp_storage()?;

        let proposal_manager = Arc::new(ProposalManager::new(GovernanceConfig::default()));
        let voting_system = Arc::new(VotingSystem::new(VotingConfig::default()));
        let delegation_manager = Arc::new(DelegationManager::with_storage(
            sample_delegation_config(),
            storage.clone(),
        ));
        let treasury = Arc::new(Treasury::new(sample_treasury_config(), storage.clone()));

        let state = GovernanceState::new(
            proposal_manager,
            voting_system,
            delegation_manager,
            treasury,
            sample_global_config(),
            storage,
        )
        .await?;

        Ok((state, temp_dir))
    }

    #[tokio::test]
    async fn governance_state_initializes() -> AvoResult<()> {
        let (governance_state, _temp_dir) = build_governance_state().await?;
        let health = governance_state.get_governance_health().await;
        assert_eq!(health.current_epoch, 1);
        assert_eq!(health.active_proposals_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn metrics_update_succeeds() -> AvoResult<()> {
        let (governance_state, _temp_dir) = build_governance_state().await?;
        governance_state.update_metrics().await?;
        let metrics = governance_state.metrics.read().await;
        assert!(metrics.last_updated > 0);
        Ok(())
    }
}
