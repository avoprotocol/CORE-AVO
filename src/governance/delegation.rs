//! # Delegación de Votos - AVO Protocol
//!
//! Sistema avanzado de delegación que permite a los poseedores de tokens
//! delegar su poder de voto a representantes de confianza.
//!
//! ## Características
//! - **Delegación Flexible**: Por categoría o global
//! - **Revocación Instantánea**: Cambio de delegado en tiempo real
//! - **Transparencia Total**: Registro público de delegaciones
//! - **Auto-Delegación**: Delegación automática basada en expertise

use crate::error::{AvoError, AvoResult};
use crate::governance::{ProposalType, TokenAmount, VotingPower};
use crate::state::storage::AvocadoStorage;
use crate::types::{NodeId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Get the global storage instance for governance operations
async fn get_storage() -> Option<Arc<AvocadoStorage>> {
    // Try to create a new storage instance
    if let Ok(storage) = crate::state::storage::AvocadoStorage::new(Default::default()) {
        return Some(Arc::new(storage));
    }

    None
}

/// Identificador único para delegaciones
pub type DelegationId = u64;

/// Tipos de delegación disponibles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DelegationType {
    /// Delegación completa de todos los votos
    Complete,
    /// Delegación por categoría de propuestas
    Category {
        categories: HashSet<ProposalCategory>,
    },
    /// Delegación temporal con fecha de expiración
    Temporary {
        expires_at: Timestamp,
        categories: Option<HashSet<ProposalCategory>>,
    },
    /// Delegación condicional basada en criterios
    Conditional {
        conditions: Vec<DelegationCondition>,
        categories: HashSet<ProposalCategory>,
    },
}

/// Categorías de propuestas para delegación específica
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProposalCategory {
    Technical,
    Economic,
    Governance,
    Security,
    Emergency,
    Treasury,
    Validator,
    Custom(String),
}

/// Condiciones para delegación condicional
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DelegationCondition {
    /// Solo si el monto en juego es menor al límite
    MaxAmount(TokenAmount),
    /// Solo para propuestas de duración específica
    MaxDuration(u64), // en bloques
    /// Solo si el quorum mínimo es alcanzado
    MinQuorum(VotingPower),
    /// Solo para ciertos tipos de propuestas
    ProposalTypes(Vec<ProposalType>),
}

/// Registro de una delegación activa
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRecord {
    pub id: DelegationId,
    pub delegator: NodeId,
    pub delegate: NodeId,
    pub delegation_type: DelegationType,
    pub voting_power: VotingPower,
    pub created_at: Timestamp,
    pub last_used: Option<Timestamp>,
    pub is_active: bool,
    pub metadata: DelegationMetadata,
}

/// Metadatos adicionales de la delegación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationMetadata {
    pub reason: Option<String>,
    pub reputation_weight: f64,
    pub performance_score: Option<f64>,
    pub trust_level: TrustLevel,
    pub fees: DelegationFees,
}

/// Nivel de confianza en el delegado
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustLevel {
    Low,
    Medium,
    High,
    Verified,
}

/// Estructura de fees para delegación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationFees {
    pub percentage: f64, // 0.0 - 100.0
    pub fixed_amount: TokenAmount,
    pub performance_bonus: Option<f64>,
}

/// Perfil de un delegado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateProfile {
    pub node_id: NodeId,
    pub name: Option<String>,
    pub description: Option<String>,
    pub expertise_areas: HashSet<ProposalCategory>,
    pub voting_history: VotingPerformance,
    pub reputation_score: f64,
    pub total_delegated_power: VotingPower,
    pub delegation_count: u64,
    pub fee_structure: DelegationFees,
    pub is_accepting_delegations: bool,
    pub max_delegations: Option<u64>,
    pub verification_status: VerificationStatus,
}

/// Estado de verificación del delegado
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationStatus {
    Unverified,
    Pending,
    Verified,
    Revoked,
}

/// Estadísticas de rendimiento de votación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingPerformance {
    pub total_votes: u64,
    pub participation_rate: f64,
    pub alignment_score: f64,   // Con el resultado final
    pub response_time_avg: f64, // Tiempo promedio de respuesta
    pub last_activity: Timestamp,
    pub votes_by_category: HashMap<ProposalCategory, u64>,
}

/// Configuración del sistema de delegación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationConfig {
    pub max_delegation_depth: u8,           // Máximo nivel de re-delegación
    pub min_delegation_amount: VotingPower, // Cambiado de TokenAmount a VotingPower
    pub max_fee_percentage: f64,
    pub delegation_cooldown: u64, // Tiempo mínimo entre cambios
    pub auto_expiry_enabled: bool,
    pub verification_required: bool,
}

/// Sistema principal de gestión de delegaciones
#[derive(Debug)]
pub struct DelegationManager {
    /// Configuración del sistema
    config: DelegationConfig,
    /// Storage para persistencia en RocksDB
    storage: Arc<AvocadoStorage>,
    /// Contador para IDs únicos
    next_delegation_id: Arc<RwLock<DelegationId>>,
}

impl DelegationManager {
    /// Crear nuevo gestor de delegaciones
    pub async fn new(config: DelegationConfig) -> AvoResult<Self> {
        let storage = if let Some(storage) = get_storage().await {
            storage
        } else {
            return Err(AvoError::StorageError {
                reason: "Failed to initialize storage".to_string(),
            });
        };

        Ok(Self::with_storage(config, storage))
    }

    /// Crear gestor usando un storage específico (útil para tests)
    pub fn with_storage(config: DelegationConfig, storage: Arc<AvocadoStorage>) -> Self {
        Self {
            config,
            storage,
            next_delegation_id: Arc::new(RwLock::new(1)),
        }
    }

    /// Crear una nueva delegación
    pub async fn create_delegation(
        &self,
        delegator: NodeId,
        delegate: NodeId,
        delegation_type: DelegationType,
        voting_power: VotingPower,
        metadata: DelegationMetadata,
    ) -> AvoResult<DelegationId> {
        // Validar parámetros
        self.validate_delegation_params(&delegator, &delegate, voting_power)
            .await?;

        // Verificar cooldown
        self.check_delegation_cooldown(&delegator).await?;

        // Crear registro de delegación
        let delegation_id = {
            let mut next_id = self.next_delegation_id.write().await;
            let id = *next_id;
            *next_id += 1;
            id
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let delegation = DelegationRecord {
            id: delegation_id,
            delegator: delegator.clone(),
            delegate: delegate.clone(),
            delegation_type: delegation_type.clone(),
            voting_power,
            created_at: now,
            last_used: None,
            is_active: true,
            metadata,
        };

        // Guardar delegación en RocksDB
        let delegation_key = format!("delegation_{}", delegation_id);
        let delegation_data =
            serde_json::to_vec(&delegation).map_err(|e| AvoError::JsonError { source: e })?;
        self.storage
            .store_governance_delegation(&delegation_key, &delegation_data)
            .await?;

        // Guardar índices para búsquedas eficientes
        let delegator_key = format!("delegator_{}", delegator);
        let delegate_key = format!("delegate_{}", delegate);
        let category_key = match &delegation_type {
            DelegationType::Category { categories } => {
                if let Some(first_cat) = categories.iter().next() {
                    format!("category_{:?}", first_cat)
                } else {
                    "category_general".to_string()
                }
            }
            _ => "category_general".to_string(),
        };

        // Guardar en índices
        self.storage
            .store_governance_delegation(&delegator_key, &delegation_data)
            .await?;
        self.storage
            .store_governance_delegation(&delegate_key, &delegation_data)
            .await?;
        self.storage
            .store_governance_delegation(&category_key, &delegation_data)
            .await?;

        // Actualizar perfil del delegado
        self.update_delegate_profile(&delegate, voting_power as i64)
            .await?;

        Ok(delegation_id)
    }

    /// Revocar una delegación
    pub async fn revoke_delegation(
        &self,
        delegator: &NodeId,
        delegation_id: DelegationId,
    ) -> AvoResult<()> {
        // Verificar ownership desde RocksDB
        let delegation_key = format!("delegation_{}", delegation_id);
        let delegation_data = self
            .storage
            .get_governance_delegation(&delegation_key)
            .await?;
        let delegation = match delegation_data {
            Some(data) => serde_json::from_slice::<DelegationRecord>(&data)
                .map_err(|e| AvoError::JsonError { source: e })?,
            None => return Err(AvoError::NotFound("Delegation not found".to_string())),
        };

        if delegation.delegator != *delegator || !delegation.is_active {
            return Err(AvoError::Unauthorized(
                "Delegation not owned or inactive".to_string(),
            ));
        }

        // Marcar como inactiva en RocksDB
        let mut updated_delegation = delegation.clone();
        updated_delegation.is_active = false;
        let updated_data = serde_json::to_vec(&updated_delegation)
            .map_err(|e| AvoError::JsonError { source: e })?;
        self.storage
            .store_governance_delegation(&delegation_key, &updated_data)
            .await?;

        // Actualizar perfil del delegado
        self.update_delegate_profile(&delegation.delegate, -(delegation.voting_power as i64))
            .await?;

        Ok(())
    }

    /// Registrar un nuevo delegado
    pub async fn register_delegate(
        &self,
        node_id: NodeId,
        profile: DelegateProfile,
    ) -> AvoResult<()> {
        // Validar perfil
        if profile.node_id != node_id {
            return Err(AvoError::InvalidInput("Node ID mismatch".to_string()));
        }

        if profile.fee_structure.percentage > self.config.max_fee_percentage {
            return Err(AvoError::InvalidInput(
                "Fee percentage too high".to_string(),
            ));
        }

        // Guardar perfil en RocksDB
        let profile_key = format!("delegate_profile_{}", node_id);
        let profile_data =
            serde_json::to_vec(&profile).map_err(|e| AvoError::JsonError { source: e })?;
        self.storage
            .store_governance_delegation(&profile_key, &profile_data)
            .await?;

        // Actualizar mapeo de expertos por categoría
        for category in &profile.expertise_areas {
            let expert_key = format!("category_expert_{:?}_{}", category, node_id);
            let node_data =
                serde_json::to_vec(&node_id).map_err(|e| AvoError::JsonError { source: e })?;
            self.storage
                .store_governance_delegation(&expert_key, &node_data)
                .await?;
        }

        Ok(())
    }

    /// Obtener poder de voto efectivo para una propuesta
    pub async fn get_effective_voting_power(
        &self,
        voter: &NodeId,
        proposal_category: &ProposalCategory,
    ) -> AvoResult<VotingPower> {
        let delegate_key = format!("delegate_{}", voter);
        let mut total_power = 0u64;

        // Buscar delegaciones donde este nodo es el delegado
        if let Some(delegation_data) = self
            .storage
            .get_governance_delegation(&delegate_key)
            .await?
        {
            let delegation = serde_json::from_slice::<DelegationRecord>(&delegation_data)
                .map_err(|e| AvoError::JsonError { source: e })?;

            if !delegation.is_active {
                return Ok(total_power);
            }

            // Verificar si la delegación aplica a esta categoría
            let applies = match &delegation.delegation_type {
                DelegationType::Complete => true,
                DelegationType::Category { categories } => categories.contains(proposal_category),
                DelegationType::Temporary {
                    expires_at,
                    categories,
                } => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    if now > *expires_at {
                        return Ok(total_power); // Delegación expirada
                    }

                    if let Some(cats) = categories {
                        cats.contains(proposal_category)
                    } else {
                        true
                    }
                }
                DelegationType::Conditional { categories, .. } => {
                    categories.contains(proposal_category)
                    // TODO: Evaluar condiciones adicionales
                }
            };

            if applies {
                total_power += delegation.voting_power;
            }
        }

        Ok(total_power)
    }

    /// Obtener recomendaciones de delegados para una categoría
    pub async fn get_recommended_delegates(
        &self,
        category: &ProposalCategory,
        max_results: usize,
    ) -> AvoResult<Vec<DelegateProfile>> {
        let mut recommendations = Vec::new();

        // Buscar expertos en esta categoría
        let expert_key_prefix = format!("category_expert_{:?}_", category);

        // Esta es una implementación simplificada - en un caso real implementaríamos
        // un método para buscar por prefijo en RocksDB
        for i in 0..max_results {
            let expert_key = format!("{}{}", expert_key_prefix, i);
            if let Some(node_data) = self.storage.get_governance_delegation(&expert_key).await? {
                let node_id = serde_json::from_slice::<NodeId>(&node_data)
                    .map_err(|e| AvoError::JsonError { source: e })?;
                let profile_key = format!("delegate_profile_{}", node_id);
                if let Some(profile_data) =
                    self.storage.get_governance_delegation(&profile_key).await?
                {
                    let profile = serde_json::from_slice::<DelegateProfile>(&profile_data)
                        .map_err(|e| AvoError::JsonError { source: e })?;
                    if profile.is_accepting_delegations
                        && profile.verification_status == VerificationStatus::Verified
                    {
                        recommendations.push(profile);
                        if recommendations.len() >= max_results {
                            break;
                        }
                    }
                }
            }
        }

        // Ordenar por reputación y rendimiento
        recommendations.sort_by(|a, b| {
            let score_a = a.reputation_score * a.voting_history.participation_rate;
            let score_b = b.reputation_score * b.voting_history.participation_rate;
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        recommendations.truncate(max_results);
        Ok(recommendations)
    }

    /// Obtener estadísticas de delegación del sistema
    pub async fn get_delegation_statistics(&self) -> DelegationStatistics {
        // Para estadísticas simplificadas - en un caso real implementaríamos
        // contadores eficientes en RocksDB
        DelegationStatistics {
            total_delegations: 0,
            total_delegators: 0,
            total_delegates: 0,
            verified_delegates: 0,
            total_delegated_power: 0,
            average_delegation_size: 0,
        }
    }

    // Métodos privados de validación y utilidad

    async fn validate_delegation_params(
        &self,
        delegator: &NodeId,
        delegate: &NodeId,
        voting_power: VotingPower,
    ) -> AvoResult<()> {
        if delegator == delegate {
            return Err(AvoError::InvalidInput(
                "Cannot delegate to self".to_string(),
            ));
        }

        if voting_power < self.config.min_delegation_amount {
            return Err(AvoError::InvalidInput(
                "Delegation amount too small".to_string(),
            ));
        }

        // Verificar que el delegado esté registrado
        let profile_key = format!("delegate_profile_{}", delegate);
        if self
            .storage
            .get_governance_delegation(&profile_key)
            .await?
            .is_none()
        {
            return Err(AvoError::NotFound("Delegate not registered".to_string()));
        }

        Ok(())
    }

    async fn check_delegation_cooldown(&self, delegator: &NodeId) -> AvoResult<()> {
        let delegator_key = format!("delegator_{}", delegator);

        if let Some(delegation_data) = self
            .storage
            .get_governance_delegation(&delegator_key)
            .await?
        {
            let delegation = serde_json::from_slice::<DelegationRecord>(&delegation_data)
                .map_err(|e| AvoError::JsonError { source: e })?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if delegation.is_active && now - delegation.created_at < self.config.delegation_cooldown
            {
                return Err(AvoError::InvalidInput(
                    "Delegation cooldown not expired".to_string(),
                ));
            }
        }

        Ok(())
    }

    async fn update_delegate_profile(&self, delegate: &NodeId, power_delta: i64) -> AvoResult<()> {
        let profile_key = format!("delegate_profile_{}", delegate);

        if let Some(profile_data) = self.storage.get_governance_delegation(&profile_key).await? {
            let mut profile = serde_json::from_slice::<DelegateProfile>(&profile_data)
                .map_err(|e| AvoError::JsonError { source: e })?;

            if power_delta > 0 {
                profile.total_delegated_power += power_delta as u64;
                profile.delegation_count += 1;
            } else {
                profile.total_delegated_power = profile
                    .total_delegated_power
                    .saturating_sub((-power_delta) as u64);
                profile.delegation_count = profile.delegation_count.saturating_sub(1);
            }

            // Guardar perfil actualizado
            let updated_data =
                serde_json::to_vec(&profile).map_err(|e| AvoError::JsonError { source: e })?;
            self.storage
                .store_governance_delegation(&profile_key, &updated_data)
                .await?;
        }

        Ok(())
    }
}

/// Estadísticas del sistema de delegación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationStatistics {
    pub total_delegations: u64,
    pub total_delegators: u64,
    pub total_delegates: u64,
    pub verified_delegates: u64,
    pub total_delegated_power: VotingPower,
    pub average_delegation_size: VotingPower,
}

/// Utilidad para mapear tipos de propuestas a categorías
impl From<&ProposalType> for ProposalCategory {
    fn from(proposal_type: &ProposalType) -> Self {
        match proposal_type {
            ProposalType::ParameterChange { .. } => ProposalCategory::Technical,
            ProposalType::TreasurySpend { .. } => ProposalCategory::Treasury,
            ProposalType::NetworkUpgrade { .. } => ProposalCategory::Technical,
            ProposalType::ValidatorChange { .. } => ProposalCategory::Validator,
            ProposalType::Emergency { .. } => ProposalCategory::Emergency,
            ProposalType::Custom { .. } => ProposalCategory::Governance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::storage::{AvocadoStorage, StorageConfig};
    use std::sync::Arc;

    fn manager_with_temp_storage(
        config: DelegationConfig,
    ) -> (DelegationManager, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().expect("failed to create delegation test temp dir");
        let mut storage_config = StorageConfig::with_path(temp_dir.path());
        storage_config.enable_wal = false;
        let storage = Arc::new(
            AvocadoStorage::new(storage_config).expect("failed to init delegation storage"),
        );
        (DelegationManager::with_storage(config, storage), temp_dir)
    }

    #[tokio::test]
    async fn test_delegation_creation() {
        let config = DelegationConfig {
            max_delegation_depth: 3,
            min_delegation_amount: 1000,
            max_fee_percentage: 10.0,
            delegation_cooldown: 86400, // 1 día
            auto_expiry_enabled: true,
            verification_required: false,
        };

        let (manager, _temp_dir) = manager_with_temp_storage(config);

        // Registrar delegado
        let delegate_id = NodeId::from("delegate1");
        let profile = DelegateProfile {
            node_id: delegate_id.clone(),
            name: Some("Expert Delegate".to_string()),
            description: Some("Technical expert".to_string()),
            expertise_areas: [ProposalCategory::Technical].iter().cloned().collect(),
            voting_history: VotingPerformance {
                total_votes: 0,
                participation_rate: 0.0,
                alignment_score: 0.0,
                response_time_avg: 0.0,
                last_activity: 0,
                votes_by_category: HashMap::new(),
            },
            reputation_score: 85.0,
            total_delegated_power: 0,
            delegation_count: 0,
            fee_structure: DelegationFees {
                percentage: 5.0,
                fixed_amount: 0,
                performance_bonus: Some(2.0),
            },
            is_accepting_delegations: true,
            max_delegations: Some(100),
            verification_status: VerificationStatus::Verified,
        };

        manager
            .register_delegate(delegate_id.clone(), profile)
            .await
            .unwrap();

        // Crear delegación
        let delegator_id = NodeId::from("delegator1");
        let metadata = DelegationMetadata {
            reason: Some("Trust in technical expertise".to_string()),
            reputation_weight: 1.0,
            performance_score: None,
            trust_level: TrustLevel::High,
            fees: DelegationFees {
                percentage: 5.0,
                fixed_amount: 0,
                performance_bonus: Some(2.0),
            },
        };

        let delegation_id = manager
            .create_delegation(
                delegator_id.clone(),
                delegate_id.clone(),
                DelegationType::Complete,
                10000,
                metadata,
            )
            .await
            .unwrap();

        assert!(delegation_id > 0);

        // Verificar poder de voto
        let power = manager
            .get_effective_voting_power(&delegate_id, &ProposalCategory::Technical)
            .await
            .unwrap();

        assert_eq!(power, 10000);
    }

    #[tokio::test]
    async fn test_category_specific_delegation() {
        let config = DelegationConfig {
            max_delegation_depth: 3,
            min_delegation_amount: 1000,
            max_fee_percentage: 10.0,
            delegation_cooldown: 0, // Sin cooldown para test
            auto_expiry_enabled: true,
            verification_required: false,
        };

        let (manager, _temp_dir) = manager_with_temp_storage(config);

        // Registrar delegado técnico
        let delegate_id = NodeId::from("tech_delegate");
        let profile = DelegateProfile {
            node_id: delegate_id.clone(),
            name: Some("Tech Expert".to_string()),
            description: None,
            expertise_areas: [ProposalCategory::Technical].iter().cloned().collect(),
            voting_history: VotingPerformance {
                total_votes: 0,
                participation_rate: 0.0,
                alignment_score: 0.0,
                response_time_avg: 0.0,
                last_activity: 0,
                votes_by_category: HashMap::new(),
            },
            reputation_score: 90.0,
            total_delegated_power: 0,
            delegation_count: 0,
            fee_structure: DelegationFees {
                percentage: 3.0,
                fixed_amount: 0,
                performance_bonus: None,
            },
            is_accepting_delegations: true,
            max_delegations: None,
            verification_status: VerificationStatus::Verified,
        };

        manager
            .register_delegate(delegate_id.clone(), profile)
            .await
            .unwrap();

        // Crear delegación solo para propuestas técnicas
        let delegator_id = NodeId::from("delegator1");
        let metadata = DelegationMetadata {
            reason: Some("Technical expertise".to_string()),
            reputation_weight: 1.0,
            performance_score: None,
            trust_level: TrustLevel::High,
            fees: DelegationFees {
                percentage: 3.0,
                fixed_amount: 0,
                performance_bonus: None,
            },
        };

        let categories = [ProposalCategory::Technical].iter().cloned().collect();
        let delegation_type = DelegationType::Category { categories };

        manager
            .create_delegation(
                delegator_id,
                delegate_id.clone(),
                delegation_type,
                5000,
                metadata,
            )
            .await
            .unwrap();

        // Verificar poder para categoría técnica
        let tech_power = manager
            .get_effective_voting_power(&delegate_id, &ProposalCategory::Technical)
            .await
            .unwrap();
        assert_eq!(tech_power, 5000);

        // Verificar poder para categoría económica (debería ser 0)
        let econ_power = manager
            .get_effective_voting_power(&delegate_id, &ProposalCategory::Economic)
            .await
            .unwrap();
        assert_eq!(econ_power, 0);
    }
}
