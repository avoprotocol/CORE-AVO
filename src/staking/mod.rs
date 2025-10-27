//! # Sistema de Staking Avanzado para AVO Protocol
//!
//! Gestión completa de staking con soporte para:
//! - Bootstrap nodes (10K AVO, 15% APR)
//! - Validadores (1K AVO, 12% APR)
//! - Delegadores (gratis, 8% APR)
//! - Unstaking automático con recompensas
//! - Estadísticas detalladas
//! - Sistema de reputación (1-5 estrellas)

pub mod delegation_manager;
pub mod reputation;
pub mod reputation_db;
pub mod rewards_calculator;
pub mod stake_manager;

pub use delegation_manager::*;
pub use reputation::*;
pub use rewards_calculator::*;
pub use stake_manager::*;

use crate::error::*;
use crate::types::*;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Estadísticas completas de un stake para frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeStats {
    pub pending_rewards: f64,          // Recompensas pendientes actuales
    pub time_staked_seconds: u64,      // Tiempo total en stake (segundos)
    pub time_staked_days: f64,         // Tiempo total en stake (días)
    pub estimated_annual_rewards: f64, // Recompensas estimadas anuales
    pub current_apr: f64,              // APR actual
    pub next_reward_in_seconds: u64,   // Tiempo hasta próxima época
    pub total_earned: f64,             // Total ganado (acumulado + pendiente)
}
use std::collections::HashMap;

const SECONDS_PER_YEAR: u128 = 31_557_600; // 365.25 días
const APR_PRECISION: u128 = 1_000_000_000; // 1e9 para precisión sub porcentual

/// Tipos de stake en AVO Protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeType {
    Bootstrap,
    Validator,
    Delegation,
}

/// Registro persistente de un validador en el protocolo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub id: u32,
    pub owner: String,
    pub stake_wei: StakeAmount,
    pub is_active: bool,
    pub registered_at: u64,
    #[serde(default)]
    pub last_updated_at: u64,
}

impl ValidatorRecord {
    pub fn new(id: u32, owner: String, stake_wei: StakeAmount) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id,
            owner,
            stake_wei,
            is_active: true,
            registered_at: now,
            last_updated_at: now,
        }
    }

    pub fn update_stake(&mut self, stake_wei: StakeAmount) {
        self.stake_wei = stake_wei;
        self.last_updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn mark_inactive(&mut self) {
        self.is_active = false;
        self.update_stake(0);
    }
}

impl StakeType {
    /// Obtener stake mínimo requerido
    pub fn min_stake(&self, params: &ProtocolParams) -> u64 {
        match self {
            StakeType::Bootstrap => params.min_bootstrap_stake.try_into().unwrap_or(u64::MAX),
            StakeType::Validator => params.min_validator_stake.try_into().unwrap_or(u64::MAX),
            StakeType::Delegation => params.min_delegation_amount.try_into().unwrap_or(0),
        }
    }

    /// Obtener APR correspondiente
    pub fn apr(&self, params: &ProtocolParams) -> f64 {
        match self {
            StakeType::Bootstrap => params.bootstrap_apr,
            StakeType::Validator => params.validator_apr,
            StakeType::Delegation => params.delegator_apr,
        }
    }

    /// Obtener descripción del rol
    pub fn description(&self) -> &'static str {
        match self {
            StakeType::Bootstrap => "Bootstrap Node - Infraestructura crítica de red",
            StakeType::Validator => "Validator - Validación de bloques y transacciones",
            StakeType::Delegation => "Delegator - Participación sin responsabilidad técnica",
        }
    }
}

/// Estado de un stake activo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakePosition {
    pub id: String,
    pub owner: String,
    pub stake_type: StakeType,
    /// Monto principal en wei (unidad mínima). Campo mantenido con nombre `amount` para compatibilidad.
    pub amount: u128,
    pub start_time: u64,
    /// Último timestamp (secs) en que se actualizó (acumuló) recompensas
    #[serde(alias = "last_reward_claim")]
    pub last_reward_update: u64,
    /// Recompensas acumuladas en wei (solo contabilizadas, aún no retiradas). Acepta legacy f64 durante deserialización.
    #[serde(deserialize_with = "deserialize_rewards_legacy")]
    pub accumulated_rewards: u128,
    pub validator_id: Option<u32>, // Para delegaciones
    pub is_active: bool,
    pub unstake_requested: Option<u64>, // Timestamp de solicitud de unstake
    /// Flag definitivo para impedir doble unstake
    pub unstaked_finalized: bool,
}

impl StakePosition {
    /// Crear nueva posición de stake
    pub fn new(
        owner: String,
        stake_type: StakeType,
        amount_wei: u128, // Aceptar wei directamente
        validator_id: Option<u32>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id: format!(
                "{}_{}_{}",
                stake_type.description().chars().next().unwrap(),
                owner,
                now
            ),
            owner,
            stake_type,
            amount: amount_wei,
            start_time: now,
            last_reward_update: now,
            accumulated_rewards: 0u128,
            validator_id,
            is_active: true,
            unstake_requested: None,
            unstaked_finalized: false,
        }
    }

    /// Calcular recompensas pendientes con matemática entera para mantener el APR correcto
    pub fn calculate_pending_rewards_wei(&self, params: &ProtocolParams) -> u128 {
        if !self.is_active {
            tracing::info!("[REWARD_DEBUG] Position not active, returning 0");
            return 0;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now <= self.last_reward_update {
            tracing::info!(
                "[REWARD_DEBUG] No time elapsed since last update: now={}, last_reward_update={}",
                now,
                self.last_reward_update
            );
            return 0;
        }

        let elapsed = now - self.last_reward_update;
        let apr_fraction = self.stake_type.apr(params);
        if apr_fraction <= 0.0 {
            tracing::info!("[REWARD_DEBUG] APR is zero, returning 0");
            return 0;
        }

        let apr_scaled = (apr_fraction * APR_PRECISION as f64).round() as u128;

        // Fórmula: reward = amount * apr * elapsed / seconds_per_year
        // Usamos matemática de enteros: amount * apr_scaled * elapsed / (APR_PRECISION * SECONDS_PER_YEAR)
        let elapsed_u128 = elapsed as u128;
        let numerator = self
            .amount
            .saturating_mul(apr_scaled)
            .saturating_mul(elapsed_u128);
        let denominator = APR_PRECISION.saturating_mul(SECONDS_PER_YEAR);

        let pending_rewards = numerator / denominator;

        tracing::info!(
            "[REWARD_DEBUG] amount={}, apr_fraction={}, apr_scaled={}, elapsed={}, pending_rewards={}",
            self.amount,
            apr_fraction,
            apr_scaled,
            elapsed,
            pending_rewards
        );

        pending_rewards
    }

    /// Obtener estadísticas completas del stake para frontend
    pub fn get_stake_stats(&self, params: &ProtocolParams) -> StakeStats {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time_staked = now - self.start_time;
        let pending_rewards_wei = self.calculate_pending_rewards_wei(params);
        let apr = self.stake_type.apr(params);
        let estimated_annual_rewards = (self.amount as f64 / 1e18f64) * apr;
        let accumulated_avo = self.accumulated_rewards as f64 / 1e18f64;
        let pending_avo = pending_rewards_wei as f64 / 1e18f64;
        StakeStats {
            pending_rewards: pending_avo,
            time_staked_seconds: time_staked,
            time_staked_days: time_staked as f64 / (24.0 * 3600.0),
            estimated_annual_rewards,
            current_apr: apr,
            next_reward_in_seconds: 30, // Basado en épocas de 30 segundos
            total_earned: accumulated_avo + pending_avo,
        }
    }

    /// Acumula recompensas pendientes, retorna el incremento (wei)
    pub fn accrue_rewards(&mut self, params: &ProtocolParams) -> u128 {
        let pending = self.calculate_pending_rewards_wei(params);
        if pending > 0 {
            self.accumulated_rewards = self.accumulated_rewards.saturating_add(pending);
            self.last_reward_update = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
        pending
    }

    /// Solicitar unstake
    pub fn request_unstake(&mut self) -> AvoResult<()> {
        if self.unstake_requested.is_some() {
            return Err(AvoError::staking("Unstake already requested".to_string()));
        }

        self.unstake_requested = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        Ok(())
    }

    /// Verificar si puede hacer unstake inmediatamente
    pub fn can_unstake_now(&self) -> bool {
        // En AVO, el unstake es inmediato para democratización
        true
    }

    /// Ejecutar unstake y obtener total a devolver
    pub fn execute_unstake(&mut self, params: &ProtocolParams) -> AvoResult<u128> {
        if !self.can_unstake_now() {
            return Err(AvoError::staking("Cannot unstake yet".to_string()));
        }
        if self.unstaked_finalized {
            return Err(AvoError::staking("Position already unstaked".to_string()));
        }

        // Debug logging antes del cálculo
        tracing::warn!(
            "[UNSTAKE_DEBUG] Before accrue_rewards: accumulated_rewards={}, amount={}",
            self.accumulated_rewards,
            self.amount
        );

        // Acumular recompensas pendientes
        let pending_rewards = self.accrue_rewards(params);

        // Debug logging después del cálculo
        tracing::warn!(
            "[UNSTAKE_DEBUG] After accrue_rewards: pending_rewards={}, accumulated_rewards={}",
            pending_rewards,
            self.accumulated_rewards
        );

        let total = self.amount.saturating_add(self.accumulated_rewards);

        tracing::warn!(
            "[UNSTAKE_DEBUG] Total returned: amount={} + accumulated_rewards={} = {}",
            self.amount,
            self.accumulated_rewards,
            total
        );

        self.is_active = false;
        self.unstaked_finalized = true;
        Ok(total)
    }

    /// Obtener tiempo restante para unstake (si aplica)
    pub fn unstake_cooldown_remaining(&self) -> Option<Duration> {
        // En AVO no hay cooldown, unstake inmediato
        None
    }
}

/// Estadísticas globales del sistema de staking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StakingStats {
    pub total_bootstrap_nodes: u32,
    pub total_validators: u32,
    pub total_delegators: u32,
    pub total_staked_bootstrap: u64,
    pub total_staked_validators: u64,
    pub total_delegated: u64,
    pub total_rewards_distributed: u128, // en wei
    pub average_bootstrap_apr: f64,
    pub average_validator_apr: f64,
    pub average_delegator_apr: f64,
    pub network_stake_ratio: f64, // % del supply total stakeado
}

impl StakingStats {
    /// Calcular estadísticas totales
    pub fn calculate_totals(&mut self) {
        self.network_stake_ratio = (self.total_staked_bootstrap
            + self.total_staked_validators
            + self.total_delegated) as f64
            / 1_000_000_000.0; // Asumiendo 1B AVO supply
    }

    /// Obtener stake total del protocolo
    pub fn total_protocol_stake(&self) -> u64 {
        self.total_staked_bootstrap + self.total_staked_validators + self.total_delegated
    }

    /// Obtener número total de participantes
    pub fn total_participants(&self) -> u32 {
        self.total_bootstrap_nodes + self.total_validators + self.total_delegators
    }
}

/// Eventos del sistema de staking para auditoría
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StakingEvent {
    StakeCreated {
        position_id: String,
        owner: String,
        stake_type: StakeType,
        amount_wei: u128,
        timestamp: u64,
    },
    RewardsClaimed {
        position_id: String,
        owner: String,
        amount_wei: u128,
        timestamp: u64,
    },
    UnstakeRequested {
        position_id: String,
        owner: String,
        timestamp: u64,
    },
    UnstakeExecuted {
        position_id: String,
        owner: String,
        total_returned_wei: u128,
        timestamp: u64,
    },
}

impl StakingEvent {
    /// Crear evento con timestamp actual
    pub fn with_timestamp(self) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        match self {
            StakingEvent::StakeCreated {
                position_id,
                owner,
                stake_type,
                amount_wei,
                ..
            } => StakingEvent::StakeCreated {
                position_id,
                owner,
                stake_type,
                amount_wei,
                timestamp: now,
            },
            StakingEvent::RewardsClaimed {
                position_id,
                owner,
                amount_wei,
                ..
            } => StakingEvent::RewardsClaimed {
                position_id,
                owner,
                amount_wei,
                timestamp: now,
            },
            StakingEvent::UnstakeRequested {
                position_id, owner, ..
            } => StakingEvent::UnstakeRequested {
                position_id,
                owner,
                timestamp: now,
            },
            StakingEvent::UnstakeExecuted {
                position_id,
                owner,
                total_returned_wei,
                ..
            } => StakingEvent::UnstakeExecuted {
                position_id,
                owner,
                total_returned_wei,
                timestamp: now,
            },
        }
    }
}

/// Deserializador que acepta tanto un u128 (wei moderno) como un f64/u64 legacy en AVO y lo convierte a wei.
fn deserialize_rewards_legacy<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    // Intentar múltiples formatos
    let val = serde_json::Value::deserialize(deserializer)?;
    match val {
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                // Podría ser legacy AVO (pequeño) o ya wei si es muy grande.
                // Heurística: si u < 1e12 asumimos AVO legacy -> escalar.
                if u < 1_000_000_000_000 {
                    Ok((u as u128) * 10u128.pow(18))
                } else {
                    Ok(u as u128)
                }
            } else if let Some(f) = n.as_f64() {
                Ok(((f.max(0.0)) * 1e18f64) as u128)
            } else {
                Err(de::Error::custom("Unsupported numeric rewards format"))
            }
        }
        serde_json::Value::String(s) => {
            if let Ok(parsed) = s.parse::<u128>() {
                return Ok(parsed);
            }
            if let Ok(f) = s.parse::<f64>() {
                return Ok(((f.max(0.0)) * 1e18f64) as u128);
            }
            Err(de::Error::custom("Cannot parse rewards string"))
        }
        serde_json::Value::Null => Ok(0),
        _ => Err(de::Error::custom("Invalid rewards value type")),
    }
}
