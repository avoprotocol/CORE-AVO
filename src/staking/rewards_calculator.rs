//! # Calculadora de Recompensas para AVO Protocol
//!
//! Funciones utilitarias para cálculo de recompensas de staking, usando matemática de enteros.

use super::*;
use super::{APR_PRECISION, SECONDS_PER_YEAR};
use crate::types::*;
use tracing::warn;

/// Calculadora de recompensas de staking
pub struct RewardsCalculator {
    params: ProtocolParams,
}

impl RewardsCalculator {
    pub fn new(params: ProtocolParams) -> Self {
        Self { params }
    }

    /// Calcular recompensas por tiempo transcurrido usando matemática de enteros.
    ///
    /// # Arguments
    /// * `stake_amount` - La cantidad de stake en la unidad más pequeña (e.g., wei).
    /// * `stake_type` - El tipo de stake que determina el APR.
    /// * `duration_seconds` - La duración del stake en segundos.
    ///
    /// # Returns
    /// La cantidad de recompensa calculada, en la unidad más pequeña.
    pub fn calculate_time_based_rewards(
        &self,
        stake_amount: StakeAmount, // Usar el tipo correcto u128
        stake_type: StakeType,
        duration_seconds: u64,
    ) -> StakeAmount {
        // Devolver el tipo correcto u128
        // Convertir el APR de f64 a u128 con la precisión definida.
        // Ejemplo: 0.12 (12%) se convierte en 0.12 * 10^9.
        let apr_fraction = stake_type.apr(&self.params);
        if apr_fraction <= 0.0 {
            tracing::info!("[REWARDS_CALC] Zero APR for {:?}, returning 0", stake_type);
            return 0;
        }

        let apr_scaled = (apr_fraction * APR_PRECISION as f64).round() as u128;
        let duration_u128 = duration_seconds as u128;

        let numerator = stake_amount
            .saturating_mul(apr_scaled)
            .saturating_mul(duration_u128);
        let denominator = APR_PRECISION.saturating_mul(SECONDS_PER_YEAR);

        let reward = numerator / denominator;

        tracing::info!(
            "[REWARDS_CALC] stake={}, apr_fraction={}, apr_scaled={}, duration={}s, reward={}",
            stake_amount,
            apr_fraction,
            apr_scaled,
            duration_seconds,
            reward
        );

        reward
    }

    /// Calcular recompensas compuestas usando matemática de enteros.
    /// La implementación actual con floats es incorrecta para un entorno de blockchain.
    /// Se deshabilita hasta que se implemente de forma segura con matemática de punto fijo.
    pub fn calculate_compound_rewards(
        &self,
        _initial_stake: StakeAmount,
        _stake_type: StakeType,
        _compound_periods: u32,
    ) -> StakeAmount {
        // TODO: Implementar cálculo de interés compuesto con matemática de enteros.
        // La implementación actual con f64 es insegura y ha sido deshabilitada.
        // Se necesita una librería de punto fijo o una implementación de `pow` para u128.
        warn!("Cálculo de recompensas compuestas no está implementado de forma segura.");
        0
    }
}
