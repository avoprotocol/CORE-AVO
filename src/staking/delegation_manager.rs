//! # Gestor de Delegaciones para AVO Protocol
//!
//! Maneja delegaciones de usuarios a validadores

use super::*;
use crate::error::*;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Información de un validador para delegación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorDelegationInfo {
    pub validator_id: u32,
    pub total_delegated: u64,
    pub delegator_count: u32,
    pub commission_rate: f64, // % que se queda el validador
    pub is_accepting_delegations: bool,
}

/// Gestor de delegaciones
#[derive(Debug, Clone)]
pub struct DelegationManager {
    validators: HashMap<u32, ValidatorDelegationInfo>,
    delegations: HashMap<String, Vec<String>>, // validator_id -> position_ids
}

impl DelegationManager {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            delegations: HashMap::new(),
        }
    }

    /// Registrar validador para delegaciones
    pub fn register_validator(&mut self, validator_id: u32, commission_rate: f64) {
        let info = ValidatorDelegationInfo {
            validator_id,
            total_delegated: 0,
            delegator_count: 0,
            commission_rate,
            is_accepting_delegations: true,
        };
        self.validators.insert(validator_id, info);
    }

    /// Obtener validadores disponibles para delegación
    pub fn get_available_validators(&self) -> Vec<&ValidatorDelegationInfo> {
        self.validators
            .values()
            .filter(|v| v.is_accepting_delegations)
            .collect()
    }

    /// Registrar nueva delegación
    pub fn add_delegation(
        &mut self,
        validator_id: u32,
        position_id: String,
        amount: u64,
    ) -> AvoResult<()> {
        let validator = self
            .validators
            .get_mut(&validator_id)
            .ok_or_else(|| AvoError::staking("Validator not found".to_string()))?;

        if !validator.is_accepting_delegations {
            return Err(AvoError::staking(
                "Validator not accepting delegations".to_string(),
            ));
        }

        validator.total_delegated += amount;
        validator.delegator_count += 1;

        self.delegations
            .entry(validator_id.to_string())
            .or_insert_with(Vec::new)
            .push(position_id);

        Ok(())
    }
}
