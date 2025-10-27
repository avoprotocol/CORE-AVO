//! # Gestor Principal de Staking para AVO Protocol
//!
//! Maneja todas las operaciones de staking incluyendo:
//! - Creación y gestión de stakes
//! - Cálculo y distribución de recompensas
//! - Operaciones de unstaking
//! - Estadísticas y métricas

use super::*;
use crate::error::*;
use crate::state::ChainState;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

/// Gestor principal del sistema de staking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeManager {
    /// Posiciones de stake activas
    positions: HashMap<String, StakePosition>,
    /// Historiales de eventos
    events: Vec<StakingEvent>,
    /// Estadísticas globales
    stats: StakingStats,
    /// Parámetros del protocolo
    params: ProtocolParams,
    /// Ruta al archivo de estado del blockchain
    chain_state_path: PathBuf,
    /// Registro de validadores activos/pasados
    validator_registry: HashMap<u32, ValidatorRecord>,
    /// Contador incremental para asignar nuevos IDs de validadores
    next_validator_id: u32,
}

impl StakeManager {
    /// Crear nuevo gestor de staking con persistencia
    pub fn new(params: ProtocolParams, chain_state_path: PathBuf) -> Self {
        let mut manager = Self {
            positions: HashMap::new(),
            events: Vec::new(),
            stats: StakingStats::default(),
            params,
            chain_state_path: chain_state_path.clone(),
            validator_registry: HashMap::new(),
            next_validator_id: 1,
        };

        // Cargar stakes existentes desde el estado persistente
        if let Ok(chain_state) = ChainState::load_or_create(&chain_state_path) {
            manager.positions = chain_state.stake_positions;
            manager.validator_registry = chain_state.validators;

            if let Some(max_id) = manager.validator_registry.keys().copied().max() {
                manager.next_validator_id = max_id.saturating_add(1);
            }

            // Asegurar que las posiciones de validadores tengan su ID asociado
            let mut updated_positions: Vec<StakePosition> = Vec::new();
            for position in manager.positions.values_mut() {
                if position.stake_type == StakeType::Validator && position.validator_id.is_none() {
                    if let Some(record) = manager
                        .validator_registry
                        .values()
                        .find(|record| record.owner == position.owner)
                    {
                        position.validator_id = Some(record.id);
                        updated_positions.push(position.clone());
                    }
                }
            }

            for position in updated_positions.iter() {
                if let Err(err) = manager.persist_stake_position(position) {
                    warn!(
                        "Failed to backfill validator ID for position {}: {}",
                        position.id, err
                    );
                }
            }

            debug!(
                "Loaded {} existing stake positions",
                manager.positions.len()
            );
        }

        manager
    }

    /// Persistir una posición de stake
    fn persist_stake_position(&self, position: &StakePosition) -> AvoResult<()> {
        ChainState::add_stake_position(&self.chain_state_path, position.clone())
    }

    /// Persistir o actualizar un registro de validador
    fn persist_validator(&self, record: &ValidatorRecord) -> AvoResult<()> {
        ChainState::upsert_validator(&self.chain_state_path, record.clone())
    }

    /// Remover una posición de stake del almacenamiento persistente
    fn remove_persisted_stake(&self, position_id: &str) -> AvoResult<()> {
        ChainState::remove_stake_position(&self.chain_state_path, position_id)
    }

    /// Buscar validador por dirección del propietario
    fn find_validator_by_owner(&self, owner: &str) -> Option<&ValidatorRecord> {
        self.validator_registry
            .values()
            .find(|record| record.owner == owner)
    }

    /// Obtener un nuevo ID de validador (o reutilizar uno existente para el mismo owner)
    fn allocate_validator_id(&mut self, owner: &str) -> u32 {
        if let Some(record) = self.find_validator_by_owner(owner) {
            record.id
        } else {
            let id = self.next_validator_id.max(1);
            self.next_validator_id = self.next_validator_id.saturating_add(1);
            id
        }
    }

    /// Asegurarse de que el validador exista y esté activo
    fn ensure_validator_active(&self, validator_id: u32) -> AvoResult<()> {
        match self.validator_registry.get(&validator_id) {
            Some(record) if record.is_active => Ok(()),
            Some(_) => Err(AvoError::staking(format!(
                "Validator {} is not active",
                validator_id
            ))),
            None => Err(AvoError::staking(format!(
                "Validator {} not found",
                validator_id
            ))),
        }
    }

    /// Desactivar un validador cuando retira su stake
    fn deactivate_validator(&mut self, validator_id: u32) -> AvoResult<()> {
        match self
            .validator_registry
            .get_mut(&validator_id)
            .map(|record| {
                record.mark_inactive();
                record.clone()
            }) {
            Some(record_clone) => self.persist_validator(&record_clone),
            None => Err(AvoError::staking(format!(
                "Validator {} not found",
                validator_id
            ))),
        }
    }

    /// Crear stake de bootstrap node
    pub fn create_bootstrap_stake(
        &mut self,
        owner: String,
        amount_wei: StakeAmount, // Aceptar u128 directamente
    ) -> AvoResult<StakePosition> {
        // Verificar stake mínimo
        if amount_wei < self.params.min_bootstrap_stake {
            return Err(AvoError::staking(format!(
                "Bootstrap stake {} below minimum {}",
                amount_wei, self.params.min_bootstrap_stake
            )));
        }

        let position = StakePosition::new(owner.clone(), StakeType::Bootstrap, amount_wei, None);

        // Registrar evento
        let event = StakingEvent::StakeCreated {
            position_id: position.id.clone(),
            owner: owner.clone(),
            stake_type: StakeType::Bootstrap,
            amount_wei,
            timestamp: 0, // Se actualizará con with_timestamp()
        }
        .with_timestamp();

        self.events.push(event);
        self.positions.insert(position.id.clone(), position.clone());

        // Persistir el stake en el estado del blockchain
        self.persist_stake_position(&position)?;

        // Actualizar estadísticas (convertir a u64 AVO para stats legacy)
        self.stats.total_bootstrap_nodes += 1;
        self.stats.total_staked_bootstrap += (amount_wei / 10u128.pow(18)) as u64;
        self.stats.calculate_totals();

        info!(
            "🚀 Bootstrap stake creado: {} wei por {}",
            amount_wei, owner
        );
        Ok(position)
    }

    /// Crear stake de validador
    pub fn create_validator_stake(
        &mut self,
        owner: String,
        amount_wei: StakeAmount, // Aceptar u128 directamente
    ) -> AvoResult<StakePosition> {
        // Verificar stake mínimo
        if amount_wei < self.params.min_validator_stake {
            return Err(AvoError::staking(format!(
                "Validator stake {} below minimum {}",
                amount_wei, self.params.min_validator_stake
            )));
        }

        let validator_id = self.allocate_validator_id(&owner);
        let position = StakePosition::new(
            owner.clone(),
            StakeType::Validator,
            amount_wei,
            Some(validator_id),
        );

        // Registrar evento
        let event = StakingEvent::StakeCreated {
            position_id: position.id.clone(),
            owner: owner.clone(),
            stake_type: StakeType::Validator,
            amount_wei,
            timestamp: 0,
        }
        .with_timestamp();

        self.events.push(event);
        self.positions.insert(position.id.clone(), position.clone());

        // Registrar/actualizar información del validador
        let mut validator_record = self
            .validator_registry
            .get(&validator_id)
            .cloned()
            .unwrap_or_else(|| ValidatorRecord::new(validator_id, owner.clone(), amount_wei));

        validator_record.owner = owner.clone();
        validator_record.is_active = true;
        validator_record.update_stake(amount_wei);

        self.validator_registry
            .insert(validator_id, validator_record.clone());

        // Persistir el stake en el estado del blockchain
        self.persist_stake_position(&position)?;
        self.persist_validator(&validator_record)?;

        // Actualizar estadísticas (convertir a u64 AVO para stats legacy)
        self.stats.total_validators += 1;
        self.stats.total_staked_validators += (amount_wei / 10u128.pow(18)) as u64;
        self.stats.calculate_totals();

        info!(
            "⚡ Validator stake creado: {} wei por {} (validator_id={})",
            amount_wei, owner, validator_id
        );
        Ok(position)
    }

    /// Crear delegación
    pub fn create_delegation(
        &mut self,
        owner: String,
        amount_wei: StakeAmount, // Aceptar u128 directamente
        validator_id: u32,
    ) -> AvoResult<StakePosition> {
        // En AVO, la delegación es gratuita (sin mínimo)
        if amount_wei == 0 {
            return Err(AvoError::staking(
                "Delegation amount cannot be zero".to_string(),
            ));
        }

        self.ensure_validator_active(validator_id)?;

        let position = StakePosition::new(
            owner.clone(),
            StakeType::Delegation,
            amount_wei,
            Some(validator_id),
        );

        // Registrar evento
        let event = StakingEvent::StakeCreated {
            position_id: position.id.clone(),
            owner: owner.clone(),
            stake_type: StakeType::Delegation,
            amount_wei,
            timestamp: 0,
        }
        .with_timestamp();

        self.events.push(event);
        self.positions.insert(position.id.clone(), position.clone());

        // Actualizar estadísticas (convertir a u64 AVO para stats legacy)
        self.stats.total_delegators += 1;
        self.stats.total_delegated += (amount_wei / 10u128.pow(18)) as u64;
        self.stats.calculate_totals();

        info!(
            "🤝 Delegación creada: {} wei por {} al validator {}",
            amount_wei, owner, validator_id
        );
        Ok(position)
    }

    /// Obtener posición de stake por ID
    pub fn get_position(&self, position_id: &str) -> Option<&StakePosition> {
        self.positions.get(position_id)
    }

    /// Obtener información de un validador registrado
    pub fn get_validator(&self, validator_id: u32) -> Option<&ValidatorRecord> {
        self.validator_registry.get(&validator_id)
    }

    /// Obtener todos los registros de validadores
    pub fn get_all_validators(&self) -> &HashMap<u32, ValidatorRecord> {
        &self.validator_registry
    }

    /// Obtener todas las posiciones de un usuario
    pub fn get_user_positions(&self, owner: &str) -> Vec<&StakePosition> {
        self.positions
            .values()
            .filter(|pos| pos.owner == owner && pos.is_active)
            .collect()
    }

    /// Reclamar recompensas de una posición
    pub fn claim_rewards(&mut self, position_id: &str) -> AvoResult<u128> {
        let position = self
            .positions
            .get_mut(position_id)
            .ok_or_else(|| AvoError::staking("Position not found".to_string()))?;

        if !position.is_active {
            return Err(AvoError::staking("Position is not active".to_string()));
        }
        let delta = position.accrue_rewards(&self.params);
        if delta > 0 {
            let event = StakingEvent::RewardsClaimed {
                position_id: position_id.to_string(),
                owner: position.owner.clone(),
                amount_wei: delta,
                timestamp: 0,
            }
            .with_timestamp();
            self.events.push(event);
            self.stats.total_rewards_distributed =
                self.stats.total_rewards_distributed.saturating_add(delta);
            info!(
                "💰 Recompensas reclamadas (accrual) {} wei por {}",
                delta, position.owner
            );
        }
        Ok(delta)
    }

    /// Reclamar todas las recompensas de un usuario
    pub fn claim_all_user_rewards(&mut self, owner: &str) -> AvoResult<u128> {
        let position_ids: Vec<String> = self
            .positions
            .values()
            .filter(|pos| pos.owner == owner && pos.is_active)
            .map(|pos| pos.id.clone())
            .collect();

        let mut total_rewards: u128 = 0;
        for position_id in position_ids {
            total_rewards += self.claim_rewards(&position_id)?;
        }

        Ok(total_rewards)
    }

    /// Solicitar unstake de una posición
    pub fn request_unstake(&mut self, position_id: &str) -> AvoResult<()> {
        // Hacer las modificaciones y obtener la información necesaria
        let (owner, position_clone) = {
            let position = self
                .positions
                .get_mut(position_id)
                .ok_or_else(|| AvoError::staking("Position not found".to_string()))?;

            position.request_unstake()?;
            (position.owner.clone(), position.clone())
        };

        // Ahora persistir el cambio de estado
        self.persist_stake_position(&position_clone)?;

        // Registrar evento
        let event = StakingEvent::UnstakeRequested {
            position_id: position_id.to_string(),
            owner,
            timestamp: 0,
        }
        .with_timestamp();

        self.events.push(event);

        info!("📤 Unstake solicitado para posición: {}", position_id);
        Ok(())
    }

    /// Ejecutar unstake y devolver fondos
    pub fn execute_unstake(&mut self, position_id: &str) -> AvoResult<u128> {
        // Hacer las modificaciones y obtener la información necesaria
        let (total_returned_wei, owner, stake_type, principal_wei, validator_id_opt) = {
            let position = self
                .positions
                .get_mut(position_id)
                .ok_or_else(|| AvoError::staking("Position not found".to_string()))?;

            let total_returned = position.execute_unstake(&self.params)?;
            (
                total_returned,
                position.owner.clone(),
                position.stake_type.clone(),
                position.amount,
                position.validator_id,
            )
        };

        // Actualizar estadísticas (usando saturating_sub para evitar overflow)
        match stake_type {
            StakeType::Bootstrap => {
                self.stats.total_bootstrap_nodes =
                    self.stats.total_bootstrap_nodes.saturating_sub(1);
                // Convert legacy stat (u64 AVO) by subtracting principal in AVO if still tracked
                let principal_avo = (principal_wei / 10u128.pow(18)) as u64;
                self.stats.total_staked_bootstrap = self
                    .stats
                    .total_staked_bootstrap
                    .saturating_sub(principal_avo);
            }
            StakeType::Validator => {
                self.stats.total_validators = self.stats.total_validators.saturating_sub(1);
                let principal_avo = (principal_wei / 10u128.pow(18)) as u64;
                self.stats.total_staked_validators = self
                    .stats
                    .total_staked_validators
                    .saturating_sub(principal_avo);
                if let Some(validator_id) = validator_id_opt {
                    self.deactivate_validator(validator_id)?;
                }
            }
            StakeType::Delegation => {
                self.stats.total_delegators = self.stats.total_delegators.saturating_sub(1);
                let principal_avo = (principal_wei / 10u128.pow(18)) as u64;
                self.stats.total_delegated =
                    self.stats.total_delegated.saturating_sub(principal_avo);
            }
        }
        self.stats.calculate_totals();

        // Registrar evento
        let event = StakingEvent::UnstakeExecuted {
            position_id: position_id.to_string(),
            owner: owner.clone(),
            total_returned_wei,
            timestamp: 0,
        }
        .with_timestamp();

        self.events.push(event);

        // Remover la posición del almacenamiento persistente
        self.remove_persisted_stake(position_id)?;

        // 🔒 CRITICAL FIX: Remover la posición del HashMap en memoria
        self.positions.remove(position_id);

        info!(
            "✅ Unstake ejecutado: {} wei devueltos a {} | Posición eliminada: {}",
            total_returned_wei, owner, position_id
        );
        Ok(total_returned_wei)
    }

    /// Obtener estadísticas de staking para un usuario
    pub fn get_user_stats(&self, owner: &str) -> UserStakingStats {
        let user_positions: Vec<&StakePosition> = self.get_user_positions(owner);

        let mut stats = UserStakingStats {
            owner: owner.to_string(),
            total_positions: user_positions.len() as u32,
            bootstrap_positions: 0,
            validator_positions: 0,
            delegation_positions: 0,
            total_staked: 0,
            total_pending_rewards: 0.0,
            total_claimed_rewards: 0,
            estimated_annual_rewards: 0.0,
        };

        for position in user_positions {
            let amount_avo = position.amount as f64 / 1e18f64;
            stats.total_staked += amount_avo as u64; // pierde decimales en esta métrica resumida
            let pending_avo = position.calculate_pending_rewards_wei(&self.params) as f64 / 1e18f64;
            stats.total_pending_rewards += pending_avo;
            stats.total_claimed_rewards += (position.accumulated_rewards / 10u128.pow(18)) as u64;
            let apr = position.stake_type.apr(&self.params);
            stats.estimated_annual_rewards += amount_avo * apr;

            match position.stake_type {
                StakeType::Bootstrap => stats.bootstrap_positions += 1,
                StakeType::Validator => stats.validator_positions += 1,
                StakeType::Delegation => stats.delegation_positions += 1,
            }
        }

        stats
    }

    /// Obtener estadísticas globales
    pub fn get_global_stats(&self) -> &StakingStats {
        &self.stats
    }

    /// Obtener historial de eventos de un usuario
    pub fn get_user_events(&self, owner: &str) -> Vec<&StakingEvent> {
        self.events
            .iter()
            .filter(|event| match event {
                StakingEvent::StakeCreated {
                    owner: event_owner, ..
                } => event_owner == owner,
                StakingEvent::RewardsClaimed {
                    owner: event_owner, ..
                } => event_owner == owner,
                StakingEvent::UnstakeRequested {
                    owner: event_owner, ..
                } => event_owner == owner,
                StakingEvent::UnstakeExecuted {
                    owner: event_owner, ..
                } => event_owner == owner,
            })
            .collect()
    }

    /// Obtener todas las posiciones de stake
    pub fn get_all_positions(&self) -> &HashMap<String, StakePosition> {
        &self.positions
    }

    /// Obtener ranking de usuarios por stake total
    pub fn get_staking_leaderboard(&self, limit: usize) -> Vec<UserStakingStats> {
        let mut user_stats: HashMap<String, UserStakingStats> = HashMap::new();

        // Calcular stats para todos los usuarios
        for position in self.positions.values() {
            if position.is_active {
                let stats =
                    user_stats
                        .entry(position.owner.clone())
                        .or_insert_with(|| UserStakingStats {
                            owner: position.owner.clone(),
                            total_positions: 0,
                            bootstrap_positions: 0,
                            validator_positions: 0,
                            delegation_positions: 0,
                            total_staked: 0,
                            total_pending_rewards: 0.0,
                            total_claimed_rewards: 0,
                            estimated_annual_rewards: 0.0,
                        });

                stats.total_positions += 1;
                let amount_avo = position.amount as f64 / 1e18f64;
                stats.total_staked += amount_avo as u64;
                let pending_avo =
                    position.calculate_pending_rewards_wei(&self.params) as f64 / 1e18f64;
                stats.total_pending_rewards += pending_avo;
                stats.total_claimed_rewards +=
                    (position.accumulated_rewards / 10u128.pow(18)) as u64;
                let apr = position.stake_type.apr(&self.params);
                stats.estimated_annual_rewards += amount_avo * apr;

                match position.stake_type {
                    StakeType::Bootstrap => stats.bootstrap_positions += 1,
                    StakeType::Validator => stats.validator_positions += 1,
                    StakeType::Delegation => stats.delegation_positions += 1,
                }
            }
        }

        // Ordenar por stake total y limitar
        let mut leaderboard: Vec<UserStakingStats> = user_stats.into_values().collect();
        leaderboard.sort_by(|a, b| b.total_staked.cmp(&a.total_staked));
        leaderboard.truncate(limit);

        leaderboard
    }
}

/// Estadísticas de staking para un usuario específico
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStakingStats {
    pub owner: String,
    pub total_positions: u32,
    pub bootstrap_positions: u32,
    pub validator_positions: u32,
    pub delegation_positions: u32,
    pub total_staked: u64,
    pub total_pending_rewards: f64,
    pub total_claimed_rewards: u64,
    pub estimated_annual_rewards: f64,
}

impl UserStakingStats {
    /// Obtener ROI actual (retorno sobre inversión)
    pub fn current_roi(&self) -> f64 {
        if self.total_staked == 0 {
            return 0.0;
        }

        (self.total_claimed_rewards as f64 / self.total_staked as f64) * 100.0
    }

    /// Obtener APR promedio
    pub fn average_apr(&self) -> f64 {
        if self.total_staked == 0 {
            return 0.0;
        }

        (self.estimated_annual_rewards as f64 / self.total_staked as f64) * 100.0
    }
}

