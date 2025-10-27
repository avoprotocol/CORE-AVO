use crate::crypto::zk_cross_shard::{CrossShardZkProof, ZkCrossShardManager};
use crate::error::*;
use crate::traits::FinalityGadget;
use crate::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Consenso inter-shard para sincronización global y transacciones cross-shard
pub struct InterShardConsensus {
    protocol_params: ProtocolParams,
    finality_gadget: Arc<dyn FinalityGadget>,
    pending_cross_shard_ops: RwLock<HashMap<TransactionId, CrossShardOperation>>,
    cross_shard_locks: Arc<RwLock<HashMap<TransactionId, CrossShardLock>>>,
    zk_cross_shard_manager: Arc<RwLock<ZkCrossShardManager>>,
    // Cache de pruebas ZK para validación rápida
    zk_proof_cache: Arc<RwLock<HashMap<TransactionId, CrossShardZkProof>>>,
}

impl InterShardConsensus {
    pub fn new(
        protocol_params: ProtocolParams,
        finality_gadget: Arc<dyn FinalityGadget>,
        zk_cross_shard_manager: Arc<RwLock<ZkCrossShardManager>>,
    ) -> Self {
        Self {
            protocol_params,
            finality_gadget,
            pending_cross_shard_ops: RwLock::new(HashMap::new()),
            cross_shard_locks: Arc::new(RwLock::new(HashMap::new())),
            zk_cross_shard_manager,
            zk_proof_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registra una operación cross-shard pendiente
    pub async fn register_cross_shard_operation(&self, operation: CrossShardOperation) {
        let mut pending = self.pending_cross_shard_ops.write().await;
        pending.insert(operation.id, operation);
    }

    /// Obtiene una operación cross-shard por ID
    pub async fn get_cross_shard_operation(
        &self,
        transaction_id: &TransactionId,
    ) -> Option<CrossShardOperation> {
        let pending = self.pending_cross_shard_ops.read().await;
        pending.get(transaction_id).cloned()
    }

    /*
    /// 🚀 Nuevo constructor con parámetros ZK
    pub fn new_with_zk_params(
        protocol_params: ProtocolParams,
        finality_gadget: Arc<dyn FinalityGadget>,
        zk_parameters: ZkParameters,
    ) -> Self {
        Self {
            protocol_params,
            finality_gadget,
            pending_cross_shard_ops: std::sync::RwLock::new(HashMap::new()),
            zk_cross_shard_manager: Arc::new(tokio::sync::RwLock::new(
                ZkCrossShardManager::new_legacy(zk_parameters, ZkCrossShardConfig::default())
            )),
            zk_proof_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
    */

    /// Sincronizar estados de todos los shards
    pub async fn synchronize_shards(
        &self,
        epoch: Epoch,
        shard_commits: HashMap<ShardId, ShardCommit>,
    ) -> AvoResult<GlobalCommit> {
        info!(
            "Synchronizing {} shards for epoch {}",
            shard_commits.len(),
            epoch
        );

        // Validar commits de shards
        for (shard_id, commit) in &shard_commits {
            self.validate_shard_commit(*shard_id, commit).await?;
        }

        // Procesar operaciones cross-shard pendientes
        let cross_shard_ops = self.process_pending_cross_shard_ops(&shard_commits).await?;

        // Crear commit global
        let global_commit = GlobalCommit {
            epoch,
            timestamp: crate::utils::time::current_timestamp(),
            shard_commits,
            sync_validator_signatures: vec![0u8; 96], // TODO: Firmas BLS reales
            cross_shard_operations: cross_shard_ops,
        };

        // Marcar como finalizado usando el finality gadget
        self.finality_gadget
            .mark_finalized(&Block {
                id: BlockId([0; 32]),
                shard_id: 0,
                epoch,
                timestamp: global_commit.timestamp,
                height: 0,
                transactions: vec![],
                parents: vec![],
                state_root: [0; 32],
                transaction_merkle_root: [0; 32],
                validator_set_hash: [0; 32],
                proposer_signature: vec![],
            })
            .await?;

        debug!("Created global commit for epoch {}", epoch);
        Ok(global_commit)
    }

    /// Ejecuta una operación cross-shard validada con ZK dentro del protocolo 2PC
    pub async fn execute_cross_shard_operation(
        &self,
        tx: &Transaction,
        involved_shards: &[ShardId],
        pre_states: &HashMap<ShardId, [u8; 32]>,
        post_states: &HashMap<ShardId, [u8; 32]>,
        zk_proof: CrossShardZkProof,
    ) -> AvoResult<()> {
        info!(
            "🔐 Executing cross-shard operation {:?} across {} shards",
            tx.id,
            involved_shards.len()
        );

        self.execute_zk_enhanced_2pc(tx, involved_shards, pre_states, post_states, &zk_proof)
            .await?;

        Ok(())
    }

    /// 🚀 Protocolo 2PC optimizado con verificación ZK real
    async fn execute_zk_enhanced_2pc(
        &self,
        tx: &Transaction,
        involved_shards: &[ShardId],
        pre_states: &HashMap<ShardId, [u8; 32]>,
        post_states: &HashMap<ShardId, [u8; 32]>,
        zk_proof: &CrossShardZkProof,
    ) -> AvoResult<()> {
        info!("🚀 Executing ZK-enhanced 2PC for transaction {:?}", tx.id);

        let prepare_success = self
            .execute_zk_prepare_phase(tx, involved_shards, pre_states, post_states, zk_proof)
            .await?;

        if prepare_success {
            self.execute_zk_commit_phase(tx, involved_shards, post_states, zk_proof)
                .await?;
            info!("✅ ZK-enhanced 2PC completed successfully");
        } else {
            self.execute_abort_phase(tx, involved_shards).await?;
            warn!("❌ ZK-enhanced 2PC aborted due to invalid proof");
        }

        Ok(())
    }

    /// Fase de preparación con verificación ZK y creación de locks
    async fn execute_zk_prepare_phase(
        &self,
        tx: &Transaction,
        involved_shards: &[ShardId],
        pre_states: &HashMap<ShardId, [u8; 32]>,
        post_states: &HashMap<ShardId, [u8; 32]>,
        zk_proof: &CrossShardZkProof,
    ) -> AvoResult<bool> {
        info!("🔍 Executing ZK prepare phase for transaction {:?}", tx.id);

        let proof_valid = {
            let manager = self.zk_cross_shard_manager.read().await;
            manager
                .verify_cross_shard_proof(zk_proof, pre_states, post_states)
                .await?
        };

        if !proof_valid {
            warn!("❌ ZK proof rejected during prepare phase");
            return Ok(false);
        }

        let timeout_epochs = std::cmp::max(
            1,
            self.protocol_params.cross_shard_timeout_ms / self.protocol_params.epoch_duration_ms,
        );

        {
            let mut locks = self.cross_shard_locks.write().await;
            locks.insert(
                tx.id,
                CrossShardLock {
                    transaction_id: tx.id,
                    source_shard: tx.shard_id,
                    target_shards: involved_shards.to_vec(),
                    timeout_epoch: timeout_epochs,
                    state_hash: zk_proof.pre_state_hash,
                    lock_type: LockType::Prepare,
                },
            );
        }

        {
            let mut pending = self.pending_cross_shard_ops.write().await;
            if let Some(op) = pending.get_mut(&tx.id) {
                op.status = CrossShardStatus::Prepared;
            }
        }

        Ok(true)
    }

    /// Fase de commit - aplica cambios, actualiza locks y cachea la prueba
    async fn execute_zk_commit_phase(
        &self,
        tx: &Transaction,
        involved_shards: &[ShardId],
        post_states: &HashMap<ShardId, [u8; 32]>,
        zk_proof: &CrossShardZkProof,
    ) -> AvoResult<()> {
        info!("⚡ Executing ZK commit phase for transaction {:?}", tx.id);

        for shard_id in involved_shards {
            debug!(
                "⚡ Commit on shard {} for transaction {:?}",
                shard_id, tx.id
            );
        }

        {
            let mut locks = self.cross_shard_locks.write().await;
            if let Some(lock) = locks.get_mut(&tx.id) {
                lock.lock_type = LockType::Commit;
                lock.state_hash = zk_proof.post_state_hash;
            }
            locks.remove(&tx.id);
        }

        {
            let mut pending = self.pending_cross_shard_ops.write().await;
            if let Some(op) = pending.get_mut(&tx.id) {
                op.status = CrossShardStatus::Committed;
                op.state_changes = post_states.clone();
            }
        }

        let mut cache = self.zk_proof_cache.write().await;
        cache.insert(tx.id, zk_proof.clone());

        Ok(())
    }

    /// 🚀 Verificación rápida usando cache de pruebas ZK
    pub async fn fast_verify_cross_shard_transaction(
        &self,
        transaction_id: &TransactionId,
        expected_state_hash: &[u8; 32],
    ) -> AvoResult<bool> {
        let proof_cache = self.zk_proof_cache.read().await;

        if let Some(cached_proof) = proof_cache.get(transaction_id) {
            // Verificación ultra-rápida comparando hashes de estado
            let is_valid = cached_proof.post_state_hash == *expected_state_hash;

            if is_valid {
                info!(
                    "⚡ Fast ZK verification successful for transaction {:?}",
                    transaction_id
                );
            } else {
                warn!("❌ Fast ZK verification failed - state hash mismatch");
            }

            Ok(is_valid)
        } else {
            Err(AvoError::crypto("No ZK proof found in cache"))
        }
    }

    /// Fase de preparación del protocolo 2PC
    /// FASE 9.4: Implementación real con validación
    async fn execute_prepare_phase(
        &self,
        tx: &Transaction,
        involved_shards: &[ShardId],
    ) -> AvoResult<bool> {
        debug!("Executing prepare phase for transaction {:?}", tx.id);

        let timeout_epochs = std::cmp::max(
            1,
            self.protocol_params.cross_shard_timeout_ms / self.protocol_params.epoch_duration_ms,
        );

        // 1. Create locks on all involved shards
        let lock = CrossShardLock {
            transaction_id: tx.id,
            source_shard: tx.shard_id,
            target_shards: involved_shards.to_vec(),
            timeout_epoch: timeout_epochs,
            state_hash: tx.id.0,
            lock_type: LockType::Prepare,
        };

        {
            let mut locks = self.cross_shard_locks.write().await;
            // Check if transaction is already locked
            if locks.contains_key(&tx.id) {
                return Err(AvoError::validation(format!(
                    "Transaction {:?} is already locked",
                    tx.id
                )));
            }
            locks.insert(tx.id, lock.clone());
        }

        // 2. Validate transaction can be executed on all shards
        let mut votes = Vec::new();

        for &shard_id in involved_shards {
            debug!("Preparing shard {} for transaction {:?}", shard_id, tx.id);

            // Validate preconditions for this shard
            match self.validate_shard_preconditions(tx, shard_id).await {
                Ok(true) => {
                    votes.push(shard_id);
                    debug!("✓ Shard {} voted YES for transaction {:?}", shard_id, tx.id);
                }
                Ok(false) | Err(_) => {
                    warn!("✗ Shard {} voted NO for transaction {:?}", shard_id, tx.id);
                }
            }
        }

        // 3. Check if we have enough votes (all shards must agree)
        let all_agreed = votes.len() == involved_shards.len();

        if !all_agreed {
            // Abort: release locks
            warn!(
                "Prepare phase ABORTED: only {}/{} shards agreed",
                votes.len(),
                involved_shards.len()
            );

            let mut locks = self.cross_shard_locks.write().await;
            if locks.remove(&tx.id).is_some() {
                debug!("Released locks for transaction {:?}", tx.id);
            }

            return Ok(false);
        }

        // 4. Update lock state to Prepared
        {
            let mut locks = self.cross_shard_locks.write().await;
            if let Some(lock) = locks.get_mut(&tx.id) {
                lock.lock_type = LockType::Prepare;
            }
        }

        info!(
            "✓ Prepare phase SUCCESSFUL: {}/{} shards agreed for transaction {:?}",
            votes.len(),
            involved_shards.len(),
            tx.id
        );

        Ok(true)
    }

    /// Validate preconditions for executing transaction on a specific shard
    async fn validate_shard_preconditions(
        &self,
        tx: &Transaction,
        shard_id: ShardId,
    ) -> AvoResult<bool> {
        // FASE 9.4: Real validation

        // 1. Check if shard is involved in transaction
        if !tx.cross_shard_deps.contains(&shard_id) && tx.shard_id != shard_id {
            return Ok(false);
        }

        // 2. For source shard: validate balance and nonce
        if tx.shard_id == shard_id {
            // This would normally query the state of the shard
            // For now, we'll do basic validation

            // Check transaction value is reasonable
            if tx.value == 0 && tx.transaction_type == TransactionType::Transfer {
                warn!("Zero-value transfer on shard {}", shard_id);
                return Ok(false);
            }

            // Check gas limits
            if tx.gas_limit == 0 {
                warn!("Zero gas limit on shard {}", shard_id);
                return Ok(false);
            }
        }

        // 3. Check for conflicting locks
        let locks = self.cross_shard_locks.read().await;
        for (lock_tx_id, lock) in locks.iter() {
            if lock_tx_id != &tx.id
                && (lock.source_shard == shard_id || lock.target_shards.contains(&shard_id))
            {
                // Another transaction has a lock on this shard
                if matches!(lock.lock_type, LockType::Prepare | LockType::Commit) {
                    warn!(
                        "Shard {} is locked by transaction {:?}",
                        shard_id, lock_tx_id
                    );
                    return Ok(false);
                }
            }
        }

        // 4. All validations passed
        Ok(true)
    }

    /// Fase de commit del protocolo 2PC
    async fn execute_commit_phase(
        &self,
        tx: &Transaction,
        involved_shards: &[ShardId],
    ) -> AvoResult<()> {
        debug!("Executing commit phase for transaction {:?}", tx.id);

        for shard_id in involved_shards {
            debug!("Committing transaction {:?} in shard {}", tx.id, shard_id);
        }

        {
            let mut locks = self.cross_shard_locks.write().await;
            locks.remove(&tx.id);
        }

        {
            let mut pending = self.pending_cross_shard_ops.write().await;
            if let Some(op) = pending.get_mut(&tx.id) {
                op.status = CrossShardStatus::Committed;
            }
        }

        Ok(())
    }

    /// Fase de abort del protocolo 2PC
    async fn execute_abort_phase(
        &self,
        tx: &Transaction,
        involved_shards: &[ShardId],
    ) -> AvoResult<()> {
        debug!("Executing abort phase for transaction {:?}", tx.id);

        for shard_id in involved_shards {
            debug!("Aborting transaction {:?} in shard {}", tx.id, shard_id);
        }

        {
            let mut locks = self.cross_shard_locks.write().await;
            if let Some(lock) = locks.get_mut(&tx.id) {
                lock.lock_type = LockType::Abort;
            }
            locks.remove(&tx.id);
        }

        {
            let mut pending = self.pending_cross_shard_ops.write().await;
            if let Some(op) = pending.get_mut(&tx.id) {
                op.status = CrossShardStatus::Aborted;
            }
        }

        Ok(())
    }

    /// Validar commit de un shard
    async fn validate_shard_commit(
        &self,
        shard_id: ShardId,
        commit: &ShardCommit,
    ) -> AvoResult<()> {
        debug!("Validating commit for shard {}", shard_id);

        // Verificar que el shard ID coincida
        if commit.shard_id != shard_id {
            return Err(AvoError::ConsensusError {
                reason: format!(
                    "Shard ID mismatch: expected {}, got {}",
                    shard_id, commit.shard_id
                ),
            });
        }

        // Usar protocol_params para validación
        if commit.validator_signatures.len() < self.protocol_params.quorum_threshold as usize * 96 {
            return Err(AvoError::ConsensusError {
                reason: "Insufficient validator signatures for quorum".to_string(),
            });
        }

        // TODO: Implementar validación real
        // - Verificar firmas BLS agregadas
        // - Validar merkle accumulator
        // - Verificar consistencia del estado

        Ok(())
    }

    /// Procesar operaciones cross-shard pendientes
    async fn process_pending_cross_shard_ops(
        &self,
        _shard_commits: &HashMap<ShardId, ShardCommit>,
    ) -> AvoResult<Vec<CrossShardOperation>> {
        let pending = self.pending_cross_shard_ops.read().await;
        let ops: Vec<CrossShardOperation> = pending.values().cloned().collect();

        // TODO: Procesar operaciones reales basadas en los commits de los shards
        Ok(ops)
    }

    /*
    /// 📊 Obtener estadísticas del sistema ZK Cross-Shard
    pub async fn get_zk_cross_shard_statistics(&self) -> crate::crypto::zk_cross_shard::ZkCrossShardStatistics {
        let zk_manager = self.zk_cross_shard_manager.read().await;
        zk_manager.get_statistics()
    }
    */

    /// 🗑️ Limpiar cache de pruebas ZK antiguas
    pub async fn cleanup_zk_proof_cache(&self, max_age_seconds: u64) {
        let mut proof_cache = self.zk_proof_cache.write().await;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        proof_cache.retain(|_, proof| current_time - proof.created_at < max_age_seconds);

        info!(
            "🗑️ Cleaned ZK proof cache, {} proofs remaining",
            proof_cache.len()
        );
    }
}
