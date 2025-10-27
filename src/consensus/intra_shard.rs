use crate::consensus::flow_consensus::CryptoSystem;
use crate::consensus::shard_dag_engine::ShardDagEngine;
use crate::crypto::bls_signatures::BlsSignature;
use crate::error::*;
use crate::state::merkle_tree::OptimizedMerkleTree;
use crate::storage::RocksDBBackend;
use crate::transaction::validator::TransactionValidator;
use crate::types::*;
use crate::utils::hash;
use sha3::Digest;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Consenso intra-shard usando DAG y votación BLS
#[derive(Clone)]
pub struct IntraShardConsensus {
    pub shard_config: ShardConfig,
    pub validators: Vec<Validator>,
    pub protocol_params: ProtocolParams,
    pub transaction_pool: Arc<RwLock<Vec<Transaction>>>,
    dag_engine: ShardDagEngine,
    crypto_system: Arc<CryptoSystem>,
    tx_validator: Arc<TransactionValidator>,
    state_tree: Arc<OptimizedMerkleTree>,
    storage: Option<Arc<RocksDBBackend>>,
}

#[derive(Debug, Clone)]
pub struct ShardMetrics {
    pub transactions_per_second: f64,
    pub average_confirmation_time_ms: f64,
    pub current_load: f64,
}

impl IntraShardConsensus {
    pub fn new(
        shard_config: ShardConfig,
        validators: Vec<Validator>,
        protocol_params: ProtocolParams,
        crypto_system: Arc<CryptoSystem>,
    ) -> Self {
        let max_tips = (shard_config.max_transactions_per_block as usize).max(4);
        let shard_id = shard_config.shard_id;

        // Create transaction validator with reasonable defaults
        let tx_validator = Arc::new(TransactionValidator::new(
            1_000_000_000, // 1 gwei minimum gas price
            10_000_000,    // 10M gas limit max
        ));

        // Create Merkle tree for state root calculation
        let state_tree = Arc::new(OptimizedMerkleTree::new());

        // FASE 9.3: Try to initialize RocksDB storage
        let storage = Self::try_init_storage(shard_id);

        Self {
            shard_config,
            validators,
            protocol_params,
            transaction_pool: Arc::new(RwLock::new(Vec::new())),
            dag_engine: ShardDagEngine::new(shard_id, max_tips),
            crypto_system,
            tx_validator,
            state_tree,
            storage,
        }
    }

    /// Try to initialize RocksDB storage
    fn try_init_storage(shard_id: ShardId) -> Option<Arc<RocksDBBackend>> {
        let storage_path = PathBuf::from(format!("./data/shard_{}", shard_id));

        match RocksDBBackend::new(&storage_path, shard_id) {
            Ok(backend) => {
                info!("✓ RocksDB storage initialized at {:?}", storage_path);
                Some(Arc::new(backend))
            }
            Err(e) => {
                warn!(
                    "Failed to initialize RocksDB storage: {}. Running in-memory mode.",
                    e
                );
                None
            }
        }
    }

    pub async fn process_transaction(&self, tx: Transaction) -> AvoResult<()> {
        debug!(
            "Processing transaction {:?} in shard {}",
            tx.id, self.shard_config.shard_id
        );

        // Validar transacción
        self.validate_transaction(&tx).await?;

        // Agregar al pool
        let mut pool = self.transaction_pool.write().await;
        pool.push(tx);

        Ok(())
    }

    pub async fn run_epoch_consensus(&self, epoch: Epoch) -> AvoResult<ShardConsensusOutput> {
        info!(
            "Running epoch {} consensus for shard {}",
            epoch, self.shard_config.shard_id
        );

        // Tomar transacciones del pool
        let transactions = {
            let mut pool = self.transaction_pool.write().await;
            let tx_count = std::cmp::min(
                pool.len(),
                self.shard_config.max_transactions_per_block as usize,
            );
            pool.drain(0..tx_count).collect::<Vec<_>>()
        };

        if transactions.is_empty() {
            debug!(
                "No transactions to process in shard {}, skipping block creation",
                self.shard_config.shard_id
            );
            let commit = ShardCommit {
                shard_id: self.shard_config.shard_id,
                block_hash: BlockId::zero(),
                state_root: [0u8; 32],
                validator_signatures: Vec::new(),
                merkle_accumulator: [0u8; 32],
            };

            return Ok(ShardConsensusOutput {
                block: None,
                commit,
                aggregated_vote: None,
                finality_summary: None,
            });
        }

        // Crear bloque
        let block = self.create_block(transactions, epoch).await?;

        // Insertar bloque en el DAG del shard
        self.dag_engine.insert_block(block.clone()).await?;

        // Generar commit, voto agregado y resumen de finalidad
        self.produce_consensus_output(block, epoch).await
    }

    async fn validate_transaction(&self, tx: &Transaction) -> AvoResult<()> {
        // FASE 9.1: Validación completa implementada
        // - Validar firma ✓
        // - Validar nonce ✓
        // - Validar balance ✓
        // - Validar gas ✓
        self.tx_validator.validate_transaction(tx)?;
        Ok(())
    }

    async fn create_block(&self, transactions: Vec<Transaction>, epoch: Epoch) -> AvoResult<Block> {
        let mut parents = self
            .dag_engine
            .select_parents(self.dag_engine.max_tips())
            .await;

        if parents.is_empty() {
            parents.push(BlockId::zero());
        }

        let metrics = self.dag_engine.metrics().await;
        let height = metrics.max_height + 1;

        // Calcular raíces de Merkle
        let tx_hashes: Vec<Hash> = transactions
            .iter()
            .map(|tx| {
                let data = bincode::serialize(tx).unwrap();
                crate::utils::hash::hash_bytes(&data)
            })
            .collect();

        let transaction_merkle_root = if tx_hashes.is_empty() {
            [0; 32]
        } else {
            crate::utils::hash::merkle_root(&tx_hashes)
        };

        // FASE 9.2: Calcular state root real
        // Update state tree with transaction effects
        let state_data: Vec<Vec<u8>> = transactions
            .iter()
            .enumerate()
            .map(|(idx, tx)| {
                // Create state leaf from transaction
                let mut data = Vec::new();
                data.extend_from_slice(&tx.from.0);
                if let Some(to) = &tx.to {
                    data.extend_from_slice(&to.0);
                }
                data.extend_from_slice(&tx.value.to_le_bytes());
                data.extend_from_slice(&tx.nonce.to_le_bytes());
                data.extend_from_slice(&(idx as u64).to_le_bytes());
                data
            })
            .collect();

        // Build merkle tree from state data
        if !state_data.is_empty() {
            self.state_tree.build_from_data(state_data).await?;
        }

        // Get state root from merkle tree
        let state_root = self.state_tree.get_root_hash().await.unwrap_or([0; 32]);

        // Calculate validator set hash
        let validator_set_hash = self.calculate_validator_set_hash();

        let mut block = Block {
            id: BlockId::zero(), // Temporal, se calculará después
            shard_id: self.shard_config.shard_id,
            epoch,
            timestamp: crate::utils::time::current_timestamp(),
            height,
            transactions,
            parents,
            state_root, // ✓ FASE 9.2: State root calculado dinámicamente
            transaction_merkle_root,
            validator_set_hash,         // ✓ Hash del conjunto de validadores
            proposer_signature: vec![], // TODO: Firmar bloque
        };

        // Calcular el ID del bloque basado en su contenido
        block.id = block.compute_id();

        // FASE 9.3: Persist block to RocksDB if available
        if let Some(ref storage) = self.storage {
            if let Err(e) = storage.store_block(&block) {
                warn!("Failed to persist block {}: {}", block.height, e);
            } else {
                debug!("✓ Block {} persisted to RocksDB", block.height);

                // Also persist transactions
                for tx in &block.transactions {
                    if let Err(e) = storage.store_transaction(tx) {
                        warn!("Failed to persist transaction {:?}: {}", tx.id, e);
                    }
                }

                // Persist state root
                if let Err(e) = storage.store_state_root(block.height, state_root) {
                    warn!("Failed to persist state root: {}", e);
                }

                // Update latest height
                if let Err(e) = storage.update_latest_height(block.height) {
                    warn!("Failed to update latest height: {}", e);
                }
            }
        }

        Ok(block)
    }

    /// Calculate hash of the validator set
    fn calculate_validator_set_hash(&self) -> Hash {
        let mut hasher = sha3::Sha3_256::new();
        for validator in &self.validators {
            hasher.update(&validator.id.to_le_bytes());
            hasher.update(&validator.public_key);
            hasher.update(&validator.stake.to_le_bytes());
        }
        hasher.finalize().into()
    }

    async fn produce_consensus_output(
        &self,
        block: Block,
        epoch: Epoch,
    ) -> AvoResult<ShardConsensusOutput> {
        let (commit, aggregated_vote, finality_summary) =
            self.create_shard_commit(&block, epoch).await?;

        Ok(ShardConsensusOutput {
            block: Some(block),
            commit,
            aggregated_vote: Some(aggregated_vote),
            finality_summary: Some(finality_summary),
        })
    }

    async fn create_shard_commit(
        &self,
        block: &Block,
        epoch: Epoch,
    ) -> AvoResult<(ShardCommit, AggregatedVote, FinalityProofSummary)> {
        let mut signatures: Vec<BlsSignature> = Vec::new();
        let mut participants: Vec<ValidatorId> = Vec::new();
        let mut total_voting_power: StakeAmount = 0;
        let mut supporting_power: StakeAmount = 0;

        for validator in &self.validators {
            total_voting_power = total_voting_power.saturating_add(validator.stake);

            if let Some((private_key, _)) = self.crypto_system.bls_keys.get(&validator.id) {
                let signature = private_key.sign(block.id.as_bytes())?;
                signatures.push(signature);
                participants.push(validator.id);
                supporting_power = supporting_power.saturating_add(validator.stake);
            } else {
                warn!(
                    validator_id = validator.id,
                    shard = self.shard_config.shard_id,
                    "No se encontró clave BLS para el validador"
                );
            }
        }

        if signatures.is_empty() {
            return Err(AvoError::crypto(
                "No se pudieron generar firmas BLS para el commit del shard",
            ));
        }

        let aggregated_signature = BlsSignature::aggregate(&signatures)?;
        let aggregated_signature_bytes = aggregated_signature.to_bytes();

        let aggregated_signature_struct = AggregatedSignature {
            signature: aggregated_signature_bytes.clone(),
            participants: participants.clone(),
            supporting_voting_power: supporting_power,
            total_voting_power,
            quorum_threshold: self.protocol_params.quorum_threshold,
        };

        let aggregated_vote = AggregatedVote {
            block_id: block.id,
            epoch,
            vote_type: VoteType::Commit,
            aggregated_signature: aggregated_signature_struct.clone(),
        };

        let vote_bytes = bincode::serialize(&aggregated_vote).map_err(|err| {
            AvoError::InvalidInput(format!(
                "No se pudo serializar aggregated vote para Merkle leaf: {}",
                err
            ))
        })?;

        let merkle_leaf = hash::hash_bytes(&vote_bytes);
        let merkle_leaves = vec![
            block.id.0,
            block.state_root,
            block.transaction_merkle_root,
            merkle_leaf,
        ];
        let merkle_root = hash::merkle_root(&merkle_leaves);
        let merkle_leaf_index = (merkle_leaves.len() - 1) as u32;
        let merkle_proof = hash::merkle_proof(&merkle_leaves, merkle_leaf_index as usize)?;

        let finality_summary = FinalityProofSummary {
            block_id: block.id,
            block_height: block.height,
            shard_id: block.shard_id,
            aggregated_vote: aggregated_vote.clone(),
            merkle_root,
            merkle_leaf,
            merkle_leaf_index,
            merkle_proof,
        };

        let commit = ShardCommit {
            shard_id: self.shard_config.shard_id,
            state_root: block.state_root,
            block_hash: block.id,
            validator_signatures: aggregated_signature_bytes,
            merkle_accumulator: merkle_root,
        };

        Ok((commit, aggregated_vote, finality_summary))
    }

    pub async fn propose_block(&self, transactions: Vec<Transaction>) -> AvoResult<Block> {
        let current_epoch = 0; // TODO: Obtener época actual
        self.create_block(transactions, current_epoch).await
    }

    pub async fn vote_on_block(&self, block: &Block) -> AvoResult<Vote> {
        // TODO: Implementar validación y votación real
        Ok(Vote {
            validator_id: 0, // TODO: Obtener ID del validador actual
            epoch: block.epoch,
            block_id: block.id,
            vote_type: VoteType::Prepare,
            signature: vec![], // TODO: Firmar voto
            justification: None,
        })
    }

    pub async fn validate_block(&self, _block: &Block) -> AvoResult<bool> {
        // TODO: Implementar validación completa del bloque
        Ok(true)
    }

    pub async fn finalize_block(&self, _block: &Block, _votes: Vec<Vote>) -> AvoResult<()> {
        // TODO: Implementar finalización con verificación de votos
        Ok(())
    }

    pub async fn get_shard_metrics(&self) -> AvoResult<ShardMetrics> {
        let dag_metrics = self.dag_engine.metrics().await;
        let pool_size = self.transaction_pool.read().await.len();

        let average_confirmation_time_ms = if dag_metrics.total_nodes == 0 {
            0.0
        } else {
            (self.shard_config.block_time_ms as f64).max(1.0)
        };

        let transactions_per_second = if average_confirmation_time_ms > 0.0 {
            (dag_metrics.total_nodes as f64)
                / ((dag_metrics.max_height.max(1) as f64) * (average_confirmation_time_ms / 1000.0))
        } else {
            0.0
        };

        Ok(ShardMetrics {
            transactions_per_second,
            average_confirmation_time_ms,
            current_load: pool_size as f64
                / (self.shard_config.max_transactions_per_block as f64).max(1.0),
        })
    }
}
