use crate::error::AvoResult;
use crate::types::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Trait para validación de transacciones
#[async_trait]
pub trait TransactionValidator: Send + Sync {
    async fn validate_transaction(&self, tx: &Transaction) -> AvoResult<bool>;
    async fn validate_signature(&self, tx: &Transaction) -> AvoResult<bool>;
    async fn validate_balance(&self, address: &Address, amount: u128) -> AvoResult<bool>;
    async fn validate_nonce(&self, address: &Address, nonce: u64) -> AvoResult<bool>;
    async fn validate_gas_limit(&self, tx: &Transaction) -> AvoResult<bool>;
}

/// Trait para participantes del consenso
#[async_trait]
pub trait ConsensusParticipant: Send + Sync {
    async fn propose_block(
        &self,
        shard_id: ShardId,
        transactions: Vec<Transaction>,
    ) -> AvoResult<Block>;
    async fn vote_on_block(&self, block: &Block) -> AvoResult<Vote>;
    async fn finalize_block(&self, block: &Block, votes: Vec<Vote>) -> AvoResult<()>;
    async fn get_validator_id(&self) -> ValidatorId;
}

/// Trait para manejo de shards
#[async_trait]
pub trait ShardManager: Send + Sync {
    async fn assign_shard(&self, transaction: &Transaction) -> AvoResult<ShardId>;
    async fn create_shard(&self, shard_id: ShardId) -> AvoResult<()>;
    async fn remove_shard(&self, shard_id: ShardId) -> AvoResult<()>;
    async fn get_shard_info(&self, shard_id: ShardId) -> AvoResult<ShardInfo>;
    async fn list_shards(&self) -> AvoResult<Vec<ShardId>>;
    async fn migrate_shard(&self, from: ShardId, to: ShardId) -> AvoResult<()>;
    async fn balance_shards(&self) -> AvoResult<()>;
}

/// Trait para almacenamiento de estado
#[async_trait]
pub trait Storage: Send + Sync {
    async fn get(&self, key: &[u8]) -> AvoResult<Option<Vec<u8>>>;
    async fn put(&self, key: &[u8], value: &[u8]) -> AvoResult<()>;
    async fn delete(&self, key: &[u8]) -> AvoResult<()>;
    async fn batch_write(&self, operations: Vec<StorageOperation>) -> AvoResult<()>;
    async fn get_state_root(&self) -> AvoResult<Hash>;
}

/// Trait para ejecución de contratos
#[async_trait]
pub trait VirtualMachine: Send + Sync {
    async fn execute_transaction(
        &self,
        tx: &Transaction,
        state: &dyn Storage,
    ) -> AvoResult<ExecutionResult>;
    async fn deploy_contract(&self, bytecode: &[u8], constructor_args: &[u8])
        -> AvoResult<Address>;
    async fn call_contract(
        &self,
        address: &Address,
        data: &[u8],
        gas_limit: u64,
    ) -> AvoResult<ExecutionResult>;
    async fn estimate_gas(&self, tx: &Transaction) -> AvoResult<u64>;
}

/// Trait para finalidad del consenso
#[async_trait]
pub trait FinalityGadget: Send + Sync {
    async fn check_finality(&self, block: &Block) -> AvoResult<bool>;
    async fn get_finalized_height(&self) -> AvoResult<u64>;
    async fn mark_finalized(&self, block: &Block) -> AvoResult<()>;
}

/// Trait para manejo de estado distribuido
#[async_trait]
pub trait StateManager: Send + Sync {
    async fn apply_transaction(&self, tx: &Transaction, state: &mut dyn Storage) -> AvoResult<()>;
    async fn create_state_proof(&self, key: &[u8]) -> AvoResult<StateProof>;
    async fn verify_state_proof(&self, proof: &StateProof) -> AvoResult<bool>;
    async fn get_account_state(&self, address: &Address) -> AvoResult<AccountState>;
    async fn update_account_state(&self, address: &Address, state: &AccountState) -> AvoResult<()>;
}

/// Trait para red P2P
#[async_trait]
pub trait NetworkManager: Send + Sync {
    async fn broadcast_transaction(&self, tx: Transaction) -> AvoResult<()>;
    async fn broadcast_block(&self, block: Block) -> AvoResult<()>;
    async fn request_blocks(&self, start_height: u64, count: u32) -> AvoResult<Vec<Block>>;
    async fn sync_with_peers(&self) -> AvoResult<()>;
    async fn get_peer_count(&self) -> AvoResult<usize>;
    async fn ban_peer(&self, peer_id: String) -> AvoResult<()>;
}

/// Trait para manejo de claves y firmas
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    async fn generate_keypair(&self) -> AvoResult<(Vec<u8>, Vec<u8>)>;
    async fn sign(&self, data: &[u8], private_key: &[u8]) -> AvoResult<Vec<u8>>;
    async fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> AvoResult<bool>;
    async fn hash(&self, data: &[u8]) -> AvoResult<Hash>;
    async fn verify_merkle_proof(&self, proof: &MerkleProof) -> AvoResult<bool>;
}

/// Trait para métricas del sistema
#[async_trait]
pub trait MetricsCollector: Send + Sync {
    async fn record_transaction_latency(&self, duration_ms: u64) -> AvoResult<()>;
    async fn record_block_size(&self, size_bytes: u64) -> AvoResult<()>;
    async fn record_consensus_round(&self, round: u64, duration_ms: u64) -> AvoResult<()>;
    async fn get_tps(&self) -> AvoResult<f64>;
    async fn get_average_latency(&self) -> AvoResult<f64>;
}

/// Operación de almacenamiento para escritura por lotes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageOperation {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

/// Resultado de ejecución de una transacción
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub status: ExecutionStatus,
    pub logs: Vec<Log>,
    pub state_changes: Vec<StateChange>,
}

/// Estado de ejecución
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Success,
    Revert,
    OutOfGas,
    InternalError,
}

/// Log de evento
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

/// Cambio de estado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub address: Address,
    pub key: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
    pub new_value: Option<Vec<u8>>,
}

/// Configuración del protocolo
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub max_block_size: u64,
    pub target_block_time: u64,
    pub max_gas_per_block: u64,
    pub quorum_threshold: f64,
    pub finality_threshold: f64,
    pub epoch_duration: u64,
    pub max_shard_count: u32,
}

/// Información de red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub chain_id: u64,
    pub protocol_version: u32,
    pub node_id: NodeId,
    pub listening_addresses: Vec<String>,
}

/// Mensaje de red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(Block),
    Vote(Vote),
    BlockRequest { start_height: u64, count: u32 },
    BlockResponse { blocks: Vec<Block> },
    Ping,
    Pong,
}

/// Prueba de Merkle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u32,
    pub proof_hashes: Vec<Hash>,
    pub leaf_hash: Hash,
    pub root_hash: Hash,
}

/// Prueba de estado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    pub account_proof: MerkleProof,
    pub storage_proof: Option<MerkleProof>,
    pub value: Vec<u8>,
}

/// Estado de cuenta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: u128,
    pub code_hash: Hash,
    pub storage_root: Hash,
}

/// Información de validador
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub id: ValidatorId,
    pub public_key: Vec<u8>,
    pub stake: u128,
    pub commission: f64,
    pub is_active: bool,
}

/// Información de shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardInfo {
    pub id: ShardId,
    pub validator_set: Vec<ValidatorId>,
    pub current_height: u64,
    pub transaction_count: u64,
    pub load_factor: f64,
}
