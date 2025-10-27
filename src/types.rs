use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

/// Hash criptográfico de 256 bits
pub type Hash = [u8; 32];

/// Identificador de shard
pub type ShardId = u32;

/// Número de época para rondas de consenso
pub type Epoch = u64;

/// Identificador de validador
pub type ValidatorId = u32;

/// Cantidad de stake en la unidad más pequeña
pub type StakeAmount = u128;

/// Cantidad genérica de tokens en la unidad mínima (wei)
pub type TokenAmount = u128;

/// Timestamp en milisegundos desde epoch Unix
pub type Timestamp = u64;

/// ID de nodo en la red P2P
pub type NodeId = String;

/// Identificador de cuenta/usuario
pub type AccountId = String;

/// Identificador único de transacción
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionId(pub Hash);

impl TransactionId {
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    pub fn zero() -> Self {
        Self([0; 32])
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for TransactionId {
    fn from(data: Vec<u8>) -> Self {
        Self::new(&data)
    }
}

/// Identificador de bloque
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId(pub Hash);

impl BlockId {
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    pub fn zero() -> Self {
        Self([0; 32])
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(bytes);
        Some(Self(hash))
    }
}

/// Dirección de cuenta (160 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        Self(addr)
    }

    pub fn zero() -> Self {
        Self([0; 20])
    }
}

/// Tipo de transacción
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    /// Transferencia simple de tokens
    Transfer,
    /// Llamada a contrato inteligente
    Contract,
    /// Creación de contrato
    ContractCreation,
    /// Transacción de staking
    Stake,
    /// Transacción de governance
    Governance,
}

/// Transacción en el protocolo AVO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TransactionId,
    pub from: Address,
    pub to: Option<Address>, // None para creación de contratos
    pub value: u128,
    pub data: Option<Vec<u8>>,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub nonce: u64,
    pub signature: Vec<u8>,
    pub parents: Vec<TransactionId>, // Padres en el DAG
    pub shard_id: ShardId,
    pub cross_shard_deps: Vec<ShardId>, // Dependencias cross-shard
    pub transaction_type: TransactionType,
}

impl Transaction {
    pub fn compute_id(&self) -> TransactionId {
        let tx_data = bincode::serialize(self).expect("Failed to serialize transaction");
        TransactionId::new(&tx_data)
    }

    pub fn is_cross_shard(&self) -> bool {
        !self.cross_shard_deps.is_empty()
    }

    /// Obtener cantidad transferida si es transacción de transfer
    pub fn get_transfer_amount(&self) -> Option<u64> {
        match self.transaction_type {
            TransactionType::Transfer => Some(self.value as u64),
            _ => None,
        }
    }
}

/// Bloque en el DAG de un shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub id: BlockId,
    pub shard_id: ShardId,
    pub epoch: Epoch,
    pub timestamp: u64,
    pub height: u64,
    pub transactions: Vec<Transaction>,
    pub parents: Vec<BlockId>, // Padres en el DAG
    pub state_root: Hash,
    pub transaction_merkle_root: Hash,
    pub validator_set_hash: Hash,
    pub proposer_signature: Vec<u8>,
}

impl Block {
    pub fn compute_id(&self) -> BlockId {
        let block_data = bincode::serialize(self).expect("Failed to serialize block");
        BlockId::new(&block_data)
    }
}

/// Información de validador
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub id: ValidatorId,
    pub public_key: Vec<u8>,
    pub bls_public_key: Vec<u8>,
    pub stake: StakeAmount,
    pub shard_assignments: Vec<ShardId>,
    pub is_sync_validator: bool,
    pub reputation_score: f64,
    pub uptime_percentage: f64,
}

/// Estado resumido de un shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardState {
    pub shard_id: ShardId,
    pub epoch: Epoch,
    pub height: u64,
    pub state_root: Hash,
    pub transaction_count: u64,
    pub validator_set: Vec<ValidatorId>,
    pub last_finalized_block: BlockId,
    pub pending_cross_shard_txs: u32,
}

/// Commit global del estado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalCommit {
    pub epoch: Epoch,
    pub timestamp: u64,
    pub shard_commits: HashMap<ShardId, ShardCommit>,
    pub sync_validator_signatures: Vec<u8>, // BLS agregado
    pub cross_shard_operations: Vec<CrossShardOperation>,
}

/// Commit de un shard individual
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardCommit {
    pub shard_id: ShardId,
    pub state_root: Hash,
    pub block_hash: BlockId,
    pub validator_signatures: Vec<u8>, // BLS agregado
    pub merkle_accumulator: Hash,
}

/// Firma agregada BLS con metadatos de quorum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedSignature {
    pub signature: Vec<u8>,
    pub participants: Vec<ValidatorId>,
    pub supporting_voting_power: StakeAmount,
    pub total_voting_power: StakeAmount,
    pub quorum_threshold: f64,
}

/// Voto agregado sobre un bloque del DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedVote {
    pub block_id: BlockId,
    pub epoch: Epoch,
    pub vote_type: VoteType,
    pub aggregated_signature: AggregatedSignature,
}

/// Prueba compacta de finalidad basada en DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProofSummary {
    pub block_id: BlockId,
    pub block_height: u64,
    pub shard_id: ShardId,
    pub aggregated_vote: AggregatedVote,
    pub merkle_root: Hash,
    pub merkle_leaf: Hash,
    pub merkle_leaf_index: u32,
    pub merkle_proof: Vec<Hash>,
}

/// Resultado completo de una ronda de consenso intra-shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConsensusOutput {
    pub block: Option<Block>,
    pub commit: ShardCommit,
    pub aggregated_vote: Option<AggregatedVote>,
    pub finality_summary: Option<FinalityProofSummary>,
}

/// Lock para transacciones cross-shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardLock {
    pub transaction_id: TransactionId,
    pub source_shard: ShardId,
    pub target_shards: Vec<ShardId>,
    pub timeout_epoch: Epoch,
    pub state_hash: Hash,
    pub lock_type: LockType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LockType {
    Prepare,
    Commit,
    Abort,
}

/// Operación cross-shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardOperation {
    pub id: TransactionId,
    pub operation_type: CrossShardOpType,
    pub involved_shards: Vec<ShardId>,
    pub state_changes: HashMap<ShardId, Hash>,
    pub status: CrossShardStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossShardOpType {
    Transfer,
    ContractCall,
    StateSync,
    ShardMigration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossShardStatus {
    Pending,
    Prepared,
    Committed,
    Aborted,
}

/// Prueba de Merkle para verificación de estado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub root: Hash,
    pub leaf: Hash,
    pub path: Vec<Hash>,
    pub indices: Vec<bool>, // true = derecha, false = izquierda
}

/// Tipos de mensajes de red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(Block),
    Vote(Vote),
    GlobalCommit(GlobalCommit),
    CrossShardPrepare(CrossShardLock),
    CrossShardCommit(TransactionId),
    CrossShardAbort(TransactionId),
    ValidatorHeartbeat(ValidatorHeartbeat),
    ShardStateSync(ShardStateSync),
    AggregatedVote {
        shard_id: ShardId,
        vote: AggregatedVote,
    },
    FinalitySummary(FinalityProofSummary),
}

/// Voto de consenso
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub validator_id: ValidatorId,
    pub epoch: Epoch,
    pub block_id: BlockId,
    pub vote_type: VoteType,
    pub signature: Vec<u8>,
    pub justification: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoteType {
    Prepare,
    Commit,
    Finalize,
    Abort,
}

/// Heartbeat de validador
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorHeartbeat {
    pub validator_id: ValidatorId,
    pub timestamp: u64,
    pub shard_loads: HashMap<ShardId, f64>,
    pub signature: Vec<u8>,
}

/// Sincronización de estado entre shards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStateSync {
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub state_delta: Vec<u8>,
    pub merkle_proof: MerkleProof,
    pub epoch: Epoch,
}

/// Configuración de un shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConfig {
    pub shard_id: ShardId,
    pub validator_count: u32,
    pub specialization: ShardSpecialization,
    pub max_transactions_per_block: u32,
    pub block_time_ms: u64,
    pub gas_limit: u64,
    pub load_threshold_split: f64,
    pub load_threshold_merge: f64,
}

/// Especialización del shard para diferentes tipos de operaciones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardSpecialization {
    General,          // Transacciones generales
    DeFi,             // Operaciones DeFi optimizadas
    HighFrequency,    // Trading de alta frecuencia
    DataAvailability, // Disponibilidad de datos
    GovernanceOnly,   // Solo gobernanza
}

/// Configuración del nodo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: Uuid,
    pub validator_id: Option<ValidatorId>,
    pub listen_address: String,
    pub bootstrap_peers: Vec<String>,
    pub shard_configs: Vec<ShardConfig>,
    pub storage_path: String,
    pub max_connections: u32,
    pub enable_rpc: bool,
    pub rpc_port: u16,
}

/// Métricas de performance del protocolo
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolMetrics {
    pub transactions_per_second: f64,
    pub average_confirmation_time_ms: f64,
    pub average_finality_time_ms: f64,
    pub active_shards: u32,
    pub total_validators: u32,
    pub network_bandwidth_mbps: f64,
    pub cross_shard_tx_ratio: f64,
    pub mev_protection_ratio: f64,
}

/// Parámetros del protocolo AVO con configuración económica diferenciada
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolParams {
    pub epoch_duration_ms: u64,
    pub quorum_threshold: f64,
    pub finality_threshold: f64,
    pub sync_validator_ratio: f64,
    pub cross_shard_timeout_ms: u64,
    pub max_shard_count: u32,
    pub min_validator_stake: StakeAmount,
    pub min_bootstrap_stake: StakeAmount,
    pub min_delegation_amount: StakeAmount,
    pub slash_percentage: f64,
    pub bootstrap_apr: f64,
    pub validator_apr: f64,
    pub delegator_apr: f64,
    pub max_validators: u32,
    pub network_id: u64,
}

impl Default for ProtocolParams {
    fn default() -> Self {
        Self {
            epoch_duration_ms: 2000,      // 2 segundos
            quorum_threshold: 0.67,       // 2/3 + 1
            finality_threshold: 0.67,     // 2/3 + 1
            sync_validator_ratio: 0.1,    // 10% sync validators
            cross_shard_timeout_ms: 5000, // 5 segundos
            max_shard_count: 256,         // Máximo 256 shards
            min_validator_stake: 1_000,   // 1K AVO - accesible para validadores
            min_bootstrap_stake: 10_000,  // 10K AVO - mayor responsabilidad de red
            min_delegation_amount: 0,     // Delegación gratuita para democratización
            slash_percentage: 0.05,       // 5% slash
            bootstrap_apr: 0.15,          // 15% APR - mayor responsabilidad de infraestructura
            validator_apr: 0.12,          // 12% APR - validación de bloques
            delegator_apr: 0.08,          // 8% APR - participación sin responsabilidad técnica
            max_validators: 1000,         // Máximo 1000 validadores
            network_id: 1337,             // ID de red por defecto
        }
    }
}

/// Resultado de la validación de una transacción
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationResult {
    Valid,
    Invalid { reason: String },
    Pending { dependencies: Vec<TransactionId> },
}

/// Estado de un validador en el protocolo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub id: ValidatorId,
    pub public_key: Vec<u8>,
    pub stake: StakeAmount,
    pub assigned_shards: Vec<ShardId>,
    pub performance_score: f64,
    pub last_activity: Timestamp,
    pub status: ValidatorStatus,
    // Campos adicionales para gestión dinámica
    pub bls_public_key: Option<Vec<u8>>,
    pub vrf_public_key: Option<Vec<u8>>,
    pub has_threshold_share: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Slashed,
    Jailed,
}

/// Información de red para un nodo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub node_id: NodeId,
    pub address: String,
    pub port: u16,
    pub protocol_version: String,
    pub supported_features: Vec<String>,
    pub last_seen: Timestamp,
}

/// Estadísticas de un shard
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShardStats {
    pub shard_id: ShardId,
    pub total_transactions: u64,
    pub pending_transactions: u64,
    pub average_tps: f64,
    pub load_factor: f64,
    pub validator_count: u32,
    pub last_block_time: Timestamp,
    pub cross_shard_operations: u64,
}

/// Configuración del threshold encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub threshold: u32,
    pub total_shares: u32,
    pub public_key: Vec<u8>,
    pub verification_keys: Vec<Vec<u8>>,
}

/// Prueba zero-knowledge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub verification_key: Vec<u8>,
}

// Implementaciones de Display para tipos principales
impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}
