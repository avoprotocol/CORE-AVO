use thiserror::Error;

pub type AvoResult<T> = Result<T, AvoError>;

#[derive(Error, Debug)]
pub enum AvoError {
    // Errores generales
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    // Errores de consenso
    #[error("Consensus error: {reason}")]
    ConsensusError { reason: String },

    #[error("Quorum not reached for epoch {epoch}")]
    QuorumNotReached { epoch: u64 },

    #[error("Invalid vote: {reason}")]
    InvalidVote { reason: String },

    #[error("Finality violation: {reason}")]
    FinalityViolation { reason: String },

    // Errores de validación
    #[error("Validation error: {reason}")]
    ValidationError { reason: String },

    // Errores de transacciones
    #[error("Transaction validation failed: {reason}")]
    TransactionValidationError { reason: String },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },

    #[error("Gas limit exceeded: used {used}, limit {limit}")]
    GasLimitExceeded { used: u64, limit: u64 },

    #[error("Invalid signature for transaction {tx_id:?}")]
    InvalidSignature { tx_id: [u8; 32] },

    // Errores de sharding
    #[error("Shard not found: {shard_id}")]
    ShardNotFound { shard_id: u32 },

    #[error("Shard overloaded: {shard_id}, load: {load}")]
    ShardOverloaded { shard_id: u32, load: f64 },

    #[error("Cross-shard operation failed: {reason}")]
    CrossShardError { reason: String },

    #[error("Cross-shard timeout for transaction {tx_id:?}")]
    CrossShardTimeout { tx_id: [u8; 32] },

    #[error("Shard migration failed: {from_shard} -> {to_shard}, reason: {reason}")]
    ShardMigrationError {
        from_shard: u32,
        to_shard: u32,
        reason: String,
    },

    // Errores de almacenamiento
    #[error("Storage error: {reason}")]
    StorageError { reason: String },

    #[error("Database error: {source}")]
    DatabaseError { source: rocksdb::Error },

    #[error("Block not found: {block_id:?}")]
    BlockNotFound { block_id: [u8; 32] },

    #[error("Transaction not found: {tx_id:?}")]
    TransactionNotFound { tx_id: [u8; 32] },

    // Errores de red
    #[error("Network error: {reason}")]
    NetworkError { reason: String },

    #[error("Peer connection failed: {peer_id}")]
    PeerConnectionFailed { peer_id: String },

    #[error("Message delivery failed: {message_type}")]
    MessageDeliveryFailed { message_type: String },

    #[error("Network partition detected")]
    NetworkPartition,

    // Errores de staking
    #[error("Staking error: {reason}")]
    StakingError { reason: String },

    // Errores de estado
    #[error("State error: {reason}")]
    StateError { reason: String },

    #[error("State corruption detected: {state_root:?}")]
    StateCorruption { state_root: [u8; 32] },

    #[error("Merkle proof verification failed")]
    MerkleProofFailed,

    #[error("State root mismatch: expected {expected:?}, got {actual:?}")]
    StateRootMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    // Errores criptográficos
    #[error("Cryptographic error: {reason}")]
    CryptoError { reason: String },

    #[error("Threshold signature invalid")]
    InvalidThresholdSignature,

    #[error("VRF verification failed")]
    VRFVerificationFailed,

    #[error("BLS signature aggregation failed")]
    BLSAggregationFailed,

    // Errores de máquina virtual
    #[error("VM execution error: {reason}")]
    VMError { reason: String },

    #[error("WASM compilation failed: {reason}")]
    WASMCompilationFailed { reason: String },

    #[error("WASM execution error: {0}")]
    WasmExecutionError(String),

    #[error("Invalid bytecode: {0}")]
    InvalidBytecode(String),

    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[error("Contract execution reverted: {reason}")]
    ContractReverted { reason: String },

    #[error("Out of gas: used {used}, available {available}")]
    OutOfGas { used: u64, available: u64 },

    // Errores de validadores
    #[error("Validator not found: {validator_id}")]
    ValidatorNotFound { validator_id: u32 },

    #[error("Validator not eligible: {validator_id}, reason: {reason}")]
    ValidatorNotEligible { validator_id: u32, reason: String },

    #[error("Validator slashed: {validator_id}, amount: {amount}")]
    ValidatorSlashed { validator_id: u32, amount: u128 },

    #[error("Insufficient validators: cannot operate with zero validators")]
    InsufficientValidators,

    // Errores de gobernanza
    #[error("Governance proposal invalid: {reason}")]
    InvalidProposal { reason: String },

    #[error("Voting period expired for proposal {proposal_id}")]
    VotingPeriodExpired { proposal_id: u64 },

    #[error("Insufficient voting power: required {required}, available {available}")]
    InsufficientVotingPower { required: u128, available: u128 },

    #[error("Governance error: {0}")]
    GovernanceError(String),

    // Errores de MEV
    #[error("MEV protection violation: {reason}")]
    MevProtectionViolation { reason: String },

    #[error("Threshold encryption failed: {reason}")]
    ThresholdEncryptionFailed { reason: String },

    // Errores de recursos
    #[error("Resource not found: {resource_type} with id {id}")]
    ResourceNotFound { resource_type: String, id: String },

    #[error("Timeout exceeded: operation took {duration_ms}ms")]
    TimeoutExceeded { duration_ms: u64 },

    #[error("Rate limit exceeded: {operation}")]
    RateLimitExceeded { operation: String },

    // Errores de configuración
    #[error("Configuration error: {reason}")]
    ConfigError { reason: String },

    #[error("Invalid parameter: {param} = {value}")]
    InvalidParameter { param: String, value: String },

    // Errores de serialización
    #[error("Serialization error: {source}")]
    SerializationError { source: bincode::Error },

    #[error("JSON error: {source}")]
    JsonError { source: serde_json::Error },

    // Errores criptográficos
    #[error("Key error: {reason}")]
    KeyError { reason: String },

    // Errores de I/O
    #[error("IO error: {source}")]
    IoError { source: std::io::Error },

    // Errores de backup
    #[error("Backup error: {0}")]
    BackupError(String),

    // Errores del sistema
    #[error("System error: {0}")]
    SystemError(String),

    // Errores de Data Availability
    #[error("Data availability error: {reason}")]
    DataAvailabilityError { reason: String },

    // Errores genéricos
    #[error("Internal error: {reason}")]
    InternalError { reason: String },

    #[error("Not implemented: {feature}")]
    NotImplemented { feature: String },

    #[error("Parse error: {reason}")]
    ParseError { reason: String },
}

// Implementación de conversiones automáticas
impl From<bincode::Error> for AvoError {
    fn from(error: bincode::Error) -> Self {
        AvoError::SerializationError { source: error }
    }
}

impl From<serde_json::Error> for AvoError {
    fn from(error: serde_json::Error) -> Self {
        AvoError::JsonError { source: error }
    }
}

impl From<std::io::Error> for AvoError {
    fn from(error: std::io::Error) -> Self {
        AvoError::IoError { source: error }
    }
}

impl From<rocksdb::Error> for AvoError {
    fn from(error: rocksdb::Error) -> Self {
        AvoError::DatabaseError { source: error }
    }
}

impl From<anyhow::Error> for AvoError {
    fn from(error: anyhow::Error) -> Self {
        AvoError::InvalidInput(error.to_string())
    }
}

impl From<hyper::Error> for AvoError {
    fn from(error: hyper::Error) -> Self {
        AvoError::NetworkError {
            reason: error.to_string(),
        }
    }
}

// Métodos auxiliares para AvoError
impl AvoError {
    /// Crea un error de consenso genérico
    pub fn consensus(reason: impl Into<String>) -> Self {
        AvoError::ConsensusError {
            reason: reason.into(),
        }
    }

    /// Crea un error de transacción genérico
    pub fn transaction(reason: impl Into<String>) -> Self {
        AvoError::TransactionValidationError {
            reason: reason.into(),
        }
    }

    /// Crea un error de shard genérico
    pub fn cross_shard(reason: impl Into<String>) -> Self {
        AvoError::CrossShardError {
            reason: reason.into(),
        }
    }

    /// Crea un error de red genérico
    pub fn network(reason: impl Into<String>) -> Self {
        AvoError::NetworkError {
            reason: reason.into(),
        }
    }

    /// Crea un error de staking genérico
    pub fn staking(reason: impl Into<String>) -> Self {
        AvoError::StakingError {
            reason: reason.into(),
        }
    }

    /// Crea un error de almacenamiento genérico
    pub fn storage(reason: impl Into<String>) -> Self {
        AvoError::StorageError {
            reason: reason.into(),
        }
    }

    /// Crea un error de estado genérico
    pub fn state(reason: impl Into<String>) -> Self {
        AvoError::StateError {
            reason: reason.into(),
        }
    }

    /// Crea un error de validación genérico
    pub fn validation(reason: impl Into<String>) -> Self {
        AvoError::ValidationError {
            reason: reason.into(),
        }
    }

    /// Crea un error interno genérico
    pub fn internal(reason: impl Into<String>) -> Self {
        AvoError::InternalError {
            reason: reason.into(),
        }
    }

    /// Crea un error de configuración genérico
    pub fn config(reason: impl Into<String>) -> Self {
        AvoError::ConfigError {
            reason: reason.into(),
        }
    }

    /// Crea un error criptográfico genérico
    pub fn crypto(reason: impl Into<String>) -> Self {
        AvoError::CryptoError {
            reason: reason.into(),
        }
    }

    /// Crea un error de parsing genérico
    pub fn parse(reason: impl Into<String>) -> Self {
        AvoError::ParseError {
            reason: reason.into(),
        }
    }

    /// Crea un error de data availability genérico
    pub fn data_availability(reason: impl Into<String>) -> Self {
        AvoError::DataAvailabilityError {
            reason: reason.into(),
        }
    }

    /// Verifica si es un error recuperable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            AvoError::TimeoutExceeded { .. }
                | AvoError::NetworkError { .. }
                | AvoError::PeerConnectionFailed { .. }
                | AvoError::MessageDeliveryFailed { .. }
                | AvoError::RateLimitExceeded { .. }
        )
    }

    /// Verifica si es un error crítico del sistema
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            AvoError::StateCorruption { .. }
                | AvoError::FinalityViolation { .. }
                | AvoError::NetworkPartition
                | AvoError::DatabaseError { .. }
        )
    }
}

// Macros útiles para errores
#[macro_export]
macro_rules! consensus_error {
    ($msg:expr) => {
        AvoError::ConsensusError { reason: $msg.to_string() }
    };
    ($fmt:expr, $($arg:tt)*) => {
        AvoError::ConsensusError { reason: format!($fmt, $($arg)*) }
    };
}

#[macro_export]
macro_rules! shard_error {
    ($msg:expr) => {
        AvoError::CrossShardError { reason: $msg.to_string() }
    };
    ($fmt:expr, $($arg:tt)*) => {
        AvoError::CrossShardError { reason: format!($fmt, $($arg)*) }
    };
}

#[macro_export]
macro_rules! internal_error {
    ($msg:expr) => {
        AvoError::InternalError { reason: $msg.to_string() }
    };
    ($fmt:expr, $($arg:tt)*) => {
        AvoError::InternalError { reason: format!($fmt, $($arg)*) }
    };
}
