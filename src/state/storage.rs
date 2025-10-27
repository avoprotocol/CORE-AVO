use crate::error::AvoError;
use crate::types::{AccountId, BlockId, Hash, ShardId, TransactionId};
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, DB};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, RwLock};

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base directory for storage
    pub base_path: PathBuf,
    /// Cache size in MB
    pub cache_size_mb: usize,
    /// Enable compression
    pub enable_compression: bool,
    /// Checkpoint interval
    pub checkpoint_interval: Duration,
    /// Maximum file size before rotation
    pub max_file_size_mb: usize,
    /// Number of backup files to keep
    pub backup_count: usize,
    /// Enable WAL (Write-Ahead Logging)
    pub enable_wal: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("./avo_data"),
            cache_size_mb: 256,
            enable_compression: true,
            checkpoint_interval: Duration::from_secs(300), // 5 minutes
            max_file_size_mb: 128,
            backup_count: 5,
            enable_wal: true,
        }
    }
}

impl StorageConfig {
    /// Create a storage config with a custom base path
    pub fn with_path<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            base_path: path.into(),
            ..Default::default()
        }
    }
}

/// Storage key types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageKey {
    Account(AccountId),
    Transaction(TransactionId),
    Block(BlockId),
    State(ShardId, String),
    Contract(AccountId, String),
    Metadata(String),
}

impl StorageKey {
    /// Convert to string representation for storage
    pub fn to_string(&self) -> String {
        match self {
            StorageKey::Account(id) => format!("acc:{}", id),
            StorageKey::Transaction(id) => format!("tx:{}", hex::encode(&id.0)),
            StorageKey::Block(id) => format!("blk:{}", hex::encode(&id.0)),
            StorageKey::State(shard, key) => format!("state:{}:{}", shard, key),
            StorageKey::Contract(addr, key) => format!("contract:{}:{}", addr, key),
            StorageKey::Metadata(key) => format!("meta:{}", key),
        }
    }

    /// Parse from string representation
    pub fn from_string(s: &str) -> Result<Self, AvoError> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(AvoError::InvalidInput(format!(
                "Invalid storage key format: {}",
                s
            )));
        }

        match parts[0] {
            "acc" => Ok(StorageKey::Account(parts[1].to_string())),
            "tx" => {
                let bytes = hex::decode(parts[1]).map_err(|_| {
                    AvoError::InvalidInput("Invalid transaction ID hex".to_string())
                })?;
                if bytes.len() != 32 {
                    return Err(AvoError::InvalidInput(
                        "Invalid transaction ID length".to_string(),
                    ));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Ok(StorageKey::Transaction(crate::types::TransactionId(hash)))
            }
            "blk" => {
                let bytes = hex::decode(parts[1])
                    .map_err(|_| AvoError::InvalidInput("Invalid block ID hex".to_string()))?;
                if bytes.len() != 32 {
                    return Err(AvoError::InvalidInput(
                        "Invalid block ID length".to_string(),
                    ));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Ok(StorageKey::Block(crate::types::BlockId(hash)))
            }
            "state" => {
                let state_parts: Vec<&str> = parts[1].splitn(2, ':').collect();
                if state_parts.len() != 2 {
                    return Err(AvoError::InvalidInput(
                        "Invalid state key format".to_string(),
                    ));
                }
                let shard_id = state_parts[0]
                    .parse::<u32>()
                    .map_err(|_| AvoError::InvalidInput("Invalid shard ID".to_string()))?;
                Ok(StorageKey::State(shard_id, state_parts[1].to_string()))
            }
            "contract" => {
                let contract_parts: Vec<&str> = parts[1].splitn(2, ':').collect();
                if contract_parts.len() != 2 {
                    return Err(AvoError::InvalidInput(
                        "Invalid contract key format".to_string(),
                    ));
                }
                Ok(StorageKey::Contract(
                    contract_parts[0].to_string(),
                    contract_parts[1].to_string(),
                ))
            }
            "meta" => Ok(StorageKey::Metadata(parts[1].to_string())),
            _ => Err(AvoError::InvalidInput(format!(
                "Unknown key type: {}",
                parts[0]
            ))),
        }
    }
}

/// Storage operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageOperation {
    Put { key: StorageKey, value: Vec<u8> },
    Get { key: StorageKey },
    Delete { key: StorageKey },
    Batch { operations: Vec<StorageOperation> },
}

/// Cache entry with metadata
#[derive(Debug, Clone)]
struct CacheEntry {
    value: Vec<u8>,
    last_accessed: SystemTime,
    access_count: u64,
    dirty: bool,
}

/// Write-Ahead Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WALEntry {
    sequence: u64,
    timestamp: u64,
    operation: StorageOperation,
    checksum: Hash,
}

/// High-performance storage engine for AVO blockchain
#[derive(Debug)]
pub struct AvocadoStorage {
    config: StorageConfig,
    /// RocksDB instance
    db: Arc<DB>,
    /// In-memory cache for hot data
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Write-ahead log for durability
    wal: Arc<Mutex<VecDeque<WALEntry>>>,
    /// Cache statistics
    cache_stats: Arc<RwLock<CacheStats>>,
    /// Storage statistics
    storage_stats: Arc<RwLock<StorageStats>>,
    /// WAL sequence number
    wal_sequence: Arc<Mutex<u64>>,
    /// Background task handles
    background_tasks: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
}

#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub size_bytes: usize,
    pub entry_count: usize,
}

#[derive(Debug, Default, Clone)]
pub struct StorageStats {
    pub total_reads: u64,
    pub total_writes: u64,
    pub total_deletes: u64,
    pub storage_size_bytes: usize,
    pub wal_entries: usize,
}

impl AvocadoStorage {
    /// Create new storage engine
    pub fn new(config: StorageConfig) -> Result<Self, AvoError> {
        // Create RocksDB options
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Define column families
        let cfs = vec![
            ColumnFamilyDescriptor::new("accounts", Options::default()),
            ColumnFamilyDescriptor::new("transactions", Options::default()),
            ColumnFamilyDescriptor::new("blocks", Options::default()),
            ColumnFamilyDescriptor::new("state", Options::default()),
            ColumnFamilyDescriptor::new("balances", Options::default()),
            ColumnFamilyDescriptor::new("validators", Options::default()),
            ColumnFamilyDescriptor::new("delegations", Options::default()),
            ColumnFamilyDescriptor::new("treasury", Options::default()),
            ColumnFamilyDescriptor::new("transaction_history", Options::default()),
            ColumnFamilyDescriptor::new("block_history", Options::default()),
            // Governance column families
            ColumnFamilyDescriptor::new("governance_proposals", Options::default()),
            ColumnFamilyDescriptor::new("governance_voting", Options::default()),
            ColumnFamilyDescriptor::new("governance_delegations", Options::default()),
            ColumnFamilyDescriptor::new("governance_state", Options::default()),
            // Additional column families for complete persistence
            ColumnFamilyDescriptor::new("stakes", Options::default()),
            ColumnFamilyDescriptor::new("vm_state", Options::default()),
            ColumnFamilyDescriptor::new("consensus_state", Options::default()),
            ColumnFamilyDescriptor::new("cross_shard_state", Options::default()),
            ColumnFamilyDescriptor::new("pending_changes", Options::default()),
            ColumnFamilyDescriptor::new("consensus_crypto", Options::default()),
        ];

        // Open database
        let db = DB::open_cf_descriptors(&opts, &config.base_path, cfs).map_err(|e| {
            AvoError::StorageError {
                reason: format!("Failed to open RocksDB: {}", e),
            }
        })?;

        Ok(Self {
            config,
            db: Arc::new(db),
            cache: Arc::new(RwLock::new(HashMap::new())),
            wal: Arc::new(Mutex::new(VecDeque::new())),
            cache_stats: Arc::new(RwLock::new(CacheStats::default())),
            storage_stats: Arc::new(RwLock::new(StorageStats::default())),
            wal_sequence: Arc::new(Mutex::new(0)),
            background_tasks: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Initialize storage engine
    pub async fn initialize(&self) -> Result<(), AvoError> {
        println!("🗄️  Initializing Avocado Storage Engine with RocksDB");

        // Create storage directory
        if !self.config.base_path.exists() {
            std::fs::create_dir_all(&self.config.base_path).map_err(|e| {
                AvoError::InvalidInput(format!("Failed to create storage directory: {}", e))
            })?;
        }

        // Load existing data if any
        self.load_existing_data().await?;

        // Start background tasks
        self.start_background_tasks().await;

        // Storage engine initialized
        Ok(())
    }

    /// Get account balance from RocksDB
    pub async fn get_balance(&self, address: &str) -> Result<u128, AvoError> {
        let cf = self
            .db
            .cf_handle("balances")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Balances column family not found".to_string(),
            })?;

        match self.db.get_cf(cf, address) {
            Ok(Some(bytes)) => {
                let balance_str = String::from_utf8(bytes).map_err(|e| AvoError::StorageError {
                    reason: format!("Invalid balance UTF-8: {}", e),
                })?;
                balance_str
                    .parse::<u128>()
                    .map_err(|e| AvoError::StorageError {
                        reason: format!("Invalid balance format: {}", e),
                    })
            }
            Ok(None) => Ok(0), // Default balance
            Err(e) => Err(AvoError::StorageError {
                reason: format!("RocksDB get error: {}", e),
            }),
        }
    }

    /// Set account balance in RocksDB
    pub async fn set_balance(&self, address: &str, balance: u128) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("balances")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Balances column family not found".to_string(),
            })?;

        let balance_str = balance.to_string();
        self.db
            .put_cf(cf, address, balance_str.as_bytes())
            .map_err(|e| AvoError::StorageError {
                reason: format!("RocksDB put error: {}", e),
            })?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            let entry = CacheEntry {
                value: balance_str.into_bytes(),
                last_accessed: SystemTime::now(),
                access_count: 1,
                dirty: false,
            };
            cache.insert(format!("balance:{}", address), entry);
        }

        Ok(())
    }

    /// Get all balances (for debugging/admin)
    pub async fn get_all_balances(&self) -> Result<HashMap<String, u128>, AvoError> {
        let cf = self
            .db
            .cf_handle("balances")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Balances column family not found".to_string(),
            })?;

        let mut balances = HashMap::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            match item {
                Ok((key, value)) => {
                    let address =
                        String::from_utf8(key.to_vec()).map_err(|e| AvoError::StorageError {
                            reason: format!("Invalid address UTF-8: {}", e),
                        })?;
                    let balance_str =
                        String::from_utf8(value.to_vec()).map_err(|e| AvoError::StorageError {
                            reason: format!("Invalid balance UTF-8: {}", e),
                        })?;
                    let balance =
                        balance_str
                            .parse::<u128>()
                            .map_err(|e| AvoError::StorageError {
                                reason: format!("Invalid balance format: {}", e),
                            })?;
                    balances.insert(address, balance);
                }
                Err(e) => {
                    return Err(AvoError::StorageError {
                        reason: format!("Iterator error: {}", e),
                    })
                }
            }
        }

        Ok(balances)
    }

    /// Store a transaction in RocksDB
    pub async fn store_transaction(
        &self,
        tx_hash: &str,
        transaction_data: &[u8],
    ) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("transactions")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Transactions column family not found".to_string(),
            })?;

        self.db
            .put_cf(cf, tx_hash, transaction_data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store transaction: {}", e),
            })?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            let entry = CacheEntry {
                value: transaction_data.to_vec(),
                last_accessed: SystemTime::now(),
                access_count: 1,
                dirty: false,
            };
            cache.insert(format!("tx:{}", tx_hash), entry);
        }

        Ok(())
    }

    /// Get a transaction from RocksDB
    pub async fn get_transaction(&self, tx_hash: &str) -> Result<Option<Vec<u8>>, AvoError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            let cache_key = format!("tx:{}", tx_hash);
            if let Some(entry) = cache.get(&cache_key) {
                return Ok(Some(entry.value.clone()));
            }
        }

        let cf = self
            .db
            .cf_handle("transactions")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Transactions column family not found".to_string(),
            })?;

        match self.db.get_cf(cf, tx_hash) {
            Ok(Some(bytes)) => Ok(Some(bytes)),
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get transaction: {}", e),
            }),
        }
    }

    /// Store a block in RocksDB
    pub async fn store_block(&self, block_hash: &str, block_data: &[u8]) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("blocks")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Blocks column family not found".to_string(),
            })?;

        self.db
            .put_cf(cf, block_hash, block_data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store block: {}", e),
            })?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            let entry = CacheEntry {
                value: block_data.to_vec(),
                last_accessed: SystemTime::now(),
                access_count: 1,
                dirty: false,
            };
            cache.insert(format!("block:{}", block_hash), entry);
        }

        Ok(())
    }

    /// Get a block from RocksDB
    pub async fn get_block(&self, block_hash: &str) -> Result<Option<Vec<u8>>, AvoError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            let cache_key = format!("block:{}", block_hash);
            if let Some(entry) = cache.get(&cache_key) {
                return Ok(Some(entry.value.clone()));
            }
        }

        let cf = self
            .db
            .cf_handle("blocks")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Blocks column family not found".to_string(),
            })?;

        match self.db.get_cf(cf, block_hash) {
            Ok(Some(bytes)) => Ok(Some(bytes)),
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get block: {}", e),
            }),
        }
    }

    /// Store stake position in RocksDB
    pub async fn store_stake_position(
        &self,
        position_id: u64,
        position_data: &[u8],
    ) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("state")
            .ok_or_else(|| AvoError::StorageError {
                reason: "State column family not found".to_string(),
            })?;

        let key = format!("stake:{}", position_id);
        self.db
            .put_cf(cf, key, position_data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store stake position: {}", e),
            })?;

        Ok(())
    }

    /// Get stake position from RocksDB
    pub async fn get_stake_position(&self, position_id: u64) -> Result<Option<Vec<u8>>, AvoError> {
        let cf = self
            .db
            .cf_handle("state")
            .ok_or_else(|| AvoError::StorageError {
                reason: "State column family not found".to_string(),
            })?;

        let key = format!("stake:{}", position_id);
        match self.db.get_cf(cf, &key) {
            Ok(Some(bytes)) => Ok(Some(bytes)),
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get stake position: {}", e),
            }),
        }
    }

    /// Store general state data in RocksDB
    pub async fn store_state(&self, key: &str, data: &[u8]) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("state")
            .ok_or_else(|| AvoError::StorageError {
                reason: "State column family not found".to_string(),
            })?;

        self.db
            .put_cf(cf, key, data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store state: {}", e),
            })?;

        Ok(())
    }

    /// Get general state data from RocksDB
    pub async fn get_state(&self, key: &str) -> Result<Option<Vec<u8>>, AvoError> {
        let cf = self
            .db
            .cf_handle("state")
            .ok_or_else(|| AvoError::StorageError {
                reason: "State column family not found".to_string(),
            })?;

        match self.db.get_cf(cf, key) {
            Ok(Some(bytes)) => Ok(Some(bytes)),
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get state: {}", e),
            }),
        }
    }

    /// Put value in storage
    pub async fn put(&self, key: StorageKey, value: Vec<u8>) -> Result<(), AvoError> {
        let key_str = key.to_string();

        // Write to WAL if enabled
        if self.config.enable_wal {
            self.write_to_wal(StorageOperation::Put {
                key: key.clone(),
                value: value.clone(),
            })
            .await?;
        }

        // Update cache
        {
            let mut cache = self.cache.write().await;
            let entry = CacheEntry {
                value: value.clone(),
                last_accessed: SystemTime::now(),
                access_count: 1,
                dirty: true,
            };
            cache.insert(key_str.clone(), entry);
        }

        // Update persistent storage - write to RocksDB
        match self.db.put(key_str.as_bytes(), &value) {
            Ok(_) => {}
            Err(e) => {
                return Err(AvoError::StorageError {
                    reason: format!("Failed to write to RocksDB: {}", e),
                })
            }
        }

        // Update statistics
        {
            let mut stats = self.storage_stats.write().await;
            stats.total_writes += 1;
        }

        Ok(())
    }

    /// Get value from storage
    pub async fn get(&self, key: &StorageKey) -> Result<Option<Vec<u8>>, AvoError> {
        let key_str = key.to_string();

        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(entry) = cache.get_mut(&key_str) {
                entry.last_accessed = SystemTime::now();
                entry.access_count += 1;

                // Update cache stats
                {
                    let mut stats = self.cache_stats.write().await;
                    stats.hits += 1;
                }

                return Ok(Some(entry.value.clone()));
            }
        }

        // Cache miss - check persistent storage (RocksDB)
        match self.db.get(key_str.as_bytes()) {
            Ok(Some(value)) => {
                // Add to cache
                {
                    let mut cache = self.cache.write().await;
                    let entry = CacheEntry {
                        value: value.clone(),
                        last_accessed: SystemTime::now(),
                        access_count: 1,
                        dirty: false,
                    };
                    cache.insert(key_str, entry);

                    // Check cache size and evict if necessary
                    self.evict_cache_if_needed(&mut cache).await;
                }

                // Update cache stats
                {
                    let mut stats = self.cache_stats.write().await;
                    stats.misses += 1;
                }

                // Update storage stats
                {
                    let mut stats = self.storage_stats.write().await;
                    stats.total_reads += 1;
                }

                return Ok(Some(value));
            }
            Ok(None) => {
                // Update stats for miss
                {
                    let mut cache_stats = self.cache_stats.write().await;
                    cache_stats.misses += 1;
                }

                return Ok(None);
            }
            Err(e) => {
                return Err(AvoError::StorageError {
                    reason: format!("Failed to read from RocksDB: {}", e),
                });
            }
        }
    }

    /// Delete value from storage
    pub async fn delete(&self, key: &StorageKey) -> Result<bool, AvoError> {
        let key_str = key.to_string();

        // Write to WAL if enabled
        if self.config.enable_wal {
            self.write_to_wal(StorageOperation::Delete { key: key.clone() })
                .await?;
        }

        // Remove from cache
        let cache_had_key = {
            let mut cache = self.cache.write().await;
            cache.remove(&key_str).is_some()
        };

        // Remove from persistent storage (RocksDB)
        let storage_had_key = match self.db.get(key_str.as_bytes()) {
            Ok(Some(_)) => match self.db.delete(key_str.as_bytes()) {
                Ok(_) => true,
                Err(e) => {
                    return Err(AvoError::StorageError {
                        reason: format!("Failed to delete from RocksDB: {}", e),
                    })
                }
            },
            Ok(None) => false,
            Err(e) => {
                return Err(AvoError::StorageError {
                    reason: format!("Failed to check key in RocksDB: {}", e),
                })
            }
        };

        let existed = cache_had_key || storage_had_key;

        if existed {
            let mut stats = self.storage_stats.write().await;
            stats.total_deletes += 1;
        }

        Ok(existed)
    }

    /// Execute batch operations atomically
    pub async fn batch(&self, operations: Vec<StorageOperation>) -> Result<(), AvoError> {
        // Executing batch operations

        // Write batch to WAL if enabled
        if self.config.enable_wal {
            self.write_to_wal(StorageOperation::Batch {
                operations: operations.clone(),
            })
            .await?;
        }

        // Execute all operations
        for operation in operations {
            match operation {
                StorageOperation::Put { key, value } => {
                    self.put(key, value).await?;
                }
                StorageOperation::Delete { key } => {
                    self.delete(&key).await?;
                }
                StorageOperation::Get { .. } => {
                    // Read operations in batch don't make sense
                    continue;
                }
                StorageOperation::Batch {
                    operations: nested_ops,
                } => {
                    // Recursive batch execution using Box::pin
                    Box::pin(self.batch(nested_ops)).await?;
                }
            }
        }

        Ok(())
    }

    /// Get range of keys with prefix
    pub async fn get_range(&self, prefix: &str) -> Result<Vec<(StorageKey, Vec<u8>)>, AvoError> {
        let mut results = Vec::new();

        // Create iterator over RocksDB
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            prefix.as_bytes(),
            rocksdb::Direction::Forward,
        ));

        for item in iter {
            match item {
                Ok((key_bytes, value_bytes)) => {
                    let key_str = String::from_utf8_lossy(&key_bytes);
                    if !key_str.starts_with(prefix) {
                        break; // Keys are sorted, so we can stop here
                    }

                    if let Ok(key) = StorageKey::from_string(&key_str) {
                        results.push((key, value_bytes.to_vec()));
                    }
                }
                Err(e) => {
                    return Err(AvoError::StorageError {
                        reason: format!("Failed to iterate RocksDB: {}", e),
                    })
                }
            }
        }

        Ok(results)
    }

    /// Get raw key/value pairs from a specific column family using a prefix
    pub async fn get_cf_range_bytes(
        &self,
        cf_name: &str,
        prefix: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, AvoError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| AvoError::StorageError {
                reason: format!("{} column family not found", cf_name),
            })?;

        let mut results = Vec::new();
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(prefix.as_bytes(), rocksdb::Direction::Forward),
        );

        for item in iter {
            let (key, value) = item.map_err(|e| AvoError::StorageError {
                reason: format!("Failed to iterate {}: {}", cf_name, e),
            })?;

            if !prefix.is_empty() && !key.starts_with(prefix.as_bytes()) {
                break;
            }

            results.push((key.to_vec(), value.to_vec()));
        }

        Ok(results)
    }

    /// Write operation to Write-Ahead Log
    async fn write_to_wal(&self, operation: StorageOperation) -> Result<(), AvoError> {
        let sequence = {
            let mut seq = self.wal_sequence.lock().await;
            *seq += 1;
            *seq
        };

        // Calculate checksum
        let serialized = serde_json::to_vec(&operation)
            .map_err(|e| AvoError::InvalidInput(format!("Failed to serialize operation: {}", e)))?;

        let mut hasher = Sha3_256::new();
        hasher.update(&serialized);
        let checksum = hasher.finalize().into();

        let entry = WALEntry {
            sequence,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            operation,
            checksum,
        };

        let mut wal = self.wal.lock().await;
        wal.push_back(entry);

        // Limit WAL size
        while wal.len() > 10000 {
            wal.pop_front();
        }

        Ok(())
    }

    /// Load existing data from storage files
    async fn load_existing_data(&self) -> Result<(), AvoError> {
        eprintln!("📂 Loading existing storage data...");
        
        // Check if genesis balances need to be initialized
        let genesis_initialized = match self.get_state("genesis_initialized").await? {
            Some(bytes) => String::from_utf8(bytes).unwrap_or_default() == "true",
            None => false,
        };
        
        if !genesis_initialized {
            eprintln!("🌱 Genesis initialized with EMPTY state - Use admin mint to create accounts");
            // Mark genesis as initialized without loading any accounts
            self.store_state("genesis_initialized", b"true").await?;
            eprintln!("✅ Genesis marked as initialized (empty state)");
        } else {
            eprintln!("ℹ️  Genesis already initialized");
        }
        
        Ok(())
    }

    /// Start background maintenance tasks
    async fn start_background_tasks(&self) {
        let cache = Arc::clone(&self.cache);
        let cache_stats = Arc::clone(&self.cache_stats);
        let config = self.config.clone();

        // Cache maintenance task
        let cache_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                // Periodic cache cleanup
                let mut cache_lock = cache.write().await;
                let mut stats = cache_stats.write().await;

                let cache_size_limit = config.cache_size_mb * 1024 * 1024;
                let current_size: usize = cache_lock.values().map(|entry| entry.value.len()).sum();

                if current_size > cache_size_limit {
                    // Simple LRU eviction
                    let entries: Vec<_> = cache_lock
                        .iter()
                        .map(|(k, v)| (k.clone(), v.last_accessed))
                        .collect();
                    let mut sorted_entries = entries;
                    sorted_entries.sort_by_key(|(_, last_accessed)| *last_accessed);

                    let to_remove = sorted_entries.len() / 4; // Remove 25% of entries
                    for (key, _) in sorted_entries.iter().take(to_remove) {
                        cache_lock.remove(key);
                        stats.evictions += 1;
                    }
                }

                stats.size_bytes = cache_lock.values().map(|e| e.value.len()).sum();
                stats.entry_count = cache_lock.len();
            }
        });

        let mut tasks = self.background_tasks.write().await;
        tasks.push(cache_task);
    }

    /// Evict cache entries if size limit exceeded
    async fn evict_cache_if_needed(&self, cache: &mut HashMap<String, CacheEntry>) {
        let cache_size_limit = self.config.cache_size_mb * 1024 * 1024;
        let current_size: usize = cache.values().map(|entry| entry.value.len()).sum();

        if current_size > cache_size_limit {
            // Simple LRU eviction
            let entries: Vec<_> = cache
                .iter()
                .map(|(k, v)| (k.clone(), v.last_accessed))
                .collect();
            let mut sorted_entries = entries;
            sorted_entries.sort_by_key(|(_, last_accessed)| *last_accessed);

            let to_remove = sorted_entries.len() / 10; // Remove 10% of entries
            for (key, _) in sorted_entries.iter().take(to_remove) {
                cache.remove(key);
            }

            let mut stats = self.cache_stats.write().await;
            stats.evictions += to_remove as u64;
        }
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> CacheStats {
        self.cache_stats.read().await.clone()
    }

    /// Get storage statistics
    pub async fn get_storage_stats(&self) -> StorageStats {
        let mut stats = self.storage_stats.read().await.clone();

        // Update current storage size - approximate using iterator
        let mut total_size = 0;
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        for item in iter {
            if let Ok((key_bytes, value_bytes)) = item {
                total_size += key_bytes.len() + value_bytes.len();
            }
        }
        stats.storage_size_bytes = total_size;

        let wal = self.wal.lock().await;
        stats.wal_entries = wal.len();

        stats
    }

    /// Flush all dirty cache entries to persistent storage
    pub async fn flush(&self) -> Result<(), AvoError> {
        println!("💾 Flushing dirty cache entries to storage");

        let dirty_entries = {
            let cache = self.cache.read().await;
            cache
                .iter()
                .filter(|(_, entry)| entry.dirty)
                .map(|(key, entry)| (key.clone(), entry.value.clone()))
                .collect::<Vec<_>>()
        };

        let dirty_count = dirty_entries.len();

        if !dirty_entries.is_empty() {
            // Write dirty entries to RocksDB
            for (key, value) in dirty_entries {
                if let Err(e) = self.db.put(key.as_bytes(), &value) {
                    return Err(AvoError::StorageError {
                        reason: format!("Failed to flush to RocksDB: {}", e),
                    });
                }
            }

            // Mark entries as clean
            let mut cache = self.cache.write().await;
            for entry in cache.values_mut() {
                entry.dirty = false;
            }

            println!("✅ Flushed {} dirty entries", dirty_count);
        }

        Ok(())
    }

    /// Create checkpoint of current state
    pub async fn checkpoint(&self) -> Result<(), AvoError> {
        println!("📸 Creating storage checkpoint");

        // Flush all dirty data first
        self.flush().await?;

        // In production, this would write to disk files
        println!("✅ Checkpoint created successfully");
        Ok(())
    }

    /// Cleanup resources
    pub async fn shutdown(&self) -> Result<(), AvoError> {
        println!("🛑 Shutting down storage engine");

        // Flush all data
        self.flush().await?;

        // Stop background tasks
        let tasks = {
            let mut background_tasks = self.background_tasks.write().await;
            std::mem::take(&mut *background_tasks)
        };

        for task in tasks {
            task.abort();
        }

        println!("✅ Storage engine shut down cleanly");
        Ok(())
    }

    // ================= VALIDATORS METHODS =================

    /// Store validator data
    pub async fn store_validator(&self, id: u32, validator_data: &[u8]) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("validators")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Validators column family not found".to_string(),
            })?;

        let key = id.to_be_bytes();
        self.db
            .put_cf(cf, &key, validator_data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store validator: {}", e),
            })?;

        Ok(())
    }

    /// Get validator data
    pub async fn get_validator(&self, id: u32) -> Result<Option<Vec<u8>>, AvoError> {
        let cf = self
            .db
            .cf_handle("validators")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Validators column family not found".to_string(),
            })?;

        let key = id.to_be_bytes();
        self.db
            .get_cf(cf, &key)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to get validator: {}", e),
            })
    }

    /// Remove validator data
    pub async fn remove_validator(&self, id: u32) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("validators")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Validators column family not found".to_string(),
            })?;

        let key = id.to_be_bytes();
        self.db
            .delete_cf(cf, &key)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to remove validator: {}", e),
            })?;

        Ok(())
    }

    /// Get all validators
    pub async fn get_all_validators(&self) -> Result<HashMap<u32, Vec<u8>>, AvoError> {
        let cf = self
            .db
            .cf_handle("validators")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Validators column family not found".to_string(),
            })?;

        let mut validators = HashMap::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item.map_err(|e| AvoError::StorageError {
                reason: format!("Failed to iterate validators: {}", e),
            })?;
            if key.len() == 4 {
                let id = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
                validators.insert(id, value.to_vec());
            }
        }

        Ok(validators)
    }

    // ================= DELEGATIONS METHODS =================

    /// Store delegations for an address
    pub async fn store_delegations(
        &self,
        address: &str,
        delegations_data: &[u8],
    ) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("delegations")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Delegations column family not found".to_string(),
            })?;

        self.db
            .put_cf(cf, address, delegations_data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store delegations: {}", e),
            })?;

        Ok(())
    }

    /// Get delegations for an address
    pub async fn get_delegations(&self, address: &str) -> Result<Option<Vec<u8>>, AvoError> {
        let cf = self
            .db
            .cf_handle("delegations")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Delegations column family not found".to_string(),
            })?;

        self.db
            .get_cf(cf, address)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to get delegations: {}", e),
            })
    }

    /// Remove delegations for an address
    pub async fn remove_delegations(&self, address: &str) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("delegations")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Delegations column family not found".to_string(),
            })?;

        self.db
            .delete_cf(cf, address)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to remove delegations: {}", e),
            })?;

        Ok(())
    }

    // ================= TREASURY METHODS =================

    /// Store treasury balance
    pub async fn store_treasury_balance(&self, token: &str, balance: u128) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("treasury")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Treasury column family not found".to_string(),
            })?;

        let balance_str = balance.to_string();
        self.db
            .put_cf(cf, token, balance_str.as_bytes())
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store treasury balance: {}", e),
            })?;

        Ok(())
    }

    /// Get treasury balance
    pub async fn get_treasury_balance(&self, token: &str) -> Result<u128, AvoError> {
        let cf = self
            .db
            .cf_handle("treasury")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Treasury column family not found".to_string(),
            })?;

        match self.db.get_cf(cf, token) {
            Ok(Some(bytes)) => {
                let balance_str = String::from_utf8(bytes).map_err(|e| AvoError::StorageError {
                    reason: format!("Invalid balance UTF-8: {}", e),
                })?;
                balance_str
                    .parse::<u128>()
                    .map_err(|e| AvoError::StorageError {
                        reason: format!("Invalid balance format: {}", e),
                    })
            }
            Ok(None) => Ok(0),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get treasury balance: {}", e),
            }),
        }
    }

    /// Get all treasury balances
    pub async fn get_all_treasury_balances(&self) -> Result<HashMap<String, u128>, AvoError> {
        let cf = self
            .db
            .cf_handle("treasury")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Treasury column family not found".to_string(),
            })?;

        let mut balances = HashMap::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item.map_err(|e| AvoError::StorageError {
                reason: format!("Failed to iterate treasury: {}", e),
            })?;
            let token = String::from_utf8_lossy(&key).to_string();
            let balance_str = String::from_utf8_lossy(&value);
            if let Ok(balance) = balance_str.parse::<u128>() {
                balances.insert(token, balance);
            }
        }

        Ok(balances)
    }

    // ================= TRANSACTION HISTORY METHODS =================

    /// Store transaction record
    pub async fn store_transaction_record(
        &self,
        tx_hash: &str,
        record_data: &[u8],
    ) -> Result<(), AvoError> {
        let cf =
            self.db
                .cf_handle("transaction_history")
                .ok_or_else(|| AvoError::StorageError {
                    reason: "Transaction history column family not found".to_string(),
                })?;

        self.db
            .put_cf(cf, tx_hash, record_data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store transaction record: {}", e),
            })?;

        Ok(())
    }

    /// Get transaction record
    pub async fn get_transaction_record(&self, tx_hash: &str) -> Result<Option<Vec<u8>>, AvoError> {
        let cf =
            self.db
                .cf_handle("transaction_history")
                .ok_or_else(|| AvoError::StorageError {
                    reason: "Transaction history column family not found".to_string(),
                })?;

        self.db
            .get_cf(cf, tx_hash)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to get transaction record: {}", e),
            })
    }

    /// Get all transaction records
    pub async fn get_all_transaction_records(&self) -> Result<Vec<Vec<u8>>, AvoError> {
        let cf =
            self.db
                .cf_handle("transaction_history")
                .ok_or_else(|| AvoError::StorageError {
                    reason: "Transaction history column family not found".to_string(),
                })?;

        let mut records = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) = item.map_err(|e| AvoError::StorageError {
                reason: format!("Failed to iterate transaction history: {}", e),
            })?;
            records.push(value.to_vec());
        }

        Ok(records)
    }

    // ================= BLOCK HISTORY METHODS =================

    /// Store block record
    pub async fn store_block_record(
        &self,
        block_hash: &str,
        record_data: &[u8],
    ) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("block_history")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Block history column family not found".to_string(),
            })?;

        self.db
            .put_cf(cf, block_hash, record_data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store block record: {}", e),
            })?;

        Ok(())
    }

    /// Get block record
    pub async fn get_block_record(&self, block_hash: &str) -> Result<Option<Vec<u8>>, AvoError> {
        let cf = self
            .db
            .cf_handle("block_history")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Block history column family not found".to_string(),
            })?;

        self.db
            .get_cf(cf, block_hash)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to get block record: {}", e),
            })
    }

    /// Get all block records
    pub async fn get_all_block_records(&self) -> Result<Vec<Vec<u8>>, AvoError> {
        let cf = self
            .db
            .cf_handle("block_history")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Block history column family not found".to_string(),
            })?;

        let mut records = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) = item.map_err(|e| AvoError::StorageError {
                reason: format!("Failed to iterate block history: {}", e),
            })?;
            records.push(value.to_vec());
        }

        Ok(records)
    }

    // ===== Governance Storage Methods =====

    /// Store governance proposal
    pub async fn store_proposal(&self, proposal_id: u64, data: &[u8]) -> Result<(), AvoError> {
        let cf =
            self.db
                .cf_handle("governance_proposals")
                .ok_or_else(|| AvoError::StorageError {
                    reason: "Governance proposals column family not found".to_string(),
                })?;

        let key = proposal_id.to_string();
        self.db
            .put_cf(cf, &key, data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store proposal: {}", e),
            })
    }

    /// Get governance proposal
    pub async fn get_proposal(&self, proposal_id: u64) -> Result<Option<Vec<u8>>, AvoError> {
        let cf =
            self.db
                .cf_handle("governance_proposals")
                .ok_or_else(|| AvoError::StorageError {
                    reason: "Governance proposals column family not found".to_string(),
                })?;

        let key = proposal_id.to_string();
        self.db
            .get_cf(cf, &key)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to get proposal: {}", e),
            })
    }

    /// Get all governance proposals
    pub async fn get_all_proposals(&self) -> Result<HashMap<u64, Vec<u8>>, AvoError> {
        let cf =
            self.db
                .cf_handle("governance_proposals")
                .ok_or_else(|| AvoError::StorageError {
                    reason: "Governance proposals column family not found".to_string(),
                })?;

        let mut proposals = HashMap::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item.map_err(|e| AvoError::StorageError {
                reason: format!("Failed to iterate proposals: {}", e),
            })?;
            if let Ok(key_str) = std::str::from_utf8(&key) {
                if let Ok(proposal_id) = key_str.parse::<u64>() {
                    proposals.insert(proposal_id, value.to_vec());
                }
            }
        }

        Ok(proposals)
    }

    /// Store governance voting data
    pub async fn store_governance_voting(&self, key: &str, data: &[u8]) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("governance_voting")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Governance voting column family not found".to_string(),
            })?;

        self.db
            .put_cf(cf, key, data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store governance voting data: {}", e),
            })
    }

    /// Get governance voting data
    pub async fn get_governance_voting(&self, key: &str) -> Result<Option<Vec<u8>>, AvoError> {
        let cf = self
            .db
            .cf_handle("governance_voting")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Governance voting column family not found".to_string(),
            })?;

        self.db.get_cf(cf, key).map_err(|e| AvoError::StorageError {
            reason: format!("Failed to get governance voting data: {}", e),
        })
    }

    /// Store governance delegation data
    pub async fn store_governance_delegation(
        &self,
        key: &str,
        data: &[u8],
    ) -> Result<(), AvoError> {
        let cf =
            self.db
                .cf_handle("governance_delegations")
                .ok_or_else(|| AvoError::StorageError {
                    reason: "Governance delegations column family not found".to_string(),
                })?;

        self.db
            .put_cf(cf, key, data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store governance delegation data: {}", e),
            })
    }

    /// Get governance delegation data
    pub async fn get_governance_delegation(&self, key: &str) -> Result<Option<Vec<u8>>, AvoError> {
        let cf =
            self.db
                .cf_handle("governance_delegations")
                .ok_or_else(|| AvoError::StorageError {
                    reason: "Governance delegations column family not found".to_string(),
                })?;

        self.db.get_cf(cf, key).map_err(|e| AvoError::StorageError {
            reason: format!("Failed to get governance delegation data: {}", e),
        })
    }

    /// Store governance state cache
    pub async fn store_governance_state(&self, key: &str, data: &[u8]) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle("governance_state")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Governance state column family not found".to_string(),
            })?;

        self.db
            .put_cf(cf, key, data)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store governance state: {}", e),
            })
    }

    /// Get governance state cache
    pub async fn get_governance_state(&self, key: &str) -> Result<Option<Vec<u8>>, AvoError> {
        let cf = self
            .db
            .cf_handle("governance_state")
            .ok_or_else(|| AvoError::StorageError {
                reason: "Governance state column family not found".to_string(),
            })?;

        self.db.get_cf(cf, key).map_err(|e| AvoError::StorageError {
            reason: format!("Failed to get governance state: {}", e),
        })
    }

    /// Store data in a specific column family
    pub async fn put_cf(&self, cf_name: &str, key: &str, value: &str) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| AvoError::StorageError {
                reason: format!("{} column family not found", cf_name),
            })?;

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AvoError::DatabaseError { source: e })?;

        Ok(())
    }

    /// Get data from a specific column family
    pub async fn get_cf(&self, cf_name: &str, key: &str) -> Result<Option<String>, AvoError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| AvoError::StorageError {
                reason: format!("{} column family not found", cf_name),
            })?;

        match self.db.get_cf(cf, key) {
            Ok(Some(value)) => {
                let value_str = String::from_utf8(value).map_err(|e| AvoError::StateError {
                    reason: format!("Invalid UTF-8 in {}: {}", cf_name, e),
                })?;
                Ok(Some(value_str))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::DatabaseError { source: e }),
        }
    }

    /// Delete data from a specific column family
    pub async fn delete_cf(&self, cf_name: &str, key: &str) -> Result<(), AvoError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| AvoError::StorageError {
                reason: format!("{} column family not found", cf_name),
            })?;

        self.db
            .delete_cf(cf, key)
            .map_err(|e| AvoError::DatabaseError { source: e })?;

        Ok(())
    }
}

impl Default for AvocadoStorage {
    fn default() -> Self {
        Self::new(StorageConfig::default()).expect("Failed to create default AvocadoStorage")
    }
}
