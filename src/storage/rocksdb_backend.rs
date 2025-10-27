/// RocksDB Backend - Complete persistent storage implementation
///
/// This module provides a production-ready RocksDB backend with:
/// - Column families for different data types
/// - Write-Ahead Log (WAL) for atomicity
/// - Batch operations
/// - Checkpointing
/// - Crash recovery
use crate::error::{AvoError, AvoResult};
use crate::types::{Address, Block, BlockId, Hash, ShardId, Transaction, TransactionId};
use rocksdb::{
    checkpoint::Checkpoint, ColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, IteratorMode,
    Options, SingleThreaded, WriteBatch, DB,
};
use std::path::Path;
use std::sync::Arc;

/// Column family names
pub const CF_BLOCKS: &str = "blocks";
pub const CF_TRANSACTIONS: &str = "transactions";
pub const CF_STATE: &str = "state";
pub const CF_ACCOUNTS: &str = "accounts";
pub const CF_VALIDATORS: &str = "validators";
pub const CF_CHECKPOINTS: &str = "checkpoints";
pub const CF_METADATA: &str = "metadata";

/// Account data stored in RocksDB
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredAccount {
    pub address: Address,
    pub balance: u128,
    pub nonce: u64,
    pub code_hash: Option<Hash>,
    pub storage_root: Option<Hash>,
}

/// RocksDB Backend with column families
#[derive(Debug)]
pub struct RocksDBBackend {
    db: Arc<DB>,
    shard_id: ShardId,
}

impl RocksDBBackend {
    /// Create a new RocksDB backend
    pub fn new<P: AsRef<Path>>(path: P, shard_id: ShardId) -> AvoResult<Self> {
        let path = path.as_ref();

        // Create options
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        // Enable WAL for crash recovery
        db_opts.set_use_fsync(false);
        db_opts.set_wal_bytes_per_sync(1024 * 1024); // 1MB

        // Performance tuning
        db_opts.set_max_open_files(10000);
        db_opts.set_keep_log_file_num(10);
        db_opts.set_max_background_jobs(4);
        db_opts.increase_parallelism(num_cpus::get() as i32);

        // Define column families
        let cf_names = vec![
            CF_BLOCKS,
            CF_TRANSACTIONS,
            CF_STATE,
            CF_ACCOUNTS,
            CF_VALIDATORS,
            CF_CHECKPOINTS,
            CF_METADATA,
        ];

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = cf_names
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_max_write_buffer_number(16);
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        // Open database with column families
        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors).map_err(|e| {
            AvoError::StorageError {
                reason: format!("Failed to open RocksDB: {}", e),
            }
        })?;

        Ok(Self {
            db: Arc::new(db),
            shard_id,
        })
    }

    /// Get column family handle
    fn cf_handle(&self, name: &str) -> AvoResult<&ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| AvoError::StorageError {
                reason: format!("Column family '{}' not found", name),
            })
    }

    // ==================== BLOCK OPERATIONS ====================

    /// Store a block
    pub fn store_block(&self, block: &Block) -> AvoResult<()> {
        let cf = self.cf_handle(CF_BLOCKS)?;
        let key = block.id.0;
        let value = bincode::serialize(block)
            .map_err(|e| AvoError::internal(format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store block: {}", e),
            })?;

        // Also store height -> block_id mapping
        let metadata_cf = self.cf_handle(CF_METADATA)?;
        let height_key = format!("height:{}", block.height);
        self.db
            .put_cf(metadata_cf, height_key.as_bytes(), block.id.0)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store height mapping: {}", e),
            })?;

        Ok(())
    }

    /// Get a block by ID
    pub fn get_block(&self, block_id: &BlockId) -> AvoResult<Option<Block>> {
        let cf = self.cf_handle(CF_BLOCKS)?;

        match self.db.get_cf(cf, block_id.0) {
            Ok(Some(data)) => {
                let block = bincode::deserialize(&data)
                    .map_err(|e| AvoError::internal(format!("Deserialization error: {}", e)))?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get block: {}", e),
            }),
        }
    }

    /// Get block by height
    pub fn get_block_by_height(&self, height: u64) -> AvoResult<Option<Block>> {
        let metadata_cf = self.cf_handle(CF_METADATA)?;
        let height_key = format!("height:{}", height);

        match self.db.get_cf(metadata_cf, height_key.as_bytes()) {
            Ok(Some(block_id_bytes)) => {
                if block_id_bytes.len() != 32 {
                    return Err(AvoError::internal("Invalid block ID length"));
                }
                let mut block_id = [0u8; 32];
                block_id.copy_from_slice(&block_id_bytes);
                self.get_block(&BlockId(block_id))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get block by height: {}", e),
            }),
        }
    }

    // ==================== TRANSACTION OPERATIONS ====================

    /// Store a transaction
    pub fn store_transaction(&self, tx: &Transaction) -> AvoResult<()> {
        let cf = self.cf_handle(CF_TRANSACTIONS)?;
        let key = tx.id.0;
        let value = bincode::serialize(tx)
            .map_err(|e| AvoError::internal(format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store transaction: {}", e),
            })?;

        Ok(())
    }

    /// Get a transaction by ID
    pub fn get_transaction(&self, tx_id: &TransactionId) -> AvoResult<Option<Transaction>> {
        let cf = self.cf_handle(CF_TRANSACTIONS)?;

        match self.db.get_cf(cf, tx_id.0) {
            Ok(Some(data)) => {
                let tx = bincode::deserialize(&data)
                    .map_err(|e| AvoError::internal(format!("Deserialization error: {}", e)))?;
                Ok(Some(tx))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get transaction: {}", e),
            }),
        }
    }

    // ==================== ACCOUNT OPERATIONS ====================

    /// Store account data
    pub fn store_account(&self, account: &StoredAccount) -> AvoResult<()> {
        let cf = self.cf_handle(CF_ACCOUNTS)?;
        let key = account.address.0;
        let value = bincode::serialize(account)
            .map_err(|e| AvoError::internal(format!("Serialization error: {}", e)))?;

        self.db
            .put_cf(cf, key, value)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store account: {}", e),
            })?;

        Ok(())
    }

    /// Get account data
    pub fn get_account(&self, address: &Address) -> AvoResult<Option<StoredAccount>> {
        let cf = self.cf_handle(CF_ACCOUNTS)?;

        match self.db.get_cf(cf, address.0) {
            Ok(Some(data)) => {
                let account = bincode::deserialize(&data)
                    .map_err(|e| AvoError::internal(format!("Deserialization error: {}", e)))?;
                Ok(Some(account))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get account: {}", e),
            }),
        }
    }

    // ==================== STATE OPERATIONS ====================

    /// Store state root
    pub fn store_state_root(&self, height: u64, state_root: Hash) -> AvoResult<()> {
        let cf = self.cf_handle(CF_STATE)?;
        let key = format!("root:{}", height);

        self.db
            .put_cf(cf, key.as_bytes(), state_root)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store state root: {}", e),
            })?;

        Ok(())
    }

    /// Get state root by height
    pub fn get_state_root(&self, height: u64) -> AvoResult<Option<Hash>> {
        let cf = self.cf_handle(CF_STATE)?;
        let key = format!("root:{}", height);

        match self.db.get_cf(cf, key.as_bytes()) {
            Ok(Some(data)) => {
                if data.len() != 32 {
                    return Err(AvoError::internal("Invalid state root length"));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data);
                Ok(Some(hash))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get state root: {}", e),
            }),
        }
    }

    // ==================== BATCH OPERATIONS ====================

    /// Execute batch write
    pub fn write_batch(&self, batch: WriteBatch) -> AvoResult<()> {
        self.db.write(batch).map_err(|e| AvoError::StorageError {
            reason: format!("Batch write failed: {}", e),
        })?;

        Ok(())
    }

    /// Create a batch for atomic writes
    pub fn create_batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Add block to batch
    pub fn batch_put_block(&self, batch: &mut WriteBatch, block: &Block) -> AvoResult<()> {
        let cf = self.cf_handle(CF_BLOCKS)?;
        let key = block.id.0;
        let value = bincode::serialize(block)
            .map_err(|e| AvoError::internal(format!("Serialization error: {}", e)))?;

        batch.put_cf(cf, key, value);
        Ok(())
    }

    /// Add account to batch
    pub fn batch_put_account(
        &self,
        batch: &mut WriteBatch,
        account: &StoredAccount,
    ) -> AvoResult<()> {
        let cf = self.cf_handle(CF_ACCOUNTS)?;
        let key = account.address.0;
        let value = bincode::serialize(account)
            .map_err(|e| AvoError::internal(format!("Serialization error: {}", e)))?;

        batch.put_cf(cf, key, value);
        Ok(())
    }

    // ==================== CHECKPOINT OPERATIONS ====================

    /// Create a checkpoint
    pub fn create_checkpoint<P: AsRef<Path>>(&self, checkpoint_path: P) -> AvoResult<()> {
        let checkpoint = Checkpoint::new(&self.db).map_err(|e| AvoError::StorageError {
            reason: format!("Failed to create checkpoint object: {}", e),
        })?;

        checkpoint
            .create_checkpoint(checkpoint_path)
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to create checkpoint: {}", e),
            })?;

        Ok(())
    }

    /// Store checkpoint metadata
    pub fn store_checkpoint_metadata(&self, height: u64, checkpoint_path: &str) -> AvoResult<()> {
        let cf = self.cf_handle(CF_CHECKPOINTS)?;
        let key = format!("checkpoint:{}", height);

        self.db
            .put_cf(cf, key.as_bytes(), checkpoint_path.as_bytes())
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to store checkpoint metadata: {}", e),
            })?;

        Ok(())
    }

    // ==================== METADATA OPERATIONS ====================

    /// Get latest block height
    pub fn get_latest_height(&self) -> AvoResult<Option<u64>> {
        let cf = self.cf_handle(CF_METADATA)?;

        match self.db.get_cf(cf, b"latest_height") {
            Ok(Some(data)) => {
                let height = u64::from_le_bytes(
                    data.as_slice()
                        .try_into()
                        .map_err(|_| AvoError::internal("Invalid height data"))?,
                );
                Ok(Some(height))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AvoError::StorageError {
                reason: format!("Failed to get latest height: {}", e),
            }),
        }
    }

    /// Update latest block height
    pub fn update_latest_height(&self, height: u64) -> AvoResult<()> {
        let cf = self.cf_handle(CF_METADATA)?;

        self.db
            .put_cf(cf, b"latest_height", &height.to_le_bytes())
            .map_err(|e| AvoError::StorageError {
                reason: format!("Failed to update latest height: {}", e),
            })?;

        Ok(())
    }

    // ==================== UTILITY OPERATIONS ====================

    /// Flush all data to disk
    pub fn flush(&self) -> AvoResult<()> {
        self.db.flush().map_err(|e| AvoError::StorageError {
            reason: format!("Failed to flush: {}", e),
        })?;

        Ok(())
    }

    /// Get database statistics
    pub fn get_stats(&self) -> AvoResult<String> {
        // Get property for each column family
        let mut stats = String::new();

        for cf_name in &[
            CF_BLOCKS,
            CF_TRANSACTIONS,
            CF_STATE,
            CF_ACCOUNTS,
            CF_VALIDATORS,
            CF_CHECKPOINTS,
            CF_METADATA,
        ] {
            if let Ok(cf) = self.cf_handle(cf_name) {
                if let Ok(Some(cf_stats)) = self.db.property_value_cf(cf, "rocksdb.stats") {
                    stats.push_str(&format!("\n=== {} ===\n{}", cf_name, cf_stats));
                }
            }
        }

        Ok(stats)
    }

    /// Compact database
    pub fn compact(&self) -> AvoResult<()> {
        self.db.compact_range::<&[u8], &[u8]>(None, None);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_block() -> Block {
        Block {
            id: BlockId([1; 32]),
            shard_id: 0,
            epoch: 1,
            timestamp: 12345,
            height: 1,
            transactions: vec![],
            parents: vec![],
            state_root: [0; 32],
            transaction_merkle_root: [0; 32],
            validator_set_hash: [0; 32],
            proposer_signature: vec![],
        }
    }

    #[test]
    fn test_rocksdb_creation() {
        let temp_dir = TempDir::new().unwrap();
        let backend = RocksDBBackend::new(temp_dir.path(), 0);
        assert!(backend.is_ok());
    }

    #[test]
    fn test_store_and_retrieve_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = RocksDBBackend::new(temp_dir.path(), 0).unwrap();

        let block = create_test_block();
        backend.store_block(&block).unwrap();

        let retrieved = backend.get_block(&block.id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, block.id);
    }

    #[test]
    fn test_get_block_by_height() {
        let temp_dir = TempDir::new().unwrap();
        let backend = RocksDBBackend::new(temp_dir.path(), 0).unwrap();

        let block = create_test_block();
        backend.store_block(&block).unwrap();

        let retrieved = backend.get_block_by_height(block.height).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().height, block.height);
    }

    #[test]
    fn test_account_storage() {
        let temp_dir = TempDir::new().unwrap();
        let backend = RocksDBBackend::new(temp_dir.path(), 0).unwrap();

        let account = StoredAccount {
            address: Address([1; 20]),
            balance: 1000,
            nonce: 5,
            code_hash: None,
            storage_root: None,
        };

        backend.store_account(&account).unwrap();

        let retrieved = backend.get_account(&account.address).unwrap();
        assert!(retrieved.is_some());
        let retrieved_account = retrieved.unwrap();
        assert_eq!(retrieved_account.balance, 1000);
        assert_eq!(retrieved_account.nonce, 5);
    }

    #[test]
    fn test_batch_operations() {
        let temp_dir = TempDir::new().unwrap();
        let backend = RocksDBBackend::new(temp_dir.path(), 0).unwrap();

        let mut batch = backend.create_batch();

        let block = create_test_block();
        backend.batch_put_block(&mut batch, &block).unwrap();

        let account = StoredAccount {
            address: Address([2; 20]),
            balance: 2000,
            nonce: 10,
            code_hash: None,
            storage_root: None,
        };
        backend.batch_put_account(&mut batch, &account).unwrap();

        backend.write_batch(batch).unwrap();

        // Verify both were written
        assert!(backend.get_block(&block.id).unwrap().is_some());
        assert!(backend.get_account(&account.address).unwrap().is_some());
    }

    #[test]
    fn test_state_root_storage() {
        let temp_dir = TempDir::new().unwrap();
        let backend = RocksDBBackend::new(temp_dir.path(), 0).unwrap();

        let state_root = [42; 32];
        backend.store_state_root(100, state_root).unwrap();

        let retrieved = backend.get_state_root(100).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), state_root);
    }

    #[test]
    fn test_latest_height() {
        let temp_dir = TempDir::new().unwrap();
        let backend = RocksDBBackend::new(temp_dir.path(), 0).unwrap();

        backend.update_latest_height(42).unwrap();

        let height = backend.get_latest_height().unwrap();
        assert_eq!(height, Some(42));
    }
}
