// Storage module - Persistent storage backends
//
// This module provides storage backends for blockchain data including:
// - RocksDB backend with column families
// - Batch operations
// - Checkpointing and recovery

pub mod rocksdb_backend;

pub use rocksdb_backend::{RocksDBBackend, StoredAccount};
pub use rocksdb_backend::{
    CF_ACCOUNTS, CF_BLOCKS, CF_CHECKPOINTS, CF_METADATA, CF_STATE, CF_TRANSACTIONS, CF_VALIDATORS,
};
