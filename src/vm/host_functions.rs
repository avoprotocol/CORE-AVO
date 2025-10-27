//! Host Functions for WASM contracts
//!
//! These functions provide the interface between WASM contracts and the AVO Protocol
//! blockchain state, consensus layer, and other system features.

use crate::error::AvoError;
use crate::state::storage::AvocadoStorage;
use crate::types::{Hash, ShardId};
use crate::vm::avo_vm::{Address as VmAddress, StateChange, VMContext, VMEvent, U256};
use crate::vm::gas_metering::{GasContext, Operation};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Extended host context with real blockchain state access
#[derive(Clone)]
pub struct ExtendedHostContext {
    /// VM execution context
    pub vm_context: VMContext,
    /// Gas metering context
    pub gas_context: Arc<Mutex<GasContext>>,
    /// Storage backend (real RocksDB storage)
    pub storage: Option<Arc<AvocadoStorage>>,
    /// Temporary storage for execution
    pub temp_storage: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    /// Events emitted during execution
    pub events: Arc<Mutex<Vec<VMEvent>>>,
    /// State changes tracked
    pub state_changes: Arc<Mutex<Vec<StateChange>>>,
    /// Active contract address (if executing contract code)
    pub contract_address: Option<VmAddress>,
    /// Current shard ID
    pub shard_id: ShardId,
    /// Cross-shard call handler
    pub cross_shard_enabled: bool,
}

impl ExtendedHostContext {
    /// Create new extended host context
    pub fn new(vm_context: VMContext, gas_limit: u64) -> Self {
        let shard_id = vm_context.shard_id;
        Self {
            vm_context,
            gas_context: Arc::new(Mutex::new(GasContext::new(gas_limit))),
            storage: None,
            temp_storage: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(Mutex::new(Vec::new())),
            state_changes: Arc::new(Mutex::new(Vec::new())),
            contract_address: None,
            shard_id,
            cross_shard_enabled: false,
        }
    }

    /// Set storage backend
    pub fn with_storage(mut self, storage: Arc<AvocadoStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Override the contract address when executing on behalf of a contract
    pub fn with_contract_address(mut self, address: VmAddress) -> Self {
        self.contract_address = Some(address);
        self
    }

    /// Enable cross-shard calls
    pub fn with_cross_shard(mut self) -> Self {
        self.cross_shard_enabled = true;
        self
    }

    /// Read from storage (temp or persistent)
    pub async fn storage_read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, AvoError> {
        // Try temp storage first
        {
            let temp = self.temp_storage.lock().unwrap();
            if let Some(value) = temp.get(key) {
                return Ok(Some(value.clone()));
            }
        }

        // Try persistent storage if available
        if let Some(ref storage) = self.storage {
            let storage_key = crate::state::storage::StorageKey::Contract(
                self.contract_storage_owner(),
                hex::encode(key),
            );
            return storage.get(&storage_key).await;
        }

        Ok(None)
    }

    /// Write to storage
    pub async fn storage_write(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), AvoError> {
        // Get old value for state change tracking
        let old_value = self.storage_read(&key).await?.unwrap_or_default();

        // Write to temp storage
        {
            let mut temp = self.temp_storage.lock().unwrap();
            temp.insert(key.clone(), value.clone());
        }

        // Track state change
        {
            let mut changes = self.state_changes.lock().unwrap();
            changes.push(StateChange {
                address: self.contract_address(),
                key: self.bytes_to_u256(&key),
                old_value: self.bytes_to_u256(&old_value),
                new_value: self.bytes_to_u256(&value),
            });
        }

        // Write to persistent storage if available
        if let Some(ref storage) = self.storage {
            let storage_key = crate::state::storage::StorageKey::Contract(
                self.contract_storage_owner(),
                hex::encode(&key),
            );
            storage.put(storage_key, value).await?;
        }

        Ok(())
    }

    /// Delete from storage
    pub async fn storage_delete(&self, key: &[u8]) -> Result<(), AvoError> {
        // Get old value for state change tracking
        let old_value = self.storage_read(key).await?.unwrap_or_default();

        // Delete from temp storage
        {
            let mut temp = self.temp_storage.lock().unwrap();
            temp.remove(key);
        }

        // Track state change
        {
            let mut changes = self.state_changes.lock().unwrap();
            changes.push(StateChange {
                address: self.contract_address(),
                key: self.bytes_to_u256(key),
                old_value: self.bytes_to_u256(&old_value),
                new_value: U256([0u8; 32]),
            });
        }

        // Delete from persistent storage if available
        if let Some(ref storage) = self.storage {
            let storage_key = crate::state::storage::StorageKey::Contract(
                self.contract_storage_owner(),
                hex::encode(key),
            );
            storage.delete(&storage_key).await?;
        }

        Ok(())
    }

    /// Emit event
    pub fn emit_event(&self, topics: Vec<Vec<u8>>, data: Vec<u8>) -> Result<(), AvoError> {
        let mut events = self.events.lock().unwrap();

        // Convert topics to U256
        let u256_topics: Vec<U256> = topics.iter().map(|t| self.bytes_to_u256(t)).collect();

        events.push(VMEvent {
            address: self.contract_address(),
            topics: u256_topics,
            data,
        });

        Ok(())
    }

    /// Hash data using SHA3-256
    pub fn sha3_hash(&self, data: &[u8]) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Hash data using BLAKE3
    pub fn blake3_hash(&self, data: &[u8]) -> Hash {
        let hash = blake3::hash(data);
        *hash.as_bytes()
    }

    /// Get caller address
    pub fn get_caller(&self) -> [u8; 20] {
        self.vm_context.sender
    }

    /// Get transaction origin
    pub fn get_tx_origin(&self) -> [u8; 20] {
        self.vm_context.sender
    }

    /// Get block number
    pub fn get_block_number(&self) -> u64 {
        self.vm_context.block_number
    }

    /// Get block timestamp
    pub fn get_timestamp(&self) -> u64 {
        self.vm_context.block_timestamp
    }

    /// Get gas remaining
    pub fn get_gas_remaining(&self) -> u64 {
        let gas_ctx = self.gas_context.lock().unwrap();
        gas_ctx.gas_remaining
    }

    /// Get chain ID
    pub fn get_chain_id(&self) -> u64 {
        self.vm_context.chain_id
    }

    /// Get shard ID
    pub fn get_shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Get transaction value
    pub fn get_tx_value(&self) -> U256 {
        self.vm_context.value
    }

    fn contract_address(&self) -> VmAddress {
        if let Some(address) = self.contract_address {
            address
        } else if let Some(recipient) = self.vm_context.recipient {
            recipient
        } else {
            self.vm_context.sender
        }
    }

    fn contract_storage_owner(&self) -> String {
        format!("0x{}", hex::encode(self.contract_address()))
    }

    /// Convert bytes to U256 (left-padded with zeros)
    fn bytes_to_u256(&self, bytes: &[u8]) -> U256 {
        let mut result = [0u8; 32];
        let len = bytes.len().min(32);
        result[32 - len..].copy_from_slice(&bytes[..len]);
        U256(result)
    }

    /// Convert U256 to bytes
    pub fn u256_to_bytes(&self, value: &U256) -> Vec<u8> {
        value.0.to_vec()
    }

    /// Consume gas
    pub fn consume_gas(&self, amount: u64) -> Result<(), AvoError> {
        let mut gas_ctx = self.gas_context.lock().unwrap();
        gas_ctx.consume_gas(amount)
    }
}

/// Host function implementations for WASM
pub struct HostFunctions;

impl HostFunctions {
    /// Storage read implementation
    pub async fn storage_read(
        context: &ExtendedHostContext,
        key: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, AvoError> {
        // Consume gas
        context.consume_gas(200)?;
        context.storage_read(&key).await
    }

    /// Storage write implementation
    pub async fn storage_write(
        context: &ExtendedHostContext,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), AvoError> {
        // Consume gas (higher cost for writes)
        let gas_cost = 20000 + (value.len() as u64 * 10);
        context.consume_gas(gas_cost)?;
        context.storage_write(key, value).await
    }

    /// Storage delete implementation
    pub async fn storage_delete(
        context: &ExtendedHostContext,
        key: Vec<u8>,
    ) -> Result<(), AvoError> {
        // Consume gas
        context.consume_gas(5000)?;
        context.storage_delete(&key).await
    }

    /// Emit event implementation
    pub fn emit_event(
        context: &ExtendedHostContext,
        topics: Vec<Vec<u8>>,
        data: Vec<u8>,
    ) -> Result<(), AvoError> {
        // Consume gas based on data size
        let gas_cost = 375 + (data.len() as u64 * 8) + (topics.len() as u64 * 375);
        context.consume_gas(gas_cost)?;
        context.emit_event(topics, data)
    }

    /// SHA3 hash implementation
    pub fn sha3_hash(context: &ExtendedHostContext, data: Vec<u8>) -> Result<Hash, AvoError> {
        // Consume gas based on data size
        let gas_cost = 30 + ((data.len() as u64 / 32) * 6);
        context.consume_gas(gas_cost)?;
        Ok(context.sha3_hash(&data))
    }

    /// BLAKE3 hash implementation
    pub fn blake3_hash(context: &ExtendedHostContext, data: Vec<u8>) -> Result<Hash, AvoError> {
        // Consume gas based on data size (BLAKE3 is faster)
        let gas_cost = 20 + ((data.len() as u64 / 32) * 4);
        context.consume_gas(gas_cost)?;
        Ok(context.blake3_hash(&data))
    }

    /// Get caller implementation
    pub fn get_caller(context: &ExtendedHostContext) -> Result<[u8; 20], AvoError> {
        context.consume_gas(2)?;
        Ok(context.get_caller())
    }

    /// Get block number implementation
    pub fn get_block_number(context: &ExtendedHostContext) -> Result<u64, AvoError> {
        context.consume_gas(2)?;
        Ok(context.get_block_number())
    }

    /// Get timestamp implementation
    pub fn get_timestamp(context: &ExtendedHostContext) -> Result<u64, AvoError> {
        context.consume_gas(2)?;
        Ok(context.get_timestamp())
    }

    /// Get gas remaining implementation
    pub fn get_gas_remaining(context: &ExtendedHostContext) -> Result<u64, AvoError> {
        context.consume_gas(2)?;
        Ok(context.get_gas_remaining())
    }

    /// Get chain ID implementation
    pub fn get_chain_id(context: &ExtendedHostContext) -> Result<u64, AvoError> {
        context.consume_gas(2)?;
        Ok(context.get_chain_id())
    }

    /// Get shard ID implementation
    pub fn get_shard_id(context: &ExtendedHostContext) -> Result<ShardId, AvoError> {
        context.consume_gas(2)?;
        Ok(context.get_shard_id())
    }

    /// Cross-shard call (placeholder for future implementation)
    pub async fn cross_shard_call(
        context: &ExtendedHostContext,
        target_shard: ShardId,
        contract_address: [u8; 20],
        function_data: Vec<u8>,
    ) -> Result<Vec<u8>, AvoError> {
        if !context.cross_shard_enabled {
            return Err(AvoError::VMError {
                reason: "Cross-shard calls are not enabled".to_string(),
            });
        }

        // Consume gas for cross-shard call
        context.consume_gas(10000)?;

        // TODO: Implement actual cross-shard call mechanism
        // For now, return error
        Err(AvoError::VMError {
            reason: format!(
                "Cross-shard call to shard {} not yet implemented",
                target_shard
            ),
        })
    }

    /// Verify signature (for on-chain signature verification)
    pub fn verify_signature(
        context: &ExtendedHostContext,
        message: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<bool, AvoError> {
        // Consume gas for signature verification
        context.consume_gas(3000)?;

        // TODO: Implement actual signature verification
        // This would use ed25519-dalek or similar
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_extended_host_context_storage() {
        let vm_context = VMContext {
            tx_hash: [0u8; 32],
            sender: [1u8; 20],
            recipient: None,
            gas_limit: 1_000_000,
            gas_price: 1,
            value: U256([0u8; 32]),
            block_number: 1,
            block_timestamp: 1000,
            chain_id: 1,
            shard_id: 0,
        };

        let context = ExtendedHostContext::new(vm_context, 1_000_000);

        // Test storage write and read
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();

        context
            .storage_write(key.clone(), value.clone())
            .await
            .unwrap();
        let read_value = context.storage_read(&key).await.unwrap();

        assert_eq!(read_value, Some(value));
    }

    #[tokio::test]
    async fn test_event_emission() {
        let vm_context = VMContext {
            tx_hash: [0u8; 32],
            sender: [1u8; 20],
            recipient: None,
            gas_limit: 1_000_000,
            gas_price: 1,
            value: U256([0u8; 32]),
            block_number: 1,
            block_timestamp: 1000,
            chain_id: 1,
            shard_id: 0,
        };

        let context = ExtendedHostContext::new(vm_context, 1_000_000);

        // Emit event
        let topics = vec![b"Transfer".to_vec()];
        let data = b"event_data".to_vec();

        context.emit_event(topics, data.clone()).unwrap();

        let events = context.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, data);
    }

    #[test]
    fn test_hashing_functions() {
        let vm_context = VMContext {
            tx_hash: [0u8; 32],
            sender: [1u8; 20],
            recipient: None,
            gas_limit: 1_000_000,
            gas_price: 1,
            value: U256([0u8; 32]),
            block_number: 1,
            block_timestamp: 1000,
            chain_id: 1,
            shard_id: 0,
        };

        let context = ExtendedHostContext::new(vm_context, 1_000_000);

        let data = b"hello world";

        // Test SHA3 hash
        let sha3_hash = context.sha3_hash(data);
        assert_ne!(sha3_hash, [0u8; 32]);

        // Test BLAKE3 hash
        let blake3_hash = context.blake3_hash(data);
        assert_ne!(blake3_hash, [0u8; 32]);

        // Hashes should be different
        assert_ne!(sha3_hash, blake3_hash);
    }

    #[test]
    fn test_context_getters() {
        let vm_context = VMContext {
            tx_hash: [0u8; 32],
            sender: [1u8; 20],
            recipient: None,
            gas_limit: 1_000_000,
            gas_price: 1,
            value: U256([0u8; 32]),
            block_number: 42,
            block_timestamp: 1234567890,
            chain_id: 1,
            shard_id: 5,
        };

        let context = ExtendedHostContext::new(vm_context.clone(), 1_000_000)
            .with_contract_address([5u8; 20]);

        assert_eq!(context.get_caller(), vm_context.sender);
        assert_eq!(context.get_block_number(), 42);
        assert_eq!(context.get_timestamp(), 1234567890);
        assert_eq!(context.get_chain_id(), 1);
        assert_eq!(context.get_shard_id(), 5);
    }
}
