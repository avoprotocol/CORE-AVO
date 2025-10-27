use crate::error::AvoError;
use crate::state::storage::{AvocadoStorage, StorageKey};
use crate::types::{Hash, ShardId};
use crate::vm::wasm_runtime::{WasmContext, WasmRuntime, WasmValue};
use revm::{
    bytecode::Bytecode as RevmBytecode,
    context::{BlockEnv, CfgEnv, Context, TxEnv},
    context_interface::result::{
        ExecutionResult as RevmExecutionResult, Output as RevmOutput, ResultAndState,
    },
    database::InMemoryDB,
    handler::{ExecuteEvm, MainBuilder, MainContext},
    primitives::{
        Address as RevmAddress, Bytes as RevmBytes, Log as RevmLog, B256, U256 as RevmU256,
    },
    state::{AccountInfo as RevmAccountInfo, EvmState as RevmState},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, warn};

/// Transaction context for VM execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMContext {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Sender address
    pub sender: Address,
    /// Recipient address (for contract calls)
    pub recipient: Option<Address>,
    /// Gas limit
    pub gas_limit: u64,
    /// Gas price
    pub gas_price: u64,
    /// Transaction value
    pub value: U256,
    /// Block number
    pub block_number: u64,
    /// Block timestamp
    pub block_timestamp: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Shard ID where the transaction executes
    pub shard_id: ShardId,
}

/// VM execution result
#[derive(Debug, Clone)]
pub struct VMResult {
    /// Execution success/failure
    pub success: bool,
    /// Gas used
    pub gas_used: u64,
    /// Return data
    pub return_data: Vec<u8>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Newly created contract address (for deployment)
    pub created_address: Option<Address>,
    /// State changes
    pub state_changes: Vec<StateChange>,
    /// Events emitted
    pub events: Vec<VMEvent>,
}

/// State change record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    /// Contract address
    pub address: Address,
    /// Storage key
    pub key: U256,
    /// Old value
    pub old_value: U256,
    /// New value
    pub new_value: U256,
}

/// VM event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMEvent {
    /// Contract address that emitted the event
    pub address: Address,
    /// Event topics
    pub topics: Vec<U256>,
    /// Event data
    pub data: Vec<u8>,
}

/// Contract bytecode type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BytecodeType {
    /// Raw EVM bytecode
    EVM(Vec<u8>),
    /// WebAssembly bytecode
    WASM(Vec<u8>),
    /// Native AVO contract
    Native(String),
}

/// Smart contract metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    /// Contract address
    pub address: Address,
    /// Contract bytecode
    pub bytecode: BytecodeType,
    /// Contract storage
    pub storage: HashMap<U256, U256>,
    /// Contract balance
    pub balance: U256,
    /// Contract nonce
    pub nonce: u64,
    /// Code hash
    pub code_hash: Hash,
    /// Creation timestamp
    pub created_at: u64,
    /// Creator address
    pub creator: Address,
}

/// Address type (20 bytes)
pub type Address = [u8; 20];

/// 256-bit unsigned integer (newtype wrapper to avoid orphan rule issues)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct U256(pub [u8; 32]);

impl Default for U256 {
    fn default() -> Self {
        U256([0u8; 32])
    }
}

impl From<[u8; 32]> for U256 {
    fn from(bytes: [u8; 32]) -> Self {
        U256(bytes)
    }
}

impl From<U256> for [u8; 32] {
    fn from(u256: U256) -> Self {
        u256.0
    }
}

fn u256_to_hex(value: &U256) -> String {
    format!("0x{}", hex::encode(value.0))
}

fn hex_to_u256(input: &str) -> Result<U256, String> {
    let trimmed = input.trim_start_matches("0x");
    if trimmed.is_empty() {
        return Ok(U256([0u8; 32]));
    }

    let bytes = hex::decode(trimmed).map_err(|e| format!("Invalid hex '{}': {}", input, e))?;
    if bytes.len() > 32 {
        return Err(format!("Hex value '{}' exceeds 32 bytes", input));
    }

    let mut buf = [0u8; 32];
    let offset = 32 - bytes.len();
    buf[offset..].copy_from_slice(&bytes);
    Ok(U256(buf))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredContractInfo {
    address: Address,
    bytecode: BytecodeType,
    storage: Vec<(String, String)>,
    balance: U256,
    nonce: u64,
    code_hash: Hash,
    created_at: u64,
    creator: Address,
}

impl StoredContractInfo {
    fn from_contract(info: &ContractInfo) -> Self {
        let storage = info
            .storage
            .iter()
            .map(|(key, value)| (u256_to_hex(key), u256_to_hex(value)))
            .collect();

        Self {
            address: info.address,
            bytecode: info.bytecode.clone(),
            storage,
            balance: info.balance,
            nonce: info.nonce,
            code_hash: info.code_hash,
            created_at: info.created_at,
            creator: info.creator,
        }
    }

    fn into_contract(self) -> Result<ContractInfo, String> {
        let mut storage = HashMap::with_capacity(self.storage.len());
        for (key, value) in self.storage {
            let key_u256 = hex_to_u256(&key)?;
            let value_u256 = hex_to_u256(&value)?;
            storage.insert(key_u256, value_u256);
        }

        Ok(ContractInfo {
            address: self.address,
            bytecode: self.bytecode,
            storage,
            balance: self.balance,
            nonce: self.nonce,
            code_hash: self.code_hash,
            created_at: self.created_at,
            creator: self.creator,
        })
    }
}

impl std::ops::Index<usize> for U256 {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl std::ops::IndexMut<usize> for U256 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

/// AVO Virtual Machine - Core execution engine
#[derive(Debug)]
pub struct AvoVM {
    /// Contract storage
    contracts: Arc<RwLock<HashMap<Address, ContractInfo>>>,
    /// Account balances
    balances: Arc<RwLock<HashMap<Address, U256>>>,
    /// Account nonces
    nonces: Arc<RwLock<HashMap<Address, u64>>>,
    /// VM configuration
    config: VMConfig,
    /// Gas metering instance
    gas_meter: Arc<super::gas_metering::GasMetering>,
    /// Precompiled contracts
    precompiles: Arc<super::precompiles::Precompiles>,
    /// WASM runtime engine
    wasm_runtime: Arc<RwLock<WasmRuntime>>,
    /// Persistent storage backend
    storage: Option<Arc<AvocadoStorage>>,
    /// Flag indicating whether contracts were loaded from storage
    contracts_loaded: Arc<RwLock<bool>>,
}

/// VM configuration
#[derive(Debug, Clone)]
pub struct VMConfig {
    /// Maximum gas per transaction
    pub max_gas_per_tx: u64,
    /// Maximum gas per block
    pub max_gas_per_block: u64,
    /// Base gas price
    pub base_gas_price: u64,
    /// Enable EVM compatibility
    pub evm_enabled: bool,
    /// Enable WASM support
    pub wasm_enabled: bool,
    /// Maximum contract size
    pub max_contract_size: usize,
    /// Maximum call depth
    pub max_call_depth: u32,
}

impl Default for VMConfig {
    fn default() -> Self {
        Self {
            max_gas_per_tx: 30_000_000,     // 30M gas per transaction
            max_gas_per_block: 100_000_000, // 100M gas per block
            base_gas_price: 1_000_000_000,  // 1 Gwei
            evm_enabled: true,
            wasm_enabled: true,
            max_contract_size: 2 * 1024 * 1024, // 2MB max contract
            max_call_depth: 1024,
        }
    }
}

impl AvoVM {
    /// Create a new AVO VM instance
    pub fn new(config: VMConfig) -> Self {
        Self::new_with_storage_internal(config, None)
    }

    /// Create a new VM instance backed by persistent storage
    pub fn new_with_storage(config: VMConfig, storage: Arc<AvocadoStorage>) -> Self {
        Self::new_with_storage_internal(config, Some(storage))
    }

    /// Create a new VM instance with optional storage backend
    fn new_with_storage_internal(config: VMConfig, storage: Option<Arc<AvocadoStorage>>) -> Self {
        // Create WASM context optimized for AVO
        let wasm_context = WasmContext {
            gas_limit: config.max_gas_per_tx,
            memory_limit: 512, // 32MB for high-performance contracts
            max_call_depth: config.max_call_depth,
            call_depth: 0,
            host_functions: vec![
                "avo_consensus_call".to_string(),
                "avo_shard_call".to_string(),
                "avo_governance_call".to_string(),
                "avo_cross_shard_call".to_string(),
                "storage_read".to_string(),
                "storage_write".to_string(),
                "emit_event".to_string(),
                "call_contract".to_string(),
                "get_caller".to_string(),
                "get_tx_origin".to_string(),
                "get_block_number".to_string(),
                "get_timestamp".to_string(),
                "get_balance".to_string(),
                "transfer".to_string(),
            ],
        };

        Self {
            contracts: Arc::new(RwLock::new(HashMap::new())),
            balances: Arc::new(RwLock::new(HashMap::new())),
            nonces: Arc::new(RwLock::new(HashMap::new())),
            config,
            gas_meter: Arc::new(super::gas_metering::GasMetering::new()),
            precompiles: Arc::new(super::precompiles::Precompiles::new()),
            wasm_runtime: Arc::new(RwLock::new(
                WasmRuntime::with_context(wasm_context).expect("Failed to create WASM runtime"),
            )),
            storage,
            contracts_loaded: Arc::new(RwLock::new(false)),
        }
    }

    /// Create VM with default configuration
    pub fn default() -> Self {
        Self::new(VMConfig::default())
    }

    /// Create VM with default configuration and persistent storage
    pub fn default_with_storage(storage: Arc<AvocadoStorage>) -> Self {
        Self::new_with_storage(VMConfig::default(), storage)
    }

    /// Preload contracts from persistent storage into memory
    pub async fn preload_contracts(&self) -> Result<(), AvoError> {
        self.ensure_contracts_loaded().await
    }

    /// Ensure contracts are loaded from persistent storage exactly once
    async fn ensure_contracts_loaded(&self) -> Result<(), AvoError> {
        let storage = match &self.storage {
            Some(storage) => storage.clone(),
            None => return Ok(()),
        };

        {
            let loaded_guard = self.contracts_loaded.read().await;
            if *loaded_guard {
                return Ok(());
            }
        }

        let entries = storage.get_range("contract:").await?;
        let mut contracts_guard = self.contracts.write().await;

        for (key, value) in entries {
            if let StorageKey::Contract(_, suffix) = key {
                if suffix != "metadata" {
                    continue;
                }

                match serde_json::from_slice::<StoredContractInfo>(&value) {
                    Ok(stored) => match stored.into_contract() {
                        Ok(info) => {
                            contracts_guard.insert(info.address, info);
                        }
                        Err(err) => {
                            warn!("Failed to convert stored contract metadata: {}", err);
                        }
                    },
                    Err(primary_err) => match serde_json::from_slice::<ContractInfo>(&value) {
                        Ok(info) => {
                            contracts_guard.insert(info.address, info);
                        }
                        Err(err) => {
                            warn!(
                                    "Failed to deserialize contract metadata (primary: {}; fallback: {})",
                                    primary_err,
                                    err
                                );
                        }
                    },
                }
            }
        }

        let mut loaded_guard = self.contracts_loaded.write().await;
        *loaded_guard = true;

        Ok(())
    }

    /// Persist contract metadata to RocksDB when available
    async fn persist_contract(&self, info: &ContractInfo) -> Result<(), AvoError> {
        let storage = match &self.storage {
            Some(storage) => storage.clone(),
            None => return Ok(()),
        };

        let key = StorageKey::Contract(
            format!("0x{}", hex::encode(info.address)),
            "metadata".to_string(),
        );
        let stored = StoredContractInfo::from_contract(info);
        let serialized = match serde_json::to_vec(&stored) {
            Ok(bytes) => bytes,
            Err(err) => {
                error!(
                    "Failed to serialize contract {} for persistence: {}",
                    format!("0x{}", hex::encode(info.address)),
                    err
                );
                return Err(AvoError::JsonError { source: err });
            }
        };
        storage.put(key, serialized).await?;

        Ok(())
    }

    pub(crate) fn contract_info_to_json(info: &ContractInfo) -> serde_json::Value {
        use serde_json::{json, Map, Value};

        let mut storage_map = Map::new();
        for (key, value) in &info.storage {
            storage_map.insert(u256_to_hex(key), Value::String(u256_to_hex(value)));
        }

        let bytecode_value = match &info.bytecode {
            BytecodeType::EVM(bytes) => json!({
                "EVM": format!("0x{}", hex::encode(bytes))
            }),
            BytecodeType::WASM(bytes) => json!({
                "WASM": format!("0x{}", hex::encode(bytes))
            }),
            BytecodeType::Native(name) => json!({
                "Native": name
            }),
        };

        json!({
            "address": format!("0x{}", hex::encode(info.address)),
            "bytecode": bytecode_value,
            "storage": storage_map,
            "balance": u256_to_hex(&info.balance),
            "nonce": info.nonce,
            "code_hash": format!("0x{}", hex::encode(info.code_hash)),
            "created_at": info.created_at,
            "creator": format!("0x{}", hex::encode(info.creator)),
        })
    }

    /// Execute a transaction
    pub async fn execute_transaction(
        &self,
        context: VMContext,
        bytecode: Vec<u8>,
        input_data: Vec<u8>,
    ) -> Result<VMResult, AvoError> {
        // Start gas metering
        let mut gas_used = 0u64;

        // Validate gas limit
        if context.gas_limit > self.config.max_gas_per_tx {
            return Err(AvoError::VMError {
                reason: "Gas limit exceeds maximum".to_string(),
            });
        }

        // Charge base transaction cost
        gas_used += self.gas_meter.base_transaction_cost();
        if gas_used > context.gas_limit {
            return Ok(VMResult {
                success: false,
                gas_used,
                return_data: Vec::new(),
                error: Some("Out of gas".to_string()),
                created_address: None,
                state_changes: Vec::new(),
                events: Vec::new(),
            });
        }

        // Execute based on bytecode type
        let result = if bytecode.is_empty() {
            // Simple transfer
            self.execute_transfer(&context).await?
        } else {
            // Contract execution
            self.execute_contract(&context, bytecode, input_data)
                .await?
        };

        Ok(result)
    }

    /// Execute a simple transfer
    async fn execute_transfer(&self, context: &VMContext) -> Result<VMResult, AvoError> {
        let mut state_changes = Vec::new();

        // Check sender balance
        let sender_balance = self.get_balance(&context.sender).await;
        if !self.has_sufficient_balance(sender_balance, context.value) {
            return Ok(VMResult {
                success: false,
                gas_used: self.gas_meter.base_transaction_cost(),
                return_data: Vec::new(),
                error: Some("Insufficient balance".to_string()),
                created_address: None,
                state_changes: Vec::new(),
                events: Vec::new(),
            });
        }

        // Update balances
        if let Some(recipient) = context.recipient {
            // Deduct from sender
            let new_sender_balance = self.subtract_balance(sender_balance, context.value);
            self.set_balance(&context.sender, new_sender_balance).await;

            state_changes.push(StateChange {
                address: context.sender,
                key: U256::default(), // Balance key
                old_value: sender_balance,
                new_value: new_sender_balance,
            });

            // Add to recipient
            let recipient_balance = self.get_balance(&recipient).await;
            let new_recipient_balance = self.add_balance(recipient_balance, context.value);
            self.set_balance(&recipient, new_recipient_balance).await;

            state_changes.push(StateChange {
                address: recipient,
                key: U256::default(), // Balance key
                old_value: recipient_balance,
                new_value: new_recipient_balance,
            });
        }

        Ok(VMResult {
            success: true,
            gas_used: self.gas_meter.base_transaction_cost(),
            return_data: Vec::new(),
            error: None,
            created_address: None,
            state_changes,
            events: Vec::new(),
        })
    }

    /// Execute contract code
    async fn execute_contract(
        &self,
        context: &VMContext,
        bytecode: Vec<u8>,
        input_data: Vec<u8>,
    ) -> Result<VMResult, AvoError> {
        let bytecode_type = self.detect_bytecode_type(&bytecode);

        match bytecode_type {
            BytecodeType::EVM(_) => {
                self.execute_evm_contract(context, bytecode, input_data)
                    .await
            }
            BytecodeType::WASM(_) => {
                self.execute_wasm_contract(context, bytecode, input_data)
                    .await
            }
            BytecodeType::Native(contract_name) => {
                self.execute_native_contract(context, contract_name, input_data)
                    .await
            }
        }
    }

    /// Execute EVM contract
    async fn execute_evm_contract(
        &self,
        context: &VMContext,
        bytecode: Vec<u8>,
        input_data: Vec<u8>,
    ) -> Result<VMResult, AvoError> {
        if !self.config.evm_enabled {
            return Err(AvoError::VMError {
                reason: "EVM execution is disabled".to_string(),
            });
        }

        // Prepare sender account
        let sender_balance = self.get_balance(&context.sender).await;
        let sender_nonce = self.get_nonce(&context.sender).await;
        let sender_address = address_to_revm(&context.sender);

        let mut db = InMemoryDB::default();
        let mut sender_info = RevmAccountInfo::default();
        sender_info.balance = u256_to_revm(sender_balance);
        sender_info.nonce = sender_nonce;
        sender_info.code = None;
        db.insert_account_info(sender_address, sender_info);

        // Prepare recipient contract state if this is a call
        if let Some(recipient) = context.recipient {
            let recipient_address = address_to_revm(&recipient);
            if let Some(contract) = self.get_contract(&recipient).await {
                let (code_bytes, balance, nonce) = match contract.bytecode.clone() {
                    BytecodeType::EVM(code) => (code, contract.balance, contract.nonce),
                    _ => (bytecode.clone(), contract.balance, contract.nonce),
                };

                let code = RevmBytecode::new_raw(RevmBytes::from(code_bytes.clone()));
                let mut account_info = RevmAccountInfo::default();
                account_info.balance = u256_to_revm(balance);
                account_info.nonce = nonce;
                account_info.code_hash = code.hash_slow();
                account_info.code = Some(code);
                db.insert_account_info(recipient_address, account_info);

                for (slot, value) in contract.storage.into_iter() {
                    let _ = db.insert_account_storage(
                        recipient_address,
                        u256_to_revm(slot),
                        u256_to_revm(value),
                    );
                }
            } else {
                let code = RevmBytecode::new_raw(RevmBytes::from(bytecode.clone()));
                let mut account_info = RevmAccountInfo::default();
                account_info.code_hash = code.hash_slow();
                account_info.code = Some(code);
                db.insert_account_info(recipient_address, account_info);
            }
        }

        let gas_price = context.gas_price as u128;
        let mut tx_builder = TxEnv::builder()
            .caller(sender_address)
            .gas_limit(context.gas_limit)
            .gas_price(gas_price)
            .value(u256_to_revm(context.value))
            .nonce(sender_nonce)
            .chain_id(Some(context.chain_id));

        if let Some(recipient) = context.recipient {
            tx_builder = tx_builder
                .call(address_to_revm(&recipient))
                .data(RevmBytes::from(input_data.clone()));
        } else {
            let mut deploy_payload = bytecode.clone();
            deploy_payload.extend_from_slice(&input_data);
            tx_builder = tx_builder.create().data(RevmBytes::from(deploy_payload));
        }

        let tx_env = tx_builder.build_fill();

        let block_gas_limit = self.config.max_gas_per_block.max(context.gas_limit);

        let ctx = Context::mainnet()
            .with_db(db)
            .modify_cfg_chained(|cfg: &mut CfgEnv| {
                cfg.chain_id = context.chain_id;
            })
            .modify_block_chained(|block: &mut BlockEnv| {
                block.number = RevmU256::from(context.block_number);
                block.timestamp = RevmU256::from(context.block_timestamp);
                block.basefee = context.gas_price;
                block.gas_limit = block_gas_limit;
            });

        let (execution_result, state) = {
            let mut evm = ctx.build_mainnet();
            let ResultAndState { result, state } =
                evm.transact(tx_env).map_err(|err| AvoError::VMError {
                    reason: format!("EVM execution error: {err:?}"),
                })?;
            (result, state)
        };

        match execution_result {
            RevmExecutionResult::Success {
                output,
                gas_used,
                logs,
                ..
            } => {
                let mut state_changes = Vec::new();
                let mut created_address = output.address().map(|addr| revm_to_address(*addr));

                let return_data = match output {
                    RevmOutput::Call(data) => data.as_ref().to_vec(),
                    RevmOutput::Create(code, address_opt) => {
                        if let Some(addr) = address_opt {
                            created_address = Some(revm_to_address(addr));
                        }
                        code.as_ref().to_vec()
                    }
                };

                let events = convert_logs(logs);

                self.apply_revm_state(context, state, &mut state_changes, &mut created_address)
                    .await?;

                Ok(VMResult {
                    success: true,
                    gas_used,
                    return_data,
                    error: None,
                    created_address,
                    state_changes,
                    events,
                })
            }
            RevmExecutionResult::Revert { gas_used, output } => {
                let output_slice = output.as_ref();
                Ok(VMResult {
                    success: false,
                    gas_used,
                    return_data: output_slice.to_vec(),
                    error: Some(format!("EVM revert: 0x{}", hex::encode(output_slice))),
                    created_address: None,
                    state_changes: Vec::new(),
                    events: Vec::new(),
                })
            }
            RevmExecutionResult::Halt { reason, gas_used } => Ok(VMResult {
                success: false,
                gas_used,
                return_data: Vec::new(),
                error: Some(format!("EVM halted: {reason:?}")),
                created_address: None,
                state_changes: Vec::new(),
                events: Vec::new(),
            }),
        }
    }

    async fn apply_revm_state(
        &self,
        context: &VMContext,
        state: RevmState,
        state_changes: &mut Vec<StateChange>,
        created_address: &mut Option<Address>,
    ) -> Result<(), AvoError> {
        use std::collections::HashMap as Map;

        let mut balance_updates: Map<Address, U256> = Map::new();
        let mut nonce_updates: Map<Address, u64> = Map::new();
        let mut code_updates: Map<Address, Vec<u8>> = Map::new();
        let mut storage_updates: Map<Address, Map<U256, U256>> = Map::new();

        for (addr, account) in state.into_iter() {
            let address = revm_to_address(addr);
            let info = account.info;
            let storage = account.storage;

            balance_updates.insert(address, from_revm_u256(info.balance));
            nonce_updates.insert(address, info.nonce);

            let code_opt = info.code;
            if let Some(code) = code_opt.as_ref() {
                code_updates.insert(address, code.bytes().as_ref().to_vec());
            }

            if created_address.is_none()
                && context.recipient.is_none()
                && address != context.sender
                && code_opt.is_some()
            {
                *created_address = Some(address);
            }

            for (slot, value) in storage.into_iter() {
                let key = from_revm_u256(slot);
                let old_value = from_revm_u256(value.original_value());
                let new_value = from_revm_u256(value.present_value());

                if old_value != new_value {
                    state_changes.push(StateChange {
                        address,
                        key,
                        old_value,
                        new_value,
                    });

                    storage_updates
                        .entry(address)
                        .or_insert_with(Map::new)
                        .insert(key, new_value);
                }
            }
        }

        // Update balances
        for (address, balance) in balance_updates.iter() {
            self.set_balance(address, *balance).await;
        }

        // Update nonces
        {
            let mut nonces = self.nonces.write().await;
            for (address, nonce) in nonce_updates.iter() {
                nonces.insert(*address, *nonce);
            }
        }

        // Update contract metadata and storage
        let mut contracts_to_persist: Map<Address, ContractInfo> = Map::new();

        {
            let mut contracts = self.contracts.write().await;

            for (address, code_bytes) in code_updates.iter() {
                let entry = contracts.entry(*address).or_insert_with(|| ContractInfo {
                    address: *address,
                    bytecode: BytecodeType::EVM(code_bytes.clone()),
                    storage: HashMap::new(),
                    balance: balance_updates.get(address).copied().unwrap_or_default(),
                    nonce: nonce_updates.get(address).copied().unwrap_or(0),
                    code_hash: self.calculate_code_hash(code_bytes),
                    created_at: context.block_timestamp,
                    creator: context.sender,
                });

                entry.bytecode = BytecodeType::EVM(code_bytes.clone());
                entry.code_hash = self.calculate_code_hash(code_bytes);
                if let Some(balance) = balance_updates.get(address) {
                    entry.balance = *balance;
                }
                if let Some(nonce) = nonce_updates.get(address) {
                    entry.nonce = *nonce;
                }
                if entry.created_at == 0 {
                    entry.created_at = context.block_timestamp;
                    entry.creator = context.sender;
                }

                contracts_to_persist.insert(*address, entry.clone());
            }

            for (address, storage_map) in storage_updates.iter() {
                let entry = contracts.entry(*address).or_insert_with(|| ContractInfo {
                    address: *address,
                    bytecode: BytecodeType::EVM(Vec::new()),
                    storage: HashMap::new(),
                    balance: balance_updates.get(address).copied().unwrap_or_default(),
                    nonce: nonce_updates.get(address).copied().unwrap_or(0),
                    code_hash: [0u8; 32],
                    created_at: context.block_timestamp,
                    creator: context.sender,
                });

                for (key, value) in storage_map.iter() {
                    if is_zero_u256(value) {
                        entry.storage.remove(key);
                    } else {
                        entry.storage.insert(*key, *value);
                    }
                }

                if let Some(balance) = balance_updates.get(address) {
                    entry.balance = *balance;
                }
                if let Some(nonce) = nonce_updates.get(address) {
                    entry.nonce = *nonce;
                }
                if let Some(code_bytes) = code_updates.get(address) {
                    entry.bytecode = BytecodeType::EVM(code_bytes.clone());
                    entry.code_hash = self.calculate_code_hash(code_bytes);
                }
                if entry.created_at == 0 {
                    entry.created_at = context.block_timestamp;
                    entry.creator = context.sender;
                }

                contracts_to_persist.insert(*address, entry.clone());
            }
        }

        for contract in contracts_to_persist.into_values() {
            self.persist_contract(&contract).await?;
        }

        Ok(())
    }

    /// Execute WASM contract with full runtime integration
    async fn execute_wasm_contract(
        &self,
        context: &VMContext,
        bytecode: Vec<u8>,
        input_data: Vec<u8>,
    ) -> Result<VMResult, AvoError> {
        // Validate WASM bytecode magic number
        if bytecode.len() < 4 || bytecode[0..4] != [0x00, 0x61, 0x73, 0x6D] {
            return Err(AvoError::InvalidBytecode(
                "Invalid WASM magic number".to_string(),
            ));
        }

        // Convert input data to WASM values (simplified - in reality would parse based on ABI)
        let wasm_args = vec![]; // Simplified for now

        // Acquire WASM runtime lock
        let mut wasm_runtime = self.wasm_runtime.write().await;

        // Execute contract using real WASM runtime
        match wasm_runtime
            .execute(
                &bytecode,
                "main", // Default WASM entry point
                &wasm_args,
                context,
                self.storage.clone(),
                context.recipient,
                false,
            )
            .await
        {
            Ok(wasm_result) => {
                // Convert WASM result to VM result
                Ok(VMResult {
                    success: wasm_result.success,
                    gas_used: wasm_result.gas_used,
                    return_data: if wasm_result.success {
                        // Convert WasmValue to bytes (simplified)
                        match wasm_result.return_value {
                            Some(value) => match value {
                                crate::vm::wasm_runtime::WasmValue::I32(v) => {
                                    v.to_le_bytes().to_vec()
                                }
                                crate::vm::wasm_runtime::WasmValue::I64(v) => {
                                    v.to_le_bytes().to_vec()
                                }
                                crate::vm::wasm_runtime::WasmValue::F32(v) => {
                                    v.to_le_bytes().to_vec()
                                }
                                crate::vm::wasm_runtime::WasmValue::F64(v) => {
                                    v.to_le_bytes().to_vec()
                                }
                                crate::vm::wasm_runtime::WasmValue::V128(v) => {
                                    v.to_le_bytes().to_vec()
                                }
                            },
                            None => Vec::new(),
                        }
                    } else {
                        Vec::new()
                    },
                    error: wasm_result.error,
                    created_address: None,
                    state_changes: wasm_result.state_changes,
                    events: wasm_result.events,
                })
            }
            Err(e) => {
                // Convert WASM runtime error to AVO error
                Err(AvoError::WasmExecutionError(format!(
                    "WASM execution failed: {:?}",
                    e
                )))
            }
        }
    }

    /// Execute native contract
    async fn execute_native_contract(
        &self,
        context: &VMContext,
        contract_name: String,
        input_data: Vec<u8>,
    ) -> Result<VMResult, AvoError> {
        // Execute precompiled native contracts
        self.precompiles
            .execute(&contract_name, context, input_data)
            .await
    }

    /// Detect bytecode type
    fn detect_bytecode_type(&self, bytecode: &[u8]) -> BytecodeType {
        if bytecode.len() >= 4 {
            // Check for WASM magic number (0x00, 0x61, 0x73, 0x6D)
            if bytecode[0..4] == [0x00, 0x61, 0x73, 0x6D] {
                return BytecodeType::WASM(bytecode.to_vec());
            }

            // Check for native contract signature
            if bytecode.starts_with(b"AVO_NATIVE_") {
                let contract_name = String::from_utf8_lossy(&bytecode[11..]).to_string();
                return BytecodeType::Native(contract_name);
            }
        }

        // Default to EVM
        BytecodeType::EVM(bytecode.to_vec())
    }

    /// Deploy a new contract
    pub async fn deploy_contract(
        &self,
        context: VMContext,
        bytecode: Vec<u8>,
        constructor_data: Vec<u8>,
    ) -> Result<(Address, VMResult), AvoError> {
        self.ensure_contracts_loaded().await?;

        // Fallback contract address (used if EVM doesn't report one)
        let fallback_address = self.generate_contract_address(&context.sender, context.tx_hash);

        // Validate contract size
        if bytecode.len() > self.config.max_contract_size {
            return Err(AvoError::VMError {
                reason: "Contract size exceeds maximum".to_string(),
            });
        }

        // Execute constructor
        let result = self
            .execute_contract(&context, bytecode.clone(), constructor_data)
            .await?;

        let contract_address = if result.success {
            result.created_address.unwrap_or(fallback_address)
        } else {
            fallback_address
        };

        if result.success {
            // Ensure contract metadata exists (fallback for non-EVM deployments)
            if self.get_contract(&contract_address).await.is_none() {
                let runtime_code = if !result.return_data.is_empty() {
                    result.return_data.clone()
                } else {
                    bytecode.clone()
                };

                let mut storage_snapshot = HashMap::new();
                for change in &result.state_changes {
                    if change.address == contract_address {
                        storage_snapshot.insert(change.key, change.new_value);
                    }
                }

                let contract_info = ContractInfo {
                    address: contract_address,
                    bytecode: self.detect_bytecode_type(&runtime_code),
                    storage: storage_snapshot,
                    balance: context.value,
                    nonce: 1,
                    code_hash: self.calculate_code_hash(&runtime_code),
                    created_at: context.block_timestamp,
                    creator: context.sender,
                };

                {
                    let mut contracts = self.contracts.write().await;
                    contracts.insert(contract_address, contract_info.clone());
                }

                if let Err(err) = self.persist_contract(&contract_info).await {
                    let mut contracts = self.contracts.write().await;
                    contracts.remove(&contract_address);
                    return Err(err);
                }
            }
        }

        Ok((contract_address, result))
    }

    /// Generate contract address
    fn generate_contract_address(&self, sender: &Address, tx_hash: Hash) -> Address {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as StdHash, Hasher};

        let mut hasher = DefaultHasher::new();
        sender.hash(&mut hasher);
        tx_hash.hash(&mut hasher);

        let hash = hasher.finish();
        let mut address = [0u8; 20];
        address[..8].copy_from_slice(&hash.to_be_bytes());
        address
    }

    /// Calculate code hash
    fn calculate_code_hash(&self, bytecode: &[u8]) -> Hash {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as StdHash, Hasher};

        let mut hasher = DefaultHasher::new();
        bytecode.hash(&mut hasher);

        let hash = hasher.finish();
        let mut code_hash = [0u8; 32];
        code_hash[..8].copy_from_slice(&hash.to_be_bytes());
        code_hash
    }

    /// Get account balance
    async fn get_balance(&self, address: &Address) -> U256 {
        let balances = self.balances.read().await;
        balances.get(address).copied().unwrap_or_default()
    }

    /// Set account balance
    async fn set_balance(&self, address: &Address, balance: U256) {
        let mut balances = self.balances.write().await;
        balances.insert(*address, balance);
    }

    /// Check if address has sufficient balance
    fn has_sufficient_balance(&self, current_balance: U256, required: U256) -> bool {
        current_balance.0 >= required.0
    }

    /// Add to balance
    fn add_balance(&self, current: U256, amount: U256) -> U256 {
        // Simple addition for U256 (would need proper implementation)
        let mut result = current.0;
        for i in 0..32 {
            let sum = result[31 - i] as u16 + amount.0[31 - i] as u16;
            result[31 - i] = sum as u8;
            if sum > 255 && i < 31 {
                // Carry over (simplified)
                result[31 - i - 1] = result[31 - i - 1].saturating_add(1);
            }
        }
        U256(result)
    }

    /// Subtract from balance
    fn subtract_balance(&self, current: U256, amount: U256) -> U256 {
        // Simple subtraction for U256 (would need proper implementation)
        let mut result = current.0;
        for i in 0..32 {
            if result[31 - i] >= amount.0[31 - i] {
                result[31 - i] -= amount.0[31 - i];
            } else {
                // Borrow (simplified)
                result[31 - i] = (256 + result[31 - i] as u16 - amount.0[31 - i] as u16) as u8;
                if i < 31 {
                    result[31 - i - 1] = result[31 - i - 1].saturating_sub(1);
                }
            }
        }
        U256(result)
    }

    /// Get contract information
    pub async fn get_contract(&self, address: &Address) -> Option<ContractInfo> {
        if let Err(err) = self.ensure_contracts_loaded().await {
            error!("Failed to load contracts from storage: {}", err);
        }
        let contracts = self.contracts.read().await;
        contracts.get(address).cloned()
    }

    /// Get account nonce
    pub async fn get_nonce(&self, address: &Address) -> u64 {
        let nonces = self.nonces.read().await;
        nonces.get(address).copied().unwrap_or(0)
    }

    /// Increment account nonce
    pub async fn increment_nonce(&self, address: &Address) {
        let mut nonces = self.nonces.write().await;
        let current = nonces.get(address).copied().unwrap_or(0);
        nonces.insert(*address, current + 1);
    }
}

// Add VMError to the error types
impl std::fmt::Display for VMResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VMResult(success: {}, gas_used: {})",
            self.success, self.gas_used
        )
    }
}

fn address_to_revm(address: &Address) -> RevmAddress {
    RevmAddress::from(*address)
}

fn revm_to_address(address: RevmAddress) -> Address {
    address.into()
}

fn u256_to_revm(value: U256) -> RevmU256 {
    RevmU256::from_be_bytes(value.0)
}

fn from_revm_u256(value: RevmU256) -> U256 {
    U256(value.to_be_bytes())
}

fn b256_to_u256(value: &B256) -> U256 {
    let bytes: [u8; 32] = value
        .to_vec()
        .try_into()
        .expect("topic hash should be 32 bytes");
    U256(bytes)
}

fn is_zero_u256(value: &U256) -> bool {
    value.0.iter().all(|byte| *byte == 0)
}

fn convert_logs(logs: Vec<RevmLog>) -> Vec<VMEvent> {
    logs.into_iter()
        .map(|log| {
            let address = revm_to_address(log.address);
            let data = log.data;

            let topics = data
                .topics()
                .iter()
                .map(|topic| b256_to_u256(topic))
                .collect();

            let data_bytes = data.data.as_ref().to_vec();

            VMEvent {
                address,
                topics,
                data: data_bytes,
            }
        })
        .collect()
}
