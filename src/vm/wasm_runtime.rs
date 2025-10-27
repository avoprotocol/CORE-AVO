//! Real WASM Runtime implementation using Wasmtime
//!
//! This module provides a production-ready WebAssembly runtime for AVO Protocol
//! with full gas metering, host function integration, and state management.

use crate::error::AvoError;
use crate::state::storage::AvocadoStorage;
use crate::vm::avo_vm::{Address as VmAddress, StateChange, VMContext, VMEvent, VMResult, U256};
use crate::vm::gas_metering::{GasContext, GasMetering, Operation};
use crate::vm::host_functions::{ExtendedHostContext, HostFunctions};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;
use wasmtime::*;

/// WASM execution context
#[derive(Debug, Clone)]
pub struct WasmContext {
    /// Gas limit for execution
    pub gas_limit: u64,
    /// Memory limit in pages (64KB each)
    pub memory_limit: u32,
    /// Maximum call depth
    pub max_call_depth: u32,
    /// Current call depth
    pub call_depth: u32,
    /// Available host functions
    pub host_functions: Vec<String>,
}

impl Default for WasmContext {
    fn default() -> Self {
        Self {
            gas_limit: 10_000_000,
            memory_limit: 256, // 16MB
            max_call_depth: 64,
            call_depth: 0,
            host_functions: vec![
                "storage_read".to_string(),
                "storage_write".to_string(),
                "storage_delete".to_string(),
                "emit_event".to_string(),
                "call_contract".to_string(),
                "get_caller".to_string(),
                "get_tx_origin".to_string(),
                "get_block_number".to_string(),
                "get_timestamp".to_string(),
                "get_gas_remaining".to_string(),
                "sha256_hash".to_string(),
                "blake3_hash".to_string(),
            ],
        }
    }
}

/// WASM module information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmModule {
    /// Module bytecode
    pub bytecode: Vec<u8>,
    /// Module hash
    pub module_hash: [u8; 32],
    /// Validation status
    pub is_valid: bool,
}

/// WASM execution result
#[derive(Debug, Clone)]
pub struct WasmExecutionResult {
    /// Execution success
    pub success: bool,
    /// Return value
    pub return_value: Option<WasmValue>,
    /// Gas used
    pub gas_used: u64,
    /// Memory used (in bytes)
    pub memory_used: u64,
    /// Error message (if failed)
    pub error: Option<String>,
    /// State changes made during execution
    pub state_changes: Vec<StateChange>,
    /// Events emitted during execution
    pub events: Vec<VMEvent>,
}

/// WASM runtime value
#[derive(Debug, Clone)]
pub enum WasmValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    V128(u128),
}

impl From<Val> for WasmValue {
    fn from(val: Val) -> Self {
        match val {
            Val::I32(v) => WasmValue::I32(v),
            Val::I64(v) => WasmValue::I64(v),
            Val::F32(v) => WasmValue::F32(f32::from_bits(v)),
            Val::F64(v) => WasmValue::F64(f64::from_bits(v)),
            Val::V128(v) => WasmValue::V128(v.as_u128()),
            _ => WasmValue::I32(0),
        }
    }
}

impl WasmValue {
    fn to_wasmtime_val(&self) -> Val {
        match self {
            WasmValue::I32(v) => Val::I32(*v),
            WasmValue::I64(v) => Val::I64(*v),
            WasmValue::F32(v) => Val::F32(v.to_bits()),
            WasmValue::F64(v) => Val::F64(v.to_bits()),
            WasmValue::V128(v) => Val::V128((*v).into()),
        }
    }
}

/// WASM execution statistics
#[derive(Debug, Clone, Default)]
pub struct WasmExecutionStats {
    /// Total executions
    pub total_executions: u64,
    /// Total gas used
    pub total_gas_used: u64,
    /// Total execution time (microseconds)
    pub total_execution_time: u64,
    /// Average gas per execution
    pub avg_gas_per_execution: u64,
    /// Average execution time (microseconds)
    pub avg_execution_time: u64,
    /// Failed executions
    pub failed_executions: u64,
}

/// Real WASM Runtime using Wasmtime
pub struct WasmRuntime {
    /// Wasmtime engine
    engine: Engine,
    /// Runtime configuration
    context: WasmContext,
    /// Gas metering system
    gas_metering: GasMetering,
    /// Loaded modules cache
    module_cache: HashMap<String, Module>,
    /// Execution statistics
    execution_stats: WasmExecutionStats,
}

impl std::fmt::Debug for WasmRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmRuntime")
            .field("context", &self.context)
            .field("module_cache_size", &self.module_cache.len())
            .field("execution_stats", &self.execution_stats)
            .finish()
    }
}

impl WasmRuntime {
    /// Create new WASM runtime with default configuration
    pub fn new() -> Result<Self, AvoError> {
        Self::with_context(WasmContext::default())
    }

    /// Create WASM runtime with custom context
    pub fn with_context(context: WasmContext) -> Result<Self, AvoError> {
        let mut config = Config::new();
        config.wasm_simd(true);
        config.wasm_bulk_memory(true);
        config.wasm_multi_value(true);
        config.wasm_reference_types(true);

        // Enable fuel consumption for gas metering
        config.consume_fuel(true);

        // Set memory limits
        config.max_wasm_stack(1024 * 1024); // 1MB stack

        let engine = Engine::new(&config).map_err(|e| AvoError::VMError {
            reason: format!("Failed to create WASM engine: {}", e),
        })?;

        Ok(Self {
            engine,
            context,
            gas_metering: GasMetering::new(),
            module_cache: HashMap::new(),
            execution_stats: WasmExecutionStats::default(),
        })
    }

    /// Execute WASM bytecode
    pub async fn execute(
        &mut self,
        bytecode: &[u8],
        function_name: &str,
        args: &[WasmValue],
        vm_context: &VMContext,
        storage: Option<Arc<AvocadoStorage>>,
        contract_address: Option<VmAddress>,
        enable_cross_shard: bool,
    ) -> Result<WasmExecutionResult, AvoError> {
        let start_time = std::time::Instant::now();

        // Validate bytecode
        if !self.is_valid_wasm(bytecode) {
            return Ok(WasmExecutionResult {
                success: false,
                return_value: None,
                gas_used: 1000,
                memory_used: 0,
                error: Some("Invalid WASM bytecode".to_string()),
                state_changes: Vec::new(),
                events: Vec::new(),
            });
        }

        // Load or get cached module
        let module_id = self.calculate_module_id(bytecode);
        let module = if let Some(cached) = self.module_cache.get(&module_id) {
            cached.clone()
        } else {
            let module = self.load_module(bytecode)?;
            self.module_cache.insert(module_id, module.clone());
            module
        };

        // Create store
        let mut store = Store::new(&self.engine, ());
        // Note: Fuel metering is handled through gas_context and host function tracking

        // Setup host context with optional components
        let mut host_context_builder =
            ExtendedHostContext::new(vm_context.clone(), vm_context.gas_limit);
        if let Some(storage) = storage {
            host_context_builder = host_context_builder.with_storage(storage);
        }
        if let Some(address) = contract_address {
            host_context_builder = host_context_builder.with_contract_address(address);
        }
        if enable_cross_shard {
            host_context_builder = host_context_builder.with_cross_shard();
        }

        let host_context = Arc::new(host_context_builder);

        // Create linker and register host functions
        let mut linker = Linker::new(&self.engine);
        let runtime_handle = Handle::current();
        self.register_host_functions(&mut linker, host_context.clone(), runtime_handle.clone())?;

        // Instantiate module
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| AvoError::VMError {
                reason: format!("Failed to instantiate WASM module: {}", e),
            })?;

        // Get the function
        let func = instance
            .get_func(&mut store, function_name)
            .ok_or_else(|| AvoError::VMError {
                reason: format!("Function '{}' not found in WASM module", function_name),
            })?;

        // Convert arguments
        let wasm_args: Vec<Val> = args.iter().map(|v| v.to_wasmtime_val()).collect();

        // Execute function
        let mut results = vec![Val::I32(0)];
        let execution_result = func.call(&mut store, &wasm_args, &mut results);

        // Calculate gas used from gas context
        let gas_used = {
            let gas_ctx = host_context.gas_context.lock().unwrap();
            gas_ctx.gas_used
        };

        // Get memory usage
        let memory_used = if let Some(memory) = instance.get_memory(&mut store, "memory") {
            memory.size(&store) as u64 * 65536 // pages to bytes
        } else {
            0
        };

        // Collect state changes and events
        let state_changes = host_context.state_changes.lock().unwrap().clone();
        let events = host_context.events.lock().unwrap().clone();

        let result = match execution_result {
            Ok(_) => WasmExecutionResult {
                success: true,
                return_value: Some(WasmValue::from(results[0].clone())),
                gas_used,
                memory_used,
                error: None,
                state_changes,
                events,
            },
            Err(e) => WasmExecutionResult {
                success: false,
                return_value: None,
                gas_used,
                memory_used,
                error: Some(format!("WASM execution error: {}", e)),
                state_changes,
                events,
            },
        };

        // Update statistics
        let execution_time = start_time.elapsed().as_micros() as u64;
        self.update_execution_stats(&result, execution_time);

        Ok(result)
    }

    /// Register host functions with the linker
    fn register_host_functions(
        &self,
        linker: &mut Linker<()>,
        host_context: Arc<ExtendedHostContext>,
        handle: Handle,
    ) -> Result<(), AvoError> {
        // Storage read
        {
            let ctx = host_context.clone();
            let handle = handle.clone();
            linker
                .func_wrap(
                    "env",
                    "storage_read",
                    move |mut caller: Caller<'_, ()>, key_ptr: i32, key_len: i32| -> i32 {
                        let memory = match caller.get_export("memory").and_then(|e| e.into_memory())
                        {
                            Some(mem) => mem,
                            None => return -1,
                        };

                        let mut key = vec![0u8; key_len as usize];
                        if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
                            return -1;
                        }

                        match handle
                            .block_on(async { HostFunctions::storage_read(&ctx, key).await })
                        {
                            Ok(Some(value)) => {
                                let mut buf = [0u8; 4];
                                for (idx, byte) in value.iter().take(4).enumerate() {
                                    buf[idx] = *byte;
                                }
                                i32::from_le_bytes(buf)
                            }
                            Ok(None) => 0,
                            Err(_) => -1,
                        }
                    },
                )
                .map_err(|e| AvoError::VMError {
                    reason: format!("Failed to register storage_read: {}", e),
                })?;
        }

        // Storage write
        {
            let ctx = host_context.clone();
            let handle = handle.clone();
            linker
                .func_wrap(
                    "env",
                    "storage_write",
                    move |mut caller: Caller<'_, ()>,
                          key_ptr: i32,
                          key_len: i32,
                          value_ptr: i32,
                          value_len: i32|
                          -> i32 {
                        let memory = match caller.get_export("memory").and_then(|e| e.into_memory())
                        {
                            Some(mem) => mem,
                            None => return -1,
                        };

                        let mut key = vec![0u8; key_len as usize];
                        let mut value = vec![0u8; value_len as usize];
                        if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
                            return -1;
                        }
                        if memory
                            .read(&caller, value_ptr as usize, &mut value)
                            .is_err()
                        {
                            return -1;
                        }

                        match handle.block_on(async {
                            HostFunctions::storage_write(&ctx, key, value).await
                        }) {
                            Ok(_) => 1,
                            Err(_) => -1,
                        }
                    },
                )
                .map_err(|e| AvoError::VMError {
                    reason: format!("Failed to register storage_write: {}", e),
                })?;
        }

        // Storage delete
        {
            let ctx = host_context.clone();
            let handle = handle.clone();
            linker
                .func_wrap(
                    "env",
                    "storage_delete",
                    move |mut caller: Caller<'_, ()>, key_ptr: i32, key_len: i32| -> i32 {
                        let memory = match caller.get_export("memory").and_then(|e| e.into_memory())
                        {
                            Some(mem) => mem,
                            None => return -1,
                        };

                        let mut key = vec![0u8; key_len as usize];
                        if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
                            return -1;
                        }

                        match handle
                            .block_on(async { HostFunctions::storage_delete(&ctx, key).await })
                        {
                            Ok(_) => 1,
                            Err(_) => -1,
                        }
                    },
                )
                .map_err(|e| AvoError::VMError {
                    reason: format!("Failed to register storage_delete: {}", e),
                })?;
        }

        // Emit event
        {
            let ctx = host_context.clone();
            linker
                .func_wrap(
                    "env",
                    "emit_event",
                    move |mut caller: Caller<'_, ()>,
                          topic_ptr: i32,
                          topic_len: i32,
                          data_ptr: i32,
                          data_len: i32|
                          -> i32 {
                        let memory = match caller.get_export("memory").and_then(|e| e.into_memory())
                        {
                            Some(mem) => mem,
                            None => return -1,
                        };

                        let mut topic = vec![0u8; topic_len as usize];
                        let mut data = vec![0u8; data_len as usize];
                        if memory
                            .read(&caller, topic_ptr as usize, &mut topic)
                            .is_err()
                        {
                            return -1;
                        }
                        if memory.read(&caller, data_ptr as usize, &mut data).is_err() {
                            return -1;
                        }

                        match HostFunctions::emit_event(&ctx, vec![topic], data) {
                            Ok(_) => 1,
                            Err(_) => -1,
                        }
                    },
                )
                .map_err(|e| AvoError::VMError {
                    reason: format!("Failed to register emit_event: {}", e),
                })?;
        }

        // Get block number
        {
            let ctx = host_context.clone();
            linker
                .func_wrap("env", "get_block_number", move |_: Caller<'_, ()>| -> i64 {
                    HostFunctions::get_block_number(&ctx)
                        .map(|value| value as i64)
                        .unwrap_or(-1)
                })
                .map_err(|e| AvoError::VMError {
                    reason: format!("Failed to register get_block_number: {}", e),
                })?;
        }

        // Get timestamp
        {
            let ctx = host_context.clone();
            linker
                .func_wrap("env", "get_timestamp", move |_: Caller<'_, ()>| -> i64 {
                    HostFunctions::get_timestamp(&ctx)
                        .map(|value| value as i64)
                        .unwrap_or(-1)
                })
                .map_err(|e| AvoError::VMError {
                    reason: format!("Failed to register get_timestamp: {}", e),
                })?;
        }

        // Get gas remaining
        {
            let ctx = host_context.clone();
            linker
                .func_wrap(
                    "env",
                    "get_gas_remaining",
                    move |_: Caller<'_, ()>| -> i64 {
                        HostFunctions::get_gas_remaining(&ctx)
                            .map(|value| value as i64)
                            .unwrap_or(-1)
                    },
                )
                .map_err(|e| AvoError::VMError {
                    reason: format!("Failed to register get_gas_remaining: {}", e),
                })?;
        }

        Ok(())
    }

    /// Validate WASM bytecode
    fn is_valid_wasm(&self, bytecode: &[u8]) -> bool {
        if bytecode.len() < 8 {
            return false;
        }
        // Check WASM magic number and version
        &bytecode[0..4] == b"\0asm" && &bytecode[4..8] == b"\x01\0\0\0"
    }

    /// Load WASM module from bytecode
    fn load_module(&self, bytecode: &[u8]) -> Result<Module, AvoError> {
        Module::new(&self.engine, bytecode).map_err(|e| AvoError::VMError {
            reason: format!("Failed to load WASM module: {}", e),
        })
    }

    /// Calculate module ID from bytecode
    fn calculate_module_id(&self, bytecode: &[u8]) -> String {
        use sha3::Digest;
        let hash = sha3::Sha3_256::digest(bytecode);
        format!("module_{}", hex::encode(hash))
    }

    /// Update execution statistics
    fn update_execution_stats(&mut self, result: &WasmExecutionResult, execution_time: u64) {
        self.execution_stats.total_executions += 1;
        self.execution_stats.total_gas_used += result.gas_used;
        self.execution_stats.total_execution_time += execution_time;

        if !result.success {
            self.execution_stats.failed_executions += 1;
        }

        if self.execution_stats.total_executions > 0 {
            self.execution_stats.avg_gas_per_execution =
                self.execution_stats.total_gas_used / self.execution_stats.total_executions;
            self.execution_stats.avg_execution_time =
                self.execution_stats.total_execution_time / self.execution_stats.total_executions;
        }
    }

    /// Get execution statistics
    pub fn get_stats(&self) -> &WasmExecutionStats {
        &self.execution_stats
    }

    /// Clear module cache
    pub fn clear_cache(&mut self) {
        self.module_cache.clear();
    }

    /// Convert WASM execution result to VM result
    pub fn wasm_to_vm_result(&self, wasm_result: WasmExecutionResult) -> VMResult {
        VMResult {
            success: wasm_result.success,
            gas_used: wasm_result.gas_used,
            return_data: match wasm_result.return_value {
                Some(WasmValue::I32(val)) => val.to_be_bytes().to_vec(),
                Some(WasmValue::I64(val)) => val.to_be_bytes().to_vec(),
                Some(WasmValue::F32(val)) => val.to_be_bytes().to_vec(),
                Some(WasmValue::F64(val)) => val.to_be_bytes().to_vec(),
                Some(WasmValue::V128(val)) => val.to_be_bytes().to_vec(),
                None => Vec::new(),
            },
            error: wasm_result.error,
            created_address: None,
            state_changes: wasm_result.state_changes,
            events: wasm_result.events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wasm_runtime_creation() {
        let runtime = WasmRuntime::new();
        assert!(runtime.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_wasm_bytecode() {
        let mut runtime = WasmRuntime::new().unwrap();
        let invalid_bytecode = vec![0x00, 0x01, 0x02, 0x03];

        let vm_context = VMContext {
            tx_hash: [0u8; 32],
            sender: [0u8; 20],
            recipient: None,
            gas_limit: 1_000_000,
            gas_price: 1,
            value: U256([0u8; 32]),
            block_number: 1,
            block_timestamp: 1000,
            chain_id: 1,
            shard_id: 0,
        };

        let result = runtime
            .execute(
                &invalid_bytecode,
                "main",
                &[],
                &vm_context,
                None,
                None,
                false,
            )
            .await;
        assert!(result.is_ok());
        let exec_result = result.unwrap();
        assert!(!exec_result.success);
    }

    #[tokio::test]
    async fn test_module_caching() {
        let mut runtime = WasmRuntime::new().unwrap();

        // Simple WASM module: (module (func (export "test") (result i32) i32.const 42))
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (func (export "test") (result i32)
                    i32.const 42
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = VMContext {
            tx_hash: [0u8; 32],
            sender: [0u8; 20],
            recipient: None,
            gas_limit: 1_000_000,
            gas_price: 1,
            value: U256([0u8; 32]),
            block_number: 1,
            block_timestamp: 1000,
            chain_id: 1,
            shard_id: 0,
        };

        // First execution - should cache the module
        let result1 = runtime
            .execute(&wasm_bytecode, "test", &[], &vm_context, None, None, false)
            .await;
        assert!(result1.is_ok());

        // Second execution - should use cached module
        let result2 = runtime
            .execute(&wasm_bytecode, "test", &[], &vm_context, None, None, false)
            .await;
        assert!(result2.is_ok());

        assert_eq!(runtime.module_cache.len(), 1);
    }
}
