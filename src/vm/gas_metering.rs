use crate::error::AvoError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Gas cost constants for different operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasCosts {
    // Base costs
    pub base_tx: u64,
    pub create_contract: u64,
    pub call_value: u64,

    // Storage operations
    pub storage_set: u64,
    pub storage_load: u64,
    pub storage_clear: u64,

    // Memory operations
    pub memory_copy: u64,
    pub memory_expansion: u64,

    // Arithmetic operations
    pub add: u64,
    pub mul: u64,
    pub div: u64,
    pub mod_op: u64,
    pub exp: u64,

    // Comparison operations
    pub lt: u64,
    pub gt: u64,
    pub eq: u64,

    // Bitwise operations
    pub and: u64,
    pub or: u64,
    pub xor: u64,
    pub not: u64,
    pub shl: u64,
    pub shr: u64,

    // Cryptographic operations
    pub sha3: u64,
    pub sha256: u64,
    pub ripemd160: u64,
    pub ecrecover: u64,

    // Contract operations
    pub call: u64,
    pub delegatecall: u64,
    pub staticcall: u64,
    pub return_op: u64,
    pub revert: u64,

    // WASM specific costs
    pub wasm_func_call: u64,
    pub wasm_memory_grow: u64,
    pub wasm_local_get: u64,
    pub wasm_local_set: u64,

    // AVO specific costs
    pub avo_consensus_call: u64,
    pub avo_shard_call: u64,
    pub avo_governance_call: u64,
}

impl Default for GasCosts {
    fn default() -> Self {
        Self {
            // Base costs (optimized for AVO's high performance)
            base_tx: 21000,
            create_contract: 32000,
            call_value: 9000,

            // Storage operations
            storage_set: 20000,
            storage_load: 200,
            storage_clear: 5000,

            // Memory operations
            memory_copy: 3,
            memory_expansion: 512,

            // Arithmetic operations (very low cost)
            add: 3,
            mul: 5,
            div: 5,
            mod_op: 5,
            exp: 50,

            // Comparison operations
            lt: 3,
            gt: 3,
            eq: 3,

            // Bitwise operations
            and: 3,
            or: 3,
            xor: 3,
            not: 3,
            shl: 3,
            shr: 3,

            // Cryptographic operations
            sha3: 30,
            sha256: 60,
            ripemd160: 600,
            ecrecover: 3000,

            // Contract operations
            call: 700,
            delegatecall: 700,
            staticcall: 700,
            return_op: 0,
            revert: 0,

            // WASM specific costs (optimized)
            wasm_func_call: 100,
            wasm_memory_grow: 1000,
            wasm_local_get: 2,
            wasm_local_set: 3,

            // AVO specific costs (very optimized)
            avo_consensus_call: 500,
            avo_shard_call: 300,
            avo_governance_call: 1000,
        }
    }
}

/// Gas execution context
#[derive(Debug, Clone)]
pub struct GasContext {
    /// Remaining gas
    pub gas_remaining: u64,
    /// Initial gas limit
    pub gas_limit: u64,
    /// Gas used so far
    pub gas_used: u64,
    /// Memory size (in bytes)
    pub memory_size: u64,
    /// Call depth
    pub call_depth: u32,
    /// Storage access count
    pub storage_access_count: u64,
}

impl GasContext {
    /// Create new gas context
    pub fn new(gas_limit: u64) -> Self {
        Self {
            gas_remaining: gas_limit,
            gas_limit,
            gas_used: 0,
            memory_size: 0,
            call_depth: 0,
            storage_access_count: 0,
        }
    }

    /// Consume gas
    pub fn consume_gas(&mut self, amount: u64) -> Result<(), AvoError> {
        if self.gas_remaining < amount {
            return Err(AvoError::VMError {
                reason: "Out of gas".to_string(),
            });
        }

        self.gas_remaining -= amount;
        self.gas_used += amount;
        Ok(())
    }

    /// Check if enough gas is available
    pub fn has_gas(&self, amount: u64) -> bool {
        self.gas_remaining >= amount
    }

    /// Get gas usage percentage
    pub fn gas_usage_percentage(&self) -> f64 {
        (self.gas_used as f64 / self.gas_limit as f64) * 100.0
    }
}

/// Operation type for gas calculation
#[derive(Debug, Clone)]
pub enum Operation {
    // Base operations
    BaseTx,
    CreateContract,
    CallValue,

    // Storage operations
    StorageSet,
    StorageLoad,
    StorageClear,

    // Memory operations
    MemoryCopy(u64),      // bytes copied
    MemoryExpansion(u64), // new memory size

    // Arithmetic operations
    Add,
    Mul,
    Div,
    Mod,
    Exp(u64), // exponent size

    // Comparison operations
    Lt,
    Gt,
    Eq,

    // Bitwise operations
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,

    // Cryptographic operations
    Sha3(u64),      // input size
    Sha256(u64),    // input size
    Ripemd160(u64), // input size
    EcRecover,

    // Contract operations
    Call,
    DelegateCall,
    StaticCall,
    Return,
    Revert,

    // WASM specific operations
    WasmFuncCall,
    WasmMemoryGrow(u64), // pages
    WasmLocalGet,
    WasmLocalSet,

    // AVO specific operations
    AvoConsensusCall,
    AvoShardCall,
    AvoGovernanceCall,
}

/// Advanced gas metering system for AVO VM
#[derive(Debug)]
pub struct GasMetering {
    /// Gas cost configuration
    costs: GasCosts,
    /// Dynamic pricing enabled
    dynamic_pricing: bool,
    /// Gas usage statistics
    usage_stats: HashMap<String, u64>,
    /// Performance optimizations enabled
    optimizations_enabled: bool,
}

impl GasMetering {
    /// Create new gas metering system
    pub fn new() -> Self {
        Self {
            costs: GasCosts::default(),
            dynamic_pricing: true,
            usage_stats: HashMap::new(),
            optimizations_enabled: true,
        }
    }

    /// Create with custom gas costs
    pub fn with_costs(costs: GasCosts) -> Self {
        Self {
            costs,
            dynamic_pricing: true,
            usage_stats: HashMap::new(),
            optimizations_enabled: true,
        }
    }

    /// Calculate gas cost for an operation
    pub fn calculate_gas_cost(&self, operation: &Operation, context: &GasContext) -> u64 {
        let base_cost = match operation {
            Operation::BaseTx => self.costs.base_tx,
            Operation::CreateContract => self.costs.create_contract,
            Operation::CallValue => self.costs.call_value,

            Operation::StorageSet => {
                // Dynamic pricing based on storage access patterns
                if self.dynamic_pricing && context.storage_access_count > 1000 {
                    self.costs.storage_set + (context.storage_access_count / 100)
                } else {
                    self.costs.storage_set
                }
            }
            Operation::StorageLoad => self.costs.storage_load,
            Operation::StorageClear => self.costs.storage_clear,

            Operation::MemoryCopy(bytes) => self.costs.memory_copy * (*bytes / 32 + 1),
            Operation::MemoryExpansion(new_size) => {
                if *new_size > context.memory_size {
                    let expansion = new_size - context.memory_size;
                    self.calculate_memory_expansion_cost(expansion)
                } else {
                    0
                }
            }

            // Arithmetic operations
            Operation::Add => self.costs.add,
            Operation::Mul => self.costs.mul,
            Operation::Div => self.costs.div,
            Operation::Mod => self.costs.mod_op,
            Operation::Exp(exponent) => {
                // Dynamic cost based on exponent size
                self.costs.exp + (*exponent / 8)
            }

            // Comparison operations
            Operation::Lt => self.costs.lt,
            Operation::Gt => self.costs.gt,
            Operation::Eq => self.costs.eq,

            // Bitwise operations
            Operation::And => self.costs.and,
            Operation::Or => self.costs.or,
            Operation::Xor => self.costs.xor,
            Operation::Not => self.costs.not,
            Operation::Shl => self.costs.shl,
            Operation::Shr => self.costs.shr,

            // Cryptographic operations
            Operation::Sha3(size) => self.costs.sha3 + (*size / 32) * 6,
            Operation::Sha256(size) => self.costs.sha256 + (*size / 32) * 12,
            Operation::Ripemd160(size) => self.costs.ripemd160 + (*size / 32) * 120,
            Operation::EcRecover => self.costs.ecrecover,

            // Contract operations
            Operation::Call => {
                // Increase cost with call depth to prevent deep recursion
                self.costs.call + (context.call_depth as u64 * 100)
            }
            Operation::DelegateCall => self.costs.delegatecall,
            Operation::StaticCall => self.costs.staticcall,
            Operation::Return => self.costs.return_op,
            Operation::Revert => self.costs.revert,

            // WASM specific operations
            Operation::WasmFuncCall => self.costs.wasm_func_call,
            Operation::WasmMemoryGrow(pages) => self.costs.wasm_memory_grow * pages,
            Operation::WasmLocalGet => self.costs.wasm_local_get,
            Operation::WasmLocalSet => self.costs.wasm_local_set,

            // AVO specific operations (highly optimized)
            Operation::AvoConsensusCall => {
                if self.optimizations_enabled {
                    self.costs.avo_consensus_call / 2 // 50% discount for native AVO operations
                } else {
                    self.costs.avo_consensus_call
                }
            }
            Operation::AvoShardCall => {
                if self.optimizations_enabled {
                    self.costs.avo_shard_call / 2 // 50% discount for shard operations
                } else {
                    self.costs.avo_shard_call
                }
            }
            Operation::AvoGovernanceCall => self.costs.avo_governance_call,
        };

        // Apply performance optimizations
        if self.optimizations_enabled {
            self.apply_optimizations(base_cost, context)
        } else {
            base_cost
        }
    }

    /// Apply performance optimizations to gas cost
    fn apply_optimizations(&self, base_cost: u64, context: &GasContext) -> u64 {
        let mut optimized_cost = base_cost;

        // Batch operation discount
        if context.gas_used > 100000 {
            // 5% discount for high-gas transactions (batch operations)
            optimized_cost = (optimized_cost * 95) / 100;
        }

        // Early execution discount
        if context.gas_usage_percentage() < 25.0 {
            // 10% discount for operations in first quarter of execution
            optimized_cost = (optimized_cost * 90) / 100;
        }

        // Deep call penalty reduction for AVO native operations
        if context.call_depth > 10 {
            optimized_cost = optimized_cost.saturating_sub(context.call_depth as u64 * 10);
        }

        optimized_cost
    }

    /// Calculate memory expansion cost
    fn calculate_memory_expansion_cost(&self, expansion_bytes: u64) -> u64 {
        // Quadratic memory expansion cost
        let words = (expansion_bytes + 31) / 32;
        let cost = words * self.costs.memory_expansion;

        // Add quadratic component for large expansions
        if words > 1024 {
            cost + (words * words) / 512
        } else {
            cost
        }
    }

    /// Execute operation with gas metering
    pub fn execute_with_metering<F, R>(
        &mut self,
        operation: Operation,
        context: &mut GasContext,
        execution_fn: F,
    ) -> Result<R, AvoError>
    where
        F: FnOnce() -> Result<R, AvoError>,
    {
        // Calculate gas cost
        let gas_cost = self.calculate_gas_cost(&operation, context);

        // Check if enough gas is available
        if !context.has_gas(gas_cost) {
            return Err(AvoError::VMError {
                reason: "Out of gas".to_string(),
            });
        }

        // Consume gas before execution
        context.consume_gas(gas_cost)?;

        // Track usage statistics
        let op_name = format!("{:?}", operation);
        let current_usage = self.usage_stats.get(&op_name).unwrap_or(&0);
        self.usage_stats.insert(op_name, current_usage + gas_cost);

        // Execute the operation
        let result = execution_fn()?;

        Ok(result)
    }

    /// Get base transaction cost
    pub fn base_transaction_cost(&self) -> u64 {
        self.costs.base_tx
    }

    /// Get contract creation cost
    pub fn contract_creation_cost(&self) -> u64 {
        self.costs.create_contract
    }

    /// Update gas costs dynamically
    pub fn update_costs(&mut self, new_costs: GasCosts) {
        self.costs = new_costs;
    }

    /// Enable/disable dynamic pricing
    pub fn set_dynamic_pricing(&mut self, enabled: bool) {
        self.dynamic_pricing = enabled;
    }

    /// Enable/disable optimizations
    pub fn set_optimizations(&mut self, enabled: bool) {
        self.optimizations_enabled = enabled;
    }

    /// Get usage statistics
    pub fn get_usage_stats(&self) -> &HashMap<String, u64> {
        &self.usage_stats
    }

    /// Reset usage statistics
    pub fn reset_stats(&mut self) {
        self.usage_stats.clear();
    }

    /// Estimate gas for a sequence of operations
    pub fn estimate_gas_for_operations(
        &self,
        operations: &[Operation],
        initial_context: &GasContext,
    ) -> u64 {
        let mut total_gas = 0;
        let mut context = initial_context.clone();

        for operation in operations {
            let gas_cost = self.calculate_gas_cost(operation, &context);
            total_gas += gas_cost;

            // Update context for next operation
            context.gas_used += gas_cost;
            context.gas_remaining = context.gas_remaining.saturating_sub(gas_cost);

            // Update context based on operation type
            match operation {
                Operation::Call | Operation::DelegateCall | Operation::StaticCall => {
                    context.call_depth += 1;
                }
                Operation::StorageSet | Operation::StorageLoad | Operation::StorageClear => {
                    context.storage_access_count += 1;
                }
                Operation::MemoryExpansion(new_size) => {
                    if *new_size > context.memory_size {
                        context.memory_size = *new_size;
                    }
                }
                _ => {}
            }
        }

        total_gas
    }

    /// Calculate refund amount for operations
    pub fn calculate_refund(&self, operations: &[Operation]) -> u64 {
        let mut refund = 0;

        for operation in operations {
            match operation {
                Operation::StorageClear => {
                    refund += self.costs.storage_clear / 2; // 50% refund for clearing storage
                }
                Operation::Return => {
                    refund += 1000; // Small refund for clean returns
                }
                _ => {}
            }
        }

        refund
    }
}
