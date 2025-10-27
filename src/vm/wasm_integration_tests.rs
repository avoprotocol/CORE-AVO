//! Integration tests for WASM VM
//!
//! Comprehensive tests for WASM runtime including:
//! - Contract deployment and execution
//! - Host function integration
//! - Gas metering
//! - State persistence
//! - Event emission
//! - Cross-contract interactions

#[cfg(test)]
mod tests {
    use crate::error::AvoError;
    use crate::vm::avo_vm::{VMContext, U256};
    use crate::vm::host_functions::ExtendedHostContext;
    use crate::vm::wasm_runtime::{WasmRuntime, WasmValue};

    fn create_test_vm_context() -> VMContext {
        VMContext {
            tx_hash: [0u8; 32],
            sender: [1u8; 20],
            recipient: None,
            gas_limit: 10_000_000,
            gas_price: 1,
            value: U256([0u8; 32]),
            block_number: 1,
            block_timestamp: 1000,
            chain_id: 1,
            shard_id: 0,
        }
    }

    #[tokio::test]
    async fn test_wasm_runtime_initialization() {
        let runtime = WasmRuntime::new();
        assert!(runtime.is_ok(), "Failed to initialize WASM runtime");

        let runtime = runtime.unwrap();
        let stats = runtime.get_stats();
        assert_eq!(stats.total_executions, 0);
        assert_eq!(stats.total_gas_used, 0);
    }

    #[tokio::test]
    async fn test_simple_wasm_execution() {
        let mut runtime = WasmRuntime::new().unwrap();

        // Simple WASM that returns 42
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (func (export "answer") (result i32)
                    i32.const 42
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = create_test_vm_context();
        let result = runtime
            .execute(
                &wasm_bytecode,
                "answer",
                &[],
                &vm_context,
                None,
                None,
                false,
            )
            .await
            .unwrap();

        assert!(result.success);
        assert!(result.gas_used > 0);
        if let Some(WasmValue::I32(val)) = result.return_value {
            assert_eq!(val, 42);
        } else {
            panic!("Expected I32 return value");
        }
    }

    #[tokio::test]
    async fn test_wasm_with_parameters() {
        let mut runtime = WasmRuntime::new().unwrap();

        // WASM function that adds two numbers
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (func (export "add") (param $a i32) (param $b i32) (result i32)
                    local.get $a
                    local.get $b
                    i32.add
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = create_test_vm_context();
        let args = vec![WasmValue::I32(10), WasmValue::I32(32)];

        let result = runtime
            .execute(&wasm_bytecode, "add", &args, &vm_context, None, None, false)
            .await
            .unwrap();

        assert!(result.success);
        if let Some(WasmValue::I32(val)) = result.return_value {
            assert_eq!(val, 42);
        } else {
            panic!("Expected I32 return value");
        }
    }

    #[tokio::test]
    async fn test_wasm_memory_operations() {
        let mut runtime = WasmRuntime::new().unwrap();

        // WASM with memory operations
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (memory (export "memory") 1)
                (func (export "store_and_load") (result i32)
                    ;; Store 42 at memory offset 0
                    (i32.store (i32.const 0) (i32.const 42))
                    ;; Load from memory offset 0
                    (i32.load (i32.const 0))
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = create_test_vm_context();
        let result = runtime
            .execute(
                &wasm_bytecode,
                "store_and_load",
                &[],
                &vm_context,
                None,
                None,
                false,
            )
            .await
            .unwrap();

        assert!(result.success);
        assert!(result.memory_used > 0);
        if let Some(WasmValue::I32(val)) = result.return_value {
            assert_eq!(val, 42);
        }
    }

    #[tokio::test]
    async fn test_wasm_gas_metering() {
        let mut runtime = WasmRuntime::new().unwrap();

        // Simple computation
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (func (export "compute") (result i32)
                    (local $i i32)
                    (local $sum i32)
                    (local.set $sum (i32.const 0))
                    (local.set $i (i32.const 0))
                    (loop $continue
                        (local.set $sum
                            (i32.add (local.get $sum) (local.get $i))
                        )
                        (local.set $i
                            (i32.add (local.get $i) (i32.const 1))
                        )
                        (br_if $continue
                            (i32.lt_u (local.get $i) (i32.const 100))
                        )
                    )
                    (local.get $sum)
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = create_test_vm_context();
        let result = runtime
            .execute(
                &wasm_bytecode,
                "compute",
                &[],
                &vm_context,
                None,
                None,
                false,
            )
            .await
            .unwrap();

        assert!(result.success);
        assert!(result.gas_used > 1000, "Expected significant gas usage");

        // Sum of 0 to 99 is 4950
        if let Some(WasmValue::I32(val)) = result.return_value {
            assert_eq!(val, 4950);
        }
    }

    #[tokio::test]
    async fn test_wasm_out_of_gas() {
        let mut runtime = WasmRuntime::new().unwrap();

        // Infinite loop (should run out of gas)
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (func (export "infinite_loop") (result i32)
                    (loop $continue
                        (br $continue)
                    )
                    (i32.const 42)
                )
            )
        "#,
        )
        .unwrap();

        let mut vm_context = create_test_vm_context();
        vm_context.gas_limit = 10000; // Low gas limit

        let result = runtime
            .execute(
                &wasm_bytecode,
                "infinite_loop",
                &[],
                &vm_context,
                None,
                None,
                false,
            )
            .await
            .unwrap();

        // Should fail due to out of gas
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_module_caching() {
        let mut runtime = WasmRuntime::new().unwrap();

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

        let vm_context = create_test_vm_context();

        // First execution
        let result1 = runtime
            .execute(&wasm_bytecode, "test", &[], &vm_context, None, None, false)
            .await
            .unwrap();
        assert!(result1.success);

        // Second execution (should use cached module)
        let result2 = runtime
            .execute(&wasm_bytecode, "test", &[], &vm_context, None, None, false)
            .await
            .unwrap();
        assert!(result2.success);

        // Check statistics
        let stats = runtime.get_stats();
        assert_eq!(stats.total_executions, 2);
    }

    #[tokio::test]
    async fn test_wasm_with_host_functions() {
        let mut runtime = WasmRuntime::new().unwrap();

        // WASM that calls host functions
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (import "env" "get_block_number" (func $get_block_number (result i64)))
                (func (export "get_info") (result i64)
                    (call $get_block_number)
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = create_test_vm_context();
        let result = runtime
            .execute(
                &wasm_bytecode,
                "get_info",
                &[],
                &vm_context,
                None,
                None,
                false,
            )
            .await
            .unwrap();

        assert!(result.success);
        if let Some(WasmValue::I64(val)) = result.return_value {
            assert_eq!(val, vm_context.block_number as i64);
        }
    }

    #[tokio::test]
    async fn test_wasm_multiple_functions() {
        let mut runtime = WasmRuntime::new().unwrap();

        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (func (export "add") (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.add
                )
                (func (export "mul") (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.mul
                )
                (func (export "sub") (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.sub
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = create_test_vm_context();

        // Test add
        let result = runtime
            .execute(
                &wasm_bytecode,
                "add",
                &[WasmValue::I32(5), WasmValue::I32(3)],
                &vm_context,
                None,
                None,
                false,
            )
            .await
            .unwrap();
        assert!(result.success);
        if let Some(WasmValue::I32(val)) = result.return_value {
            assert_eq!(val, 8);
        }

        // Test mul
        let result = runtime
            .execute(
                &wasm_bytecode,
                "mul",
                &[WasmValue::I32(5), WasmValue::I32(3)],
                &vm_context,
                None,
                None,
                false,
            )
            .await
            .unwrap();
        assert!(result.success);
        if let Some(WasmValue::I32(val)) = result.return_value {
            assert_eq!(val, 15);
        }

        // Test sub
        let result = runtime
            .execute(
                &wasm_bytecode,
                "sub",
                &[WasmValue::I32(5), WasmValue::I32(3)],
                &vm_context,
                None,
                None,
                false,
            )
            .await
            .unwrap();
        assert!(result.success);
        if let Some(WasmValue::I32(val)) = result.return_value {
            assert_eq!(val, 2);
        }
    }

    #[tokio::test]
    async fn test_wasm_invalid_function() {
        let mut runtime = WasmRuntime::new().unwrap();

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

        let vm_context = create_test_vm_context();

        // Try to call non-existent function
        let result = runtime
            .execute(
                &wasm_bytecode,
                "nonexistent",
                &[],
                &vm_context,
                None,
                None,
                false,
            )
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_host_context_storage() {
        let vm_context = create_test_vm_context();
        let context = ExtendedHostContext::new(vm_context, 1_000_000);

        // Test write and read
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();

        context
            .storage_write(key.clone(), value.clone())
            .await
            .unwrap();
        let read_value = context.storage_read(&key).await.unwrap();

        assert_eq!(read_value, Some(value));

        // Check state changes were tracked
        let changes = context.state_changes.lock().unwrap();
        assert_eq!(changes.len(), 1);
    }

    #[tokio::test]
    async fn test_host_context_events() {
        let vm_context = create_test_vm_context();
        let context = ExtendedHostContext::new(vm_context, 1_000_000);

        // Emit events
        context
            .emit_event(vec![b"Transfer".to_vec()], b"event_data".to_vec())
            .unwrap();
        context
            .emit_event(vec![b"Approval".to_vec()], b"approval_data".to_vec())
            .unwrap();

        let events = context.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, b"event_data");
        assert_eq!(events[1].data, b"approval_data");
    }

    #[tokio::test]
    async fn test_host_context_hashing() {
        let vm_context = create_test_vm_context();
        let context = ExtendedHostContext::new(vm_context, 1_000_000);

        let data = b"hello world";

        let sha3_hash = context.sha3_hash(data);
        let blake3_hash = context.blake3_hash(data);

        // Hashes should not be zero
        assert_ne!(sha3_hash, [0u8; 32]);
        assert_ne!(blake3_hash, [0u8; 32]);

        // Different hash algorithms should produce different results
        assert_ne!(sha3_hash, blake3_hash);

        // Same input should produce same output
        let sha3_hash2 = context.sha3_hash(data);
        assert_eq!(sha3_hash, sha3_hash2);
    }

    #[tokio::test]
    async fn test_gas_consumption() {
        let vm_context = create_test_vm_context();
        let context = ExtendedHostContext::new(vm_context, 100_000);

        let initial_gas = context.get_gas_remaining();
        assert_eq!(initial_gas, 100_000);

        // Consume some gas
        context.consume_gas(1000).unwrap();
        let after_gas = context.get_gas_remaining();
        assert_eq!(after_gas, 99_000);

        // Try to consume more gas than available
        let result = context.consume_gas(100_000);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execution_statistics() {
        let mut runtime = WasmRuntime::new().unwrap();

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

        let vm_context = create_test_vm_context();

        // Execute multiple times
        for _ in 0..5 {
            let _ = runtime
                .execute(&wasm_bytecode, "test", &[], &vm_context, None, None, false)
                .await;
        }

        let stats = runtime.get_stats();
        assert_eq!(stats.total_executions, 5);
        assert!(stats.total_gas_used > 0);
        assert!(stats.avg_gas_per_execution > 0);
        assert!(stats.avg_execution_time > 0);
    }

    #[tokio::test]
    async fn test_storage_deletion() {
        let vm_context = create_test_vm_context();
        let context = ExtendedHostContext::new(vm_context, 1_000_000);

        let key = b"delete_me".to_vec();
        let value = b"value".to_vec();

        // Write
        context
            .storage_write(key.clone(), value.clone())
            .await
            .unwrap();
        assert_eq!(context.storage_read(&key).await.unwrap(), Some(value));

        // Delete
        context.storage_delete(&key).await.unwrap();
        assert_eq!(context.storage_read(&key).await.unwrap(), None);
    }
}
