//! Performance benchmarks for WASM VM
//!
//! Benchmarks various aspects of the WASM runtime including:
//! - Module loading and caching
//! - Function execution
//! - Host function calls
//! - Gas metering overhead
//! - Memory operations

use crate::vm::avo_vm::{VMContext, U256};
use crate::vm::host_functions::ExtendedHostContext;
use crate::vm::wasm_runtime::{WasmRuntime, WasmValue};
use std::time::{Duration, Instant};

/// Benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: u64,
    pub total_time: Duration,
    pub avg_time: Duration,
    pub min_time: Duration,
    pub max_time: Duration,
    pub throughput: f64, // operations per second
}

impl BenchmarkResult {
    pub fn new(name: String, iterations: u64) -> Self {
        Self {
            name,
            iterations,
            total_time: Duration::from_secs(0),
            avg_time: Duration::from_secs(0),
            min_time: Duration::from_secs(u64::MAX),
            max_time: Duration::from_secs(0),
            throughput: 0.0,
        }
    }

    pub fn calculate_stats(&mut self, times: &[Duration]) {
        self.total_time = times.iter().sum();
        self.avg_time = self.total_time / (times.len() as u32);
        self.min_time = *times.iter().min().unwrap();
        self.max_time = *times.iter().max().unwrap();
        self.throughput = self.iterations as f64 / self.total_time.as_secs_f64();
    }

    pub fn print(&self) {
        println!("\n=== {} ===", self.name);
        println!("Iterations: {}", self.iterations);
        println!("Total time: {:?}", self.total_time);
        println!("Average time: {:?}", self.avg_time);
        println!("Min time: {:?}", self.min_time);
        println!("Max time: {:?}", self.max_time);
        println!("Throughput: {:.2} ops/sec", self.throughput);
    }
}

/// WASM VM Benchmarks
pub struct WasmBenchmarks;

impl WasmBenchmarks {
    fn create_test_context() -> VMContext {
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

    /// Benchmark simple function execution
    pub async fn bench_simple_execution(iterations: u64) -> BenchmarkResult {
        let mut result = BenchmarkResult::new("Simple Execution".to_string(), iterations);
        let mut times = Vec::new();

        let mut runtime = WasmRuntime::new().unwrap();
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (func (export "compute") (result i32)
                    i32.const 42
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = Self::create_test_context();

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = runtime
                .execute(
                    &wasm_bytecode,
                    "compute",
                    &[],
                    &vm_context,
                    None,
                    None,
                    false,
                )
                .await;
            times.push(start.elapsed());
        }

        result.calculate_stats(&times);
        result
    }

    /// Benchmark arithmetic operations
    pub async fn bench_arithmetic_ops(iterations: u64) -> BenchmarkResult {
        let mut result = BenchmarkResult::new("Arithmetic Operations".to_string(), iterations);
        let mut times = Vec::new();

        let mut runtime = WasmRuntime::new().unwrap();
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (func (export "compute") (param i32 i32) (result i32)
                    (local $result i32)
                    (local.set $result (i32.add (local.get 0) (local.get 1)))
                    (local.set $result (i32.mul (local.get $result) (i32.const 2)))
                    (local.set $result (i32.sub (local.get $result) (i32.const 10)))
                    (local.get $result)
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = Self::create_test_context();
        let args = vec![WasmValue::I32(10), WasmValue::I32(20)];

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = runtime
                .execute(
                    &wasm_bytecode,
                    "compute",
                    &args,
                    &vm_context,
                    None,
                    None,
                    false,
                )
                .await;
            times.push(start.elapsed());
        }

        result.calculate_stats(&times);
        result
    }

    /// Benchmark loop execution
    pub async fn bench_loop_execution(iterations: u64) -> BenchmarkResult {
        let mut result = BenchmarkResult::new("Loop Execution".to_string(), iterations);
        let mut times = Vec::new();

        let mut runtime = WasmRuntime::new().unwrap();
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (func (export "sum_100") (result i32)
                    (local $i i32)
                    (local $sum i32)
                    (local.set $sum (i32.const 0))
                    (local.set $i (i32.const 0))
                    (loop $continue
                        (local.set $sum (i32.add (local.get $sum) (local.get $i)))
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br_if $continue (i32.lt_u (local.get $i) (i32.const 100)))
                    )
                    (local.get $sum)
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = Self::create_test_context();

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = runtime
                .execute(
                    &wasm_bytecode,
                    "sum_100",
                    &[],
                    &vm_context,
                    None,
                    None,
                    false,
                )
                .await;
            times.push(start.elapsed());
        }

        result.calculate_stats(&times);
        result
    }

    /// Benchmark memory operations
    pub async fn bench_memory_operations(iterations: u64) -> BenchmarkResult {
        let mut result = BenchmarkResult::new("Memory Operations".to_string(), iterations);
        let mut times = Vec::new();

        let mut runtime = WasmRuntime::new().unwrap();
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (memory (export "memory") 1)
                (func (export "memory_ops") (result i32)
                    (local $i i32)
                    (local.set $i (i32.const 0))
                    (loop $continue
                        (i32.store (local.get $i) (local.get $i))
                        (local.set $i (i32.add (local.get $i) (i32.const 4)))
                        (br_if $continue (i32.lt_u (local.get $i) (i32.const 1000)))
                    )
                    (i32.load (i32.const 0))
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = Self::create_test_context();

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = runtime
                .execute(
                    &wasm_bytecode,
                    "memory_ops",
                    &[],
                    &vm_context,
                    None,
                    None,
                    false,
                )
                .await;
            times.push(start.elapsed());
        }

        result.calculate_stats(&times);
        result
    }

    /// Benchmark host function calls
    pub async fn bench_host_function_calls(iterations: u64) -> BenchmarkResult {
        let mut result = BenchmarkResult::new("Host Function Calls".to_string(), iterations);
        let mut times = Vec::new();

        let mut runtime = WasmRuntime::new().unwrap();
        let wasm_bytecode = wat::parse_str(
            r#"
            (module
                (import "env" "get_block_number" (func $get_block_number (result i64)))
                (import "env" "get_timestamp" (func $get_timestamp (result i64)))
                (import "env" "get_gas_remaining" (func $get_gas_remaining (result i64)))
                (func (export "call_hosts") (result i64)
                    (local $result i64)
                    (local.set $result (call $get_block_number))
                    (local.set $result (i64.add (local.get $result) (call $get_timestamp)))
                    (local.set $result (i64.add (local.get $result) (call $get_gas_remaining)))
                    (local.get $result)
                )
            )
        "#,
        )
        .unwrap();

        let vm_context = Self::create_test_context();

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = runtime
                .execute(
                    &wasm_bytecode,
                    "call_hosts",
                    &[],
                    &vm_context,
                    None,
                    None,
                    false,
                )
                .await;
            times.push(start.elapsed());
        }

        result.calculate_stats(&times);
        result
    }

    /// Benchmark module caching
    pub async fn bench_module_caching(iterations: u64) -> BenchmarkResult {
        let mut result = BenchmarkResult::new("Module Caching".to_string(), iterations);
        let mut times = Vec::new();

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

        let vm_context = Self::create_test_context();

        // First execution to populate cache
        let _ = runtime
            .execute(&wasm_bytecode, "test", &[], &vm_context, None, None, false)
            .await;

        // Benchmark cached executions
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = runtime
                .execute(&wasm_bytecode, "test", &[], &vm_context, None, None, false)
                .await;
            times.push(start.elapsed());
        }

        result.calculate_stats(&times);
        result
    }

    /// Benchmark storage operations
    pub async fn bench_storage_operations(iterations: u64) -> BenchmarkResult {
        let mut result = BenchmarkResult::new("Storage Operations".to_string(), iterations);
        let mut times = Vec::new();

        let vm_context = Self::create_test_context();
        let context = ExtendedHostContext::new(vm_context, 10_000_000);

        let key = b"benchmark_key".to_vec();
        let value = b"benchmark_value_data".to_vec();

        for _ in 0..iterations {
            let start = Instant::now();

            // Write
            let _ = context.storage_write(key.clone(), value.clone()).await;

            // Read
            let _ = context.storage_read(&key).await;

            times.push(start.elapsed());
        }

        result.calculate_stats(&times);
        result
    }

    /// Benchmark event emission
    pub async fn bench_event_emission(iterations: u64) -> BenchmarkResult {
        let mut result = BenchmarkResult::new("Event Emission".to_string(), iterations);
        let mut times = Vec::new();

        let vm_context = Self::create_test_context();
        let context = ExtendedHostContext::new(vm_context, 10_000_000);

        for i in 0..iterations {
            let topics = vec![format!("Topic{}", i).into_bytes()];
            let data = format!("Event data {}", i).into_bytes();

            let start = Instant::now();
            let _ = context.emit_event(topics, data);
            times.push(start.elapsed());
        }

        result.calculate_stats(&times);
        result
    }

    /// Benchmark hashing operations
    pub async fn bench_hashing(iterations: u64) -> BenchmarkResult {
        let mut result = BenchmarkResult::new("Hashing Operations".to_string(), iterations);
        let mut times = Vec::new();

        let vm_context = Self::create_test_context();
        let context = ExtendedHostContext::new(vm_context, 10_000_000);

        let data = b"benchmark data for hashing operations";

        for _ in 0..iterations {
            let start = Instant::now();

            // SHA3 hash
            let _ = context.sha3_hash(data);

            // BLAKE3 hash
            let _ = context.blake3_hash(data);

            times.push(start.elapsed());
        }

        result.calculate_stats(&times);
        result
    }

    /// Run all benchmarks
    pub async fn run_all_benchmarks(iterations: u64) -> Vec<BenchmarkResult> {
        println!("\n╔══════════════════════════════════════════════╗");
        println!("║     AVO WASM VM Performance Benchmarks      ║");
        println!("╚══════════════════════════════════════════════╝");
        println!("\nRunning {} iterations per benchmark...\n", iterations);

        let mut results = Vec::new();

        let bench = Self::bench_simple_execution(iterations).await;
        bench.print();
        results.push(bench);

        let bench = Self::bench_arithmetic_ops(iterations).await;
        bench.print();
        results.push(bench);

        let bench = Self::bench_loop_execution(iterations).await;
        bench.print();
        results.push(bench);

        let bench = Self::bench_memory_operations(iterations).await;
        bench.print();
        results.push(bench);

        let bench = Self::bench_host_function_calls(iterations).await;
        bench.print();
        results.push(bench);

        let bench = Self::bench_module_caching(iterations).await;
        bench.print();
        results.push(bench);

        let bench = Self::bench_storage_operations(iterations).await;
        bench.print();
        results.push(bench);

        let bench = Self::bench_event_emission(iterations).await;
        bench.print();
        results.push(bench);

        let bench = Self::bench_hashing(iterations).await;
        bench.print();
        results.push(bench);

        println!("\n╔══════════════════════════════════════════════╗");
        println!("║         Benchmarks Completed                 ║");
        println!("╚══════════════════════════════════════════════╝\n");

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_benchmark_simple_execution() {
        let result = WasmBenchmarks::bench_simple_execution(10).await;
        assert_eq!(result.iterations, 10);
        assert!(result.avg_time.as_micros() > 0);
    }

    #[tokio::test]
    async fn test_benchmark_arithmetic() {
        let result = WasmBenchmarks::bench_arithmetic_ops(10).await;
        assert_eq!(result.iterations, 10);
        assert!(result.throughput > 0.0);
    }

    #[tokio::test]
    async fn test_all_benchmarks() {
        let results = WasmBenchmarks::run_all_benchmarks(5).await;
        assert_eq!(results.len(), 9);
        for result in results {
            assert!(result.throughput > 0.0);
        }
    }
}
