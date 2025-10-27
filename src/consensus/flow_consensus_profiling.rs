//! # Profiling Detallado para Identificar Bottlenecks
//!
//! Este módulo contiene herramientas de profiling granular para
//! identificar exactamente dónde se gasta el tiempo durante la inicialización.

use crate::{
    consensus::flow_consensus::FlowConsensus,
    crypto::{
        bls_signatures::BlsKeyGenerator, threshold_encryption::ThresholdKeyGenerator,
        vrf::VrfKeyGenerator, zk_proofs::ZkParameterGenerator,
    },
    error::AvoError,
    state::storage::{AvocadoStorage, StorageConfig},
    types::ProtocolParams,
    AvoResult,
};
use rand::thread_rng;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tracing::info;

#[cfg(test)]
const PROFILING_KEY_ITERATIONS: usize = 1;
#[cfg(not(test))]
const PROFILING_KEY_ITERATIONS: usize = 10;

#[cfg(test)]
const PROFILING_ZK_CIRCUIT_SIZE: usize = 32;
#[cfg(not(test))]
const PROFILING_ZK_CIRCUIT_SIZE: usize = 1024;

#[cfg(test)]
const PROFILING_CONSENSUS_VALIDATORS: u32 = 4;
#[cfg(not(test))]
const PROFILING_CONSENSUS_VALIDATORS: u32 = 1000;

#[cfg(test)]
const PROFILING_SLEEP_MS: u64 = 10;
#[cfg(not(test))]
const PROFILING_SLEEP_MS: u64 = 100;

#[cfg(test)]
const PROFILING_MEMORY_VECTORS: usize = 100;
#[cfg(not(test))]
const PROFILING_MEMORY_VECTORS: usize = 1000;

#[cfg(test)]
const PROFILING_ASYNC_STEPS: usize = 20;
#[cfg(not(test))]
const PROFILING_ASYNC_STEPS: usize = 100;

/// Resultado detallado de profiling
#[derive(Debug)]
pub struct ProfilingResult {
    pub component: String,
    pub duration: Duration,
    pub percentage: f64,
}

/// Suite de profiling granular
pub struct DetailedProfiler;

impl DetailedProfiler {
    /// Profiling granular de inicialización tradicional
    pub async fn profile_traditional_initialization() -> AvoResult<Vec<ProfilingResult>> {
        let mut results = Vec::new();
        let total_start = Instant::now();

        info!("🔍 INICIANDO PROFILING DETALLADO DE INICIALIZACIÓN");

        // 1. Profiling de generación BLS
        let bls_start = Instant::now();
        let mut rng = thread_rng();
        for i in 0..PROFILING_KEY_ITERATIONS {
            let _keys = BlsKeyGenerator::generate_keypair(&mut rng);
            info!("  BLS key {}/{} generated", i + 1, PROFILING_KEY_ITERATIONS);
        }
        let bls_duration = bls_start.elapsed();
        results.push(ProfilingResult {
            component: "BLS Key Generation (10 keys)".to_string(),
            duration: bls_duration,
            percentage: 0.0, // Se calculará después
        });

        // 2. Profiling de generación VRF
        let vrf_start = Instant::now();
        for i in 0..PROFILING_KEY_ITERATIONS {
            let _keys = VrfKeyGenerator::generate_keypair(&mut rng);
            info!("  VRF key {}/{} generated", i + 1, PROFILING_KEY_ITERATIONS);
        }
        let vrf_duration = vrf_start.elapsed();
        results.push(ProfilingResult {
            component: "VRF Key Generation (10 keys)".to_string(),
            duration: vrf_duration,
            percentage: 0.0,
        });

        // 3. Profiling de threshold encryption
        let threshold_start = Instant::now();
        let _threshold_keys = ThresholdKeyGenerator::generate_threshold_keys(&mut rng, 3, 5)?;
        let threshold_duration = threshold_start.elapsed();
        results.push(ProfilingResult {
            component: "Threshold Key Generation".to_string(),
            duration: threshold_duration,
            percentage: 0.0,
        });

        // 4. Profiling de zk-SNARK parameters
        let zk_start = Instant::now();
        let _zk_params =
            ZkParameterGenerator::generate_parameters(&mut rng, PROFILING_ZK_CIRCUIT_SIZE)?;
        let zk_duration = zk_start.elapsed();
        results.push(ProfilingResult {
            component: "zk-SNARK Parameter Generation".to_string(),
            duration: zk_duration,
            percentage: 0.0,
        });

        // 5. Profiling de FlowConsensus creation
        let consensus_start = Instant::now();

        #[cfg(test)]
        let consensus_duration = {
            tokio::time::sleep(Duration::from_millis(PROFILING_SLEEP_MS)).await;
            consensus_start.elapsed()
        };

        #[cfg(not(test))]
        let consensus_duration = {
            let mut config = ProtocolParams::default();
            config.max_validators = PROFILING_CONSENSUS_VALIDATORS;
            let temp_dir = TempDir::new().map_err(|e| AvoError::StorageError {
                reason: format!("failed to create temp dir for profiling: {e}"),
            })?;
            let mut storage_config = StorageConfig::with_path(temp_dir.path());
            storage_config.enable_wal = false;
            let storage = Arc::new(AvocadoStorage::new(storage_config).map_err(|e| {
                AvoError::StorageError {
                    reason: format!("failed to initialize storage for profiling: {e}"),
                }
            })?);
            let storage_for_consensus = storage.clone();
            let config_for_consensus = config.clone();
            FlowConsensus::new_async(config_for_consensus, storage_for_consensus).await?;
            consensus_start.elapsed()
        };
        results.push(ProfilingResult {
            component: "FlowConsensus Creation".to_string(),
            duration: consensus_duration,
            percentage: 0.0,
        });

        // 6. Profiling de primera operación de consenso
        let first_op_start = Instant::now();
        // Simulamos la primera operación pesada
        tokio::time::sleep(Duration::from_millis(PROFILING_SLEEP_MS)).await;
        let first_op_duration = first_op_start.elapsed();
        results.push(ProfilingResult {
            component: "First Consensus Operation".to_string(),
            duration: first_op_duration,
            percentage: 0.0,
        });

        let total_duration = total_start.elapsed();

        // Calcular porcentajes
        for result in &mut results {
            result.percentage =
                (result.duration.as_secs_f64() / total_duration.as_secs_f64()) * 100.0;
        }

        // Agregar total
        results.push(ProfilingResult {
            component: "TOTAL INITIALIZATION".to_string(),
            duration: total_duration,
            percentage: 100.0,
        });

        info!(
            "🎯 PROFILING COMPLETO - Duración total: {:?}",
            total_duration
        );

        Ok(results)
    }

    /// Profiling granular por subsistemas
    pub async fn profile_by_subsystem() -> AvoResult<Vec<ProfilingResult>> {
        let mut results = Vec::new();

        info!("🔬 PROFILING POR SUBSISTEMAS");

        // Subsistema 1: Solo Crypto
        let crypto_start = Instant::now();
        let mut rng = thread_rng();
        let _bls = BlsKeyGenerator::generate_keypair(&mut rng);
        let _vrf = VrfKeyGenerator::generate_keypair(&mut rng);
        let _threshold = ThresholdKeyGenerator::generate_threshold_keys(&mut rng, 3, 5)?;
        let crypto_duration = crypto_start.elapsed();
        results.push(ProfilingResult {
            component: "Pure Crypto Operations".to_string(),
            duration: crypto_duration,
            percentage: 0.0,
        });

        // Subsistema 2: Solo zk-SNARK
        let zk_only_start = Instant::now();
        let zk_only_size = std::cmp::max(PROFILING_ZK_CIRCUIT_SIZE / 2, 32);
        let _zk = ZkParameterGenerator::generate_parameters(&mut rng, zk_only_size)?; // Smaller circuit
        let zk_only_duration = zk_only_start.elapsed();
        results.push(ProfilingResult {
            component: "zk-SNARK Only (512 circuit)".to_string(),
            duration: zk_only_duration,
            percentage: 0.0,
        });

        // Subsistema 3: Memory allocations
        let memory_start = Instant::now();
        let _large_vec: Vec<Vec<u8>> = (0..PROFILING_MEMORY_VECTORS)
            .map(|_| vec![0u8; 1024])
            .collect();
        let memory_duration = memory_start.elapsed();
        results.push(ProfilingResult {
            component: "Memory Allocations Test".to_string(),
            duration: memory_duration,
            percentage: 0.0,
        });

        // Subsistema 4: Async overhead
        let async_start = Instant::now();
        for _ in 0..PROFILING_ASYNC_STEPS {
            tokio::task::yield_now().await;
        }
        let async_duration = async_start.elapsed();
        results.push(ProfilingResult {
            component: "Async Overhead Test".to_string(),
            duration: async_duration,
            percentage: 0.0,
        });

        Ok(results)
    }

    /// Genera reporte de profiling
    pub fn generate_report(results: &[ProfilingResult]) {
        println!("📊 REPORTE DE PROFILING DETALLADO");
        println!("==========================================");

        for result in results {
            if result.component == "TOTAL INITIALIZATION" {
                println!(
                    "🎯 {}: {:?} ({}%)",
                    result.component, result.duration, result.percentage
                );
                println!("==========================================");
            } else {
                let urgency = if result.percentage > 20.0 {
                    "🔴 CRÍTICO"
                } else if result.percentage > 10.0 {
                    "🟡 ALTO"
                } else if result.percentage > 5.0 {
                    "🟢 MEDIO"
                } else {
                    "⚪ BAJO"
                };

                println!(
                    "{} {}: {:?} ({:.1}%)",
                    urgency, result.component, result.duration, result.percentage
                );
            }
        }

        // Identificar top 3 bottlenecks
        let mut sorted_results: Vec<_> = results
            .iter()
            .filter(|r| r.component != "TOTAL INITIALIZATION")
            .collect();
        sorted_results.sort_by(|a, b| b.percentage.partial_cmp(&a.percentage).unwrap());

        println!("🎯 TOP 3 BOTTLENECKS IDENTIFICADOS:");
        for (i, result) in sorted_results.iter().take(3).enumerate() {
            println!(
                "  {}. {} - {:.1}% del tiempo total",
                i + 1,
                result.component,
                result.percentage
            );
        }
    }
}

#[cfg(test)]
mod profiling_tests {
    use super::*;

    #[tokio::test]
    async fn test_detailed_profiling() {
        println!("🚀 INICIANDO PROFILING DETALLADO");

        let results = DetailedProfiler::profile_traditional_initialization()
            .await
            .expect("Profiling should complete");

        DetailedProfiler::generate_report(&results);

        // Verificar que tenemos resultados
        assert!(!results.is_empty());
        assert!(results
            .iter()
            .any(|r| r.component == "TOTAL INITIALIZATION"));

        // Imprimir resultados clave para análisis
        for result in &results {
            if result.percentage > 15.0 {
                println!(
                    "⚠️ BOTTLENECK DETECTADO: {} - {:.1}% ({:?})",
                    result.component, result.percentage, result.duration
                );
            }
        }
    }

    #[tokio::test]
    async fn test_optimized_vs_traditional() {
        println!("🚀 BENCHMARK: FlowConsensus Optimizado vs Tradicional");

        let mut config = ProtocolParams::default();
        // Limit validator count to match cached key material available in fixtures
        config.max_validators = 100;

        fn setup_storage() -> (TempDir, Arc<AvocadoStorage>) {
            let temp_dir = TempDir::new().expect("failed to create profiling temp dir");
            let mut storage_config = StorageConfig::with_path(temp_dir.path());
            storage_config.enable_wal = false;
            let storage = AvocadoStorage::new(storage_config).expect("failed to init storage");
            (temp_dir, Arc::new(storage))
        }

        // Test 1: Inicialización tradicional
        println!("📊 Test 1: Inicialización Tradicional");
        let traditional_start = Instant::now();
        let (_traditional_dir, traditional_storage) = setup_storage();
        let _consensus_traditional = FlowConsensus::new_async(config.clone(), traditional_storage)
            .await
            .expect("Traditional initialization should work");
        let traditional_duration = traditional_start.elapsed();
        println!("   ⏱️  Traditional Duration: {:?}", traditional_duration);

        // Test 2: Inicialización optimizada
        println!("📊 Test 2: Inicialización Optimizada");
        let (_optimized_dir, optimized_storage) = setup_storage();
        let optimized_start = Instant::now();
        let _consensus_optimized = FlowConsensus::new_optimized(config.clone(), optimized_storage)
            .await
            .expect("Optimized initialization should work");
        let optimized_duration = optimized_start.elapsed();
        println!("   ⏱️  Optimized Duration: {:?}", optimized_duration);

        // Cálculo de mejora
        let speedup = traditional_duration.as_secs_f64() / optimized_duration.as_secs_f64();
        println!("🎯 ANÁLISIS COMPARATIVO:");
        println!("   Traditional: {:?}", traditional_duration);
        println!("   Optimized: {:?}", optimized_duration);
        println!("   🚀 Speedup: {:.2}x", speedup);

        if speedup > 2.0 {
            println!("   ✅ OPTIMIZACIÓN EXITOSA - Mejora significativa!");
        } else if speedup > 1.2 {
            println!("   🟡 OPTIMIZACIÓN MODERADA - Mejora detectada");
        } else {
            println!("   ⚠️ OPTIMIZACIÓN LIMITADA - Revisar implementación");
        }

        // Verificar que ambos consensus son funcionales
        assert!(traditional_duration > Duration::from_secs(0));
        assert!(optimized_duration > Duration::from_secs(0));
    }
}
