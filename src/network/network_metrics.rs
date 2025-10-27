//! # Sistema de métricas de red avanzadas para AVO Protocol
//!
//! Proporciona medición en tiempo real de:
//! - Bandwidth de red por nodo y global
//! - Ratio de transacciones cross-shard
//! - Métricas de protección MEV
//! - Latencia y throughput

use crate::error::*;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Configuración para métricas de red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetricsConfig {
    /// Ventana de tiempo para promedios (segundos)
    pub measurement_window_secs: u64,
    /// Intervalo de cálculo de métricas (segundos)
    pub calculation_interval_secs: u64,
    /// Número máximo de samples para mantener
    pub max_samples: usize,
    /// Threshold para alertas de bandwidth
    pub bandwidth_alert_threshold_mbps: f64,
    /// Threshold para alertas de latencia
    pub latency_alert_threshold_ms: f64,
}

impl Default for NetworkMetricsConfig {
    fn default() -> Self {
        Self {
            measurement_window_secs: 60,           // 1 minuto
            calculation_interval_secs: 10,         // Cada 10 segundos
            max_samples: 1000,                     // Máximo 1000 samples
            bandwidth_alert_threshold_mbps: 100.0, // 100 Mbps
            latency_alert_threshold_ms: 1000.0,    // 1 segundo
        }
    }
}

/// Sample de datos de red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSample {
    pub timestamp: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub latency_ms: f64,
    pub active_connections: usize,
}

/// Métricas agregadas de red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedNetworkMetrics {
    pub bandwidth_mbps_out: f64,
    pub bandwidth_mbps_in: f64,
    pub bandwidth_mbps_total: f64,
    pub average_latency_ms: f64,
    pub peak_latency_ms: f64,
    pub packet_loss_ratio: f64,
    pub connection_count: usize,
    pub bytes_per_second_out: f64,
    pub bytes_per_second_in: f64,
    pub measurement_period_secs: u64,
}

/// Métricas de transacciones cross-shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardMetrics {
    pub total_transactions: u64,
    pub cross_shard_transactions: u64,
    pub intra_shard_transactions: u64,
    pub cross_shard_ratio: f64,
    pub average_cross_shard_latency_ms: f64,
    pub cross_shard_success_rate: f64,
}

/// Métricas de protección MEV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MEVProtectionMetrics {
    pub total_blocks: u64,
    pub mev_protected_blocks: u64,
    pub protection_ratio: f64,
    pub threshold_encrypted_txs: u64,
    pub revealed_txs: u64,
    pub redistribution_amount: u64,
    pub burn_amount: u64,
    pub validator_rewards: u64,
    pub treasury_amount: u64,
}

/// Collector principal de métricas de red
#[derive(Debug)]
pub struct NetworkMetricsCollector {
    config: NetworkMetricsConfig,

    // Contadores atómicos para threads concurrentes
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    packets_sent: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,

    // Samples históricos
    network_samples: Arc<RwLock<VecDeque<NetworkSample>>>,

    // Métricas agregadas actuales
    current_metrics: Arc<RwLock<AggregatedNetworkMetrics>>,
    cross_shard_metrics: Arc<RwLock<CrossShardMetrics>>,
    mev_metrics: Arc<RwLock<MEVProtectionMetrics>>,

    // Tracking de latencia
    latency_samples: Arc<RwLock<VecDeque<(Instant, f64)>>>,

    // Estado del collector
    is_running: Arc<RwLock<bool>>,
    start_time: Instant,
}

impl NetworkMetricsCollector {
    /// Crear nuevo collector
    pub fn new(config: NetworkMetricsConfig) -> Self {
        info!("🔬 Initializing Network Metrics Collector");
        info!(
            "📊 Measurement window: {}s, Calculation interval: {}s",
            config.measurement_window_secs, config.calculation_interval_secs
        );

        Self {
            config,
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            network_samples: Arc::new(RwLock::new(VecDeque::new())),
            current_metrics: Arc::new(RwLock::new(AggregatedNetworkMetrics::default())),
            cross_shard_metrics: Arc::new(RwLock::new(CrossShardMetrics::default())),
            mev_metrics: Arc::new(RwLock::new(MEVProtectionMetrics::default())),
            latency_samples: Arc::new(RwLock::new(VecDeque::new())),
            is_running: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
        }
    }

    /// Iniciar collection de métricas
    pub async fn start(&self) -> AvoResult<()> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(AvoError::network("Metrics collector already running"));
        }
        *is_running = true;
        drop(is_running);

        // Iniciar loop de cálculo de métricas
        self.start_calculation_loop().await;

        info!("✅ Network Metrics Collector started");
        Ok(())
    }

    /// Detener collection
    pub async fn stop(&self) {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        info!("🛑 Network Metrics Collector stopped");
    }

    /// Iniciar loop de cálculo de métricas
    async fn start_calculation_loop(&self) {
        let bytes_sent = Arc::clone(&self.bytes_sent);
        let bytes_received = Arc::clone(&self.bytes_received);
        let packets_sent = Arc::clone(&self.packets_sent);
        let packets_received = Arc::clone(&self.packets_received);
        let network_samples = Arc::clone(&self.network_samples);
        let current_metrics = Arc::clone(&self.current_metrics);
        let latency_samples = Arc::clone(&self.latency_samples);
        let is_running = Arc::clone(&self.is_running);
        let config = self.config.clone();

        tokio::spawn(async move {
            let interval = Duration::from_secs(config.calculation_interval_secs);

            while *is_running.read().await {
                // Crear sample actual
                let sample = NetworkSample {
                    timestamp: SystemTime::now(),
                    bytes_sent: bytes_sent.load(Ordering::Relaxed),
                    bytes_received: bytes_received.load(Ordering::Relaxed),
                    packets_sent: packets_sent.load(Ordering::Relaxed),
                    packets_received: packets_received.load(Ordering::Relaxed),
                    latency_ms: Self::calculate_current_latency(&latency_samples).await,
                    active_connections: 0, // Se actualizará desde P2P manager
                };

                // Agregar sample y calcular métricas
                {
                    let mut samples = network_samples.write().await;
                    samples.push_back(sample.clone());

                    // Mantener solo los samples dentro de la ventana
                    let cutoff_time =
                        SystemTime::now() - Duration::from_secs(config.measurement_window_secs);
                    while let Some(front) = samples.front() {
                        if front.timestamp < cutoff_time {
                            samples.pop_front();
                        } else {
                            break;
                        }
                    }

                    // Limitar número máximo de samples
                    while samples.len() > config.max_samples {
                        samples.pop_front();
                    }
                }

                // Calcular métricas agregadas
                Self::calculate_aggregated_metrics(
                    &network_samples,
                    &current_metrics,
                    config.measurement_window_secs,
                )
                .await;

                tokio::time::sleep(interval).await;
            }
        });
    }

    /// Registrar bytes enviados
    pub fn record_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Registrar bytes recibidos
    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Registrar packets enviados
    pub fn record_packets_sent(&self, count: u64) {
        self.packets_sent.fetch_add(count, Ordering::Relaxed);
    }

    /// Registrar packets recibidos
    pub fn record_packets_received(&self, count: u64) {
        self.packets_received.fetch_add(count, Ordering::Relaxed);
    }

    /// Registrar muestra de latencia
    pub async fn record_latency(&self, latency_ms: f64) {
        let mut samples = self.latency_samples.write().await;
        samples.push_back((Instant::now(), latency_ms));

        // Mantener solo samples recientes
        let cutoff = Instant::now() - Duration::from_secs(self.config.measurement_window_secs);
        while let Some((timestamp, _)) = samples.front() {
            if *timestamp < cutoff {
                samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Calcular latencia actual promedio
    async fn calculate_current_latency(
        latency_samples: &Arc<RwLock<VecDeque<(Instant, f64)>>>,
    ) -> f64 {
        let samples = latency_samples.read().await;
        if samples.is_empty() {
            return 0.0;
        }

        let sum: f64 = samples.iter().map(|(_, latency)| latency).sum();
        sum / samples.len() as f64
    }

    /// Calcular métricas agregadas
    async fn calculate_aggregated_metrics(
        network_samples: &Arc<RwLock<VecDeque<NetworkSample>>>,
        current_metrics: &Arc<RwLock<AggregatedNetworkMetrics>>,
        window_secs: u64,
    ) {
        let samples = network_samples.read().await;
        if samples.len() < 2 {
            return;
        }

        let oldest = samples.front().unwrap();
        let newest = samples.back().unwrap();

        let time_diff = newest
            .timestamp
            .duration_since(oldest.timestamp)
            .unwrap_or(Duration::from_secs(1))
            .as_secs_f64();

        if time_diff <= 0.0 {
            return;
        }

        let bytes_sent_diff = newest.bytes_sent.saturating_sub(oldest.bytes_sent);
        let bytes_received_diff = newest.bytes_received.saturating_sub(oldest.bytes_received);

        let bytes_per_sec_out = bytes_sent_diff as f64 / time_diff;
        let bytes_per_sec_in = bytes_received_diff as f64 / time_diff;

        // Convertir a Mbps (megabits por segundo)
        let bandwidth_out = (bytes_per_sec_out * 8.0) / 1_000_000.0;
        let bandwidth_in = (bytes_per_sec_in * 8.0) / 1_000_000.0;

        // Calcular latencia promedio y pico
        let latencies: Vec<f64> = samples.iter().map(|s| s.latency_ms).collect();
        let avg_latency = if latencies.is_empty() {
            0.0
        } else {
            latencies.iter().sum::<f64>() / latencies.len() as f64
        };
        let peak_latency: f64 = latencies.iter().fold(0.0_f64, |acc, &x| acc.max(x));

        let metrics = AggregatedNetworkMetrics {
            bandwidth_mbps_out: bandwidth_out,
            bandwidth_mbps_in: bandwidth_in,
            bandwidth_mbps_total: bandwidth_out + bandwidth_in,
            average_latency_ms: avg_latency,
            peak_latency_ms: peak_latency,
            packet_loss_ratio: 0.0, // Simplificado por ahora
            connection_count: newest.active_connections,
            bytes_per_second_out: bytes_per_sec_out,
            bytes_per_second_in: bytes_per_sec_in,
            measurement_period_secs: window_secs,
        };

        *current_metrics.write().await = metrics;
    }

    /// Registrar transacción cross-shard
    pub async fn record_cross_shard_transaction(&self, latency_ms: f64, success: bool) {
        let mut metrics = self.cross_shard_metrics.write().await;
        metrics.total_transactions += 1;
        metrics.cross_shard_transactions += 1;

        // Actualizar latencia promedio
        let total_latency =
            metrics.average_cross_shard_latency_ms * (metrics.cross_shard_transactions - 1) as f64;
        metrics.average_cross_shard_latency_ms =
            (total_latency + latency_ms) / metrics.cross_shard_transactions as f64;

        // Actualizar success rate
        if success {
            let successful_txs = (metrics.cross_shard_success_rate
                * (metrics.cross_shard_transactions - 1) as f64)
                + 1.0;
            metrics.cross_shard_success_rate =
                successful_txs / metrics.cross_shard_transactions as f64;
        } else {
            let successful_txs =
                metrics.cross_shard_success_rate * (metrics.cross_shard_transactions - 1) as f64;
            metrics.cross_shard_success_rate =
                successful_txs / metrics.cross_shard_transactions as f64;
        }

        // Recalcular ratio
        metrics.cross_shard_ratio =
            metrics.cross_shard_transactions as f64 / metrics.total_transactions as f64;
    }

    /// Registrar transacción intra-shard
    pub async fn record_intra_shard_transaction(&self) {
        let mut metrics = self.cross_shard_metrics.write().await;
        metrics.total_transactions += 1;
        metrics.intra_shard_transactions += 1;

        // Recalcular ratio
        metrics.cross_shard_ratio =
            metrics.cross_shard_transactions as f64 / metrics.total_transactions as f64;
    }

    /// Registrar bloque con protección MEV
    pub async fn record_mev_protected_block(&self, redistributed_amount: u64) {
        let mut metrics = self.mev_metrics.write().await;
        metrics.total_blocks += 1;
        metrics.mev_protected_blocks += 1;
        metrics.redistribution_amount += redistributed_amount;

        // Distribución: 40% burn, 30% validators, 30% treasury
        metrics.burn_amount += (redistributed_amount * 40) / 100;
        metrics.validator_rewards += (redistributed_amount * 30) / 100;
        metrics.treasury_amount += (redistributed_amount * 30) / 100;

        // Recalcular ratio
        metrics.protection_ratio =
            metrics.mev_protected_blocks as f64 / metrics.total_blocks as f64;
    }

    /// Registrar bloque sin protección MEV
    pub async fn record_regular_block(&self) {
        let mut metrics = self.mev_metrics.write().await;
        metrics.total_blocks += 1;

        // Recalcular ratio
        metrics.protection_ratio =
            metrics.mev_protected_blocks as f64 / metrics.total_blocks as f64;
    }

    /// Obtener métricas actuales de red
    pub async fn get_network_metrics(&self) -> AggregatedNetworkMetrics {
        self.current_metrics.read().await.clone()
    }

    /// Obtener métricas cross-shard
    pub async fn get_cross_shard_metrics(&self) -> CrossShardMetrics {
        self.cross_shard_metrics.read().await.clone()
    }

    /// Obtener métricas MEV
    pub async fn get_mev_metrics(&self) -> MEVProtectionMetrics {
        self.mev_metrics.read().await.clone()
    }

    /// Obtener todas las métricas en un reporte completo
    pub async fn get_comprehensive_report(&self) -> NetworkMetricsReport {
        NetworkMetricsReport {
            network: self.get_network_metrics().await,
            cross_shard: self.get_cross_shard_metrics().await,
            mev_protection: self.get_mev_metrics().await,
            uptime_secs: self.start_time.elapsed().as_secs(),
            timestamp: SystemTime::now(),
        }
    }
}

/// Reporte completo de métricas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetricsReport {
    pub network: AggregatedNetworkMetrics,
    pub cross_shard: CrossShardMetrics,
    pub mev_protection: MEVProtectionMetrics,
    pub uptime_secs: u64,
    pub timestamp: SystemTime,
}

impl Default for AggregatedNetworkMetrics {
    fn default() -> Self {
        Self {
            bandwidth_mbps_out: 0.0,
            bandwidth_mbps_in: 0.0,
            bandwidth_mbps_total: 0.0,
            average_latency_ms: 0.0,
            peak_latency_ms: 0.0,
            packet_loss_ratio: 0.0,
            connection_count: 0,
            bytes_per_second_out: 0.0,
            bytes_per_second_in: 0.0,
            measurement_period_secs: 60,
        }
    }
}

impl Default for CrossShardMetrics {
    fn default() -> Self {
        Self {
            total_transactions: 0,
            cross_shard_transactions: 0,
            intra_shard_transactions: 0,
            cross_shard_ratio: 0.0,
            average_cross_shard_latency_ms: 0.0,
            cross_shard_success_rate: 1.0,
        }
    }
}

impl Default for MEVProtectionMetrics {
    fn default() -> Self {
        Self {
            total_blocks: 0,
            mev_protected_blocks: 0,
            protection_ratio: 1.0, // Empezar optimista
            threshold_encrypted_txs: 0,
            revealed_txs: 0,
            redistribution_amount: 0,
            burn_amount: 0,
            validator_rewards: 0,
            treasury_amount: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_metrics_collector() {
        let collector = NetworkMetricsCollector::new(NetworkMetricsConfig::default());

        // Iniciar collector
        assert!(collector.start().await.is_ok());

        // Registrar algunos datos
        collector.record_bytes_sent(1000);
        collector.record_bytes_received(2000);
        collector.record_latency(50.0).await;

        // Esperar un poco para que se calculen métricas
        sleep(Duration::from_millis(100)).await;

        // Verificar métricas
        let metrics = collector.get_network_metrics().await;
        assert_eq!(metrics.measurement_period_secs, 60);

        // Detener collector
        collector.stop().await;
    }

    #[tokio::test]
    async fn test_cross_shard_metrics() {
        let collector = NetworkMetricsCollector::new(NetworkMetricsConfig::default());

        // Registrar transacciones
        collector.record_cross_shard_transaction(100.0, true).await;
        collector.record_intra_shard_transaction().await;
        collector.record_cross_shard_transaction(150.0, false).await;

        let metrics = collector.get_cross_shard_metrics().await;
        assert_eq!(metrics.total_transactions, 3);
        assert_eq!(metrics.cross_shard_transactions, 2);
        assert_eq!(metrics.intra_shard_transactions, 1);
        assert!((metrics.cross_shard_ratio - 0.6667).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_mev_metrics() {
        let collector = NetworkMetricsCollector::new(NetworkMetricsConfig::default());

        // Registrar bloques
        collector.record_mev_protected_block(1000).await;
        collector.record_regular_block().await;
        collector.record_mev_protected_block(2000).await;

        let metrics = collector.get_mev_metrics().await;
        assert_eq!(metrics.total_blocks, 3);
        assert_eq!(metrics.mev_protected_blocks, 2);
        assert!((metrics.protection_ratio - 0.6667).abs() < 0.001);
        assert_eq!(metrics.redistribution_amount, 3000);
        assert_eq!(metrics.burn_amount, 1200); // 40% of 3000
    }
}
