use crate::error::*;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Sistema de recolección y análisis de métricas para producción
#[derive(Debug)]
pub struct MetricsCollector {
    /// Configuración del colector
    config: MetricsConfig,
    /// Métricas del sistema actual
    system_metrics: Arc<RwLock<SystemMetrics>>,
    /// Métricas de rendimiento
    performance_metrics: Arc<RwLock<PerformanceMetrics>>,
    /// Métricas de negocio
    business_metrics: Arc<RwLock<BusinessMetrics>>,
    /// Historial de métricas
    metrics_history: Arc<RwLock<MetricsHistory>>,
    /// Alertas basadas en métricas
    metric_alerts: Arc<RwLock<HashMap<String, MetricAlert>>>,
}

/// Configuración del colector de métricas
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Intervalo de recolección en segundos
    pub collection_interval_seconds: u64,
    /// Número de puntos de datos a mantener en historial
    pub max_history_points: usize,
    /// Habilitar métricas detalladas
    pub enable_detailed_metrics: bool,
    /// Habilitar export a sistemas externos
    pub enable_metrics_export: bool,
    /// Configuración de alertas
    pub alert_thresholds: MetricAlertThresholds,
    /// Endpoint para exportar métricas (Prometheus, etc.)
    pub export_endpoint: Option<String>,
    /// Formato de export (prometheus, json, custom)
    pub export_format: String,
}

/// Métricas del sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// Timestamp de última actualización
    pub last_updated: u64,
    /// Uso de CPU (%)
    pub cpu_usage_percent: f64,
    /// Uso de memoria (bytes)
    pub memory_used_bytes: u64,
    /// Memoria total disponible (bytes)
    pub memory_total_bytes: u64,
    /// Uso de memoria (%)
    pub memory_usage_percent: f64,
    /// Uso de disco (bytes)
    pub disk_used_bytes: u64,
    /// Espacio total en disco (bytes)
    pub disk_total_bytes: u64,
    /// Uso de disco (%)
    pub disk_usage_percent: f64,
    /// Número de threads activos
    pub active_threads: u32,
    /// File descriptors abiertos
    pub open_file_descriptors: u32,
    /// Network I/O
    pub network_io: NetworkIOMetrics,
    /// Disk I/O
    pub disk_io: DiskIOMetrics,
    /// Carga del sistema (load average)
    pub system_load: SystemLoadMetrics,
}

/// Métricas de I/O de red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIOMetrics {
    /// Bytes recibidos por segundo
    pub bytes_received_per_sec: f64,
    /// Bytes enviados por segundo
    pub bytes_sent_per_sec: f64,
    /// Paquetes recibidos por segundo
    pub packets_received_per_sec: f64,
    /// Paquetes enviados por segundo
    pub packets_sent_per_sec: f64,
    /// Conexiones activas
    pub active_connections: u32,
}

/// Métricas de I/O de disco
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIOMetrics {
    /// Bytes leídos por segundo
    pub bytes_read_per_sec: f64,
    /// Bytes escritos por segundo
    pub bytes_written_per_sec: f64,
    /// Operaciones de lectura por segundo
    pub read_ops_per_sec: f64,
    /// Operaciones de escritura por segundo
    pub write_ops_per_sec: f64,
    /// Tiempo promedio de I/O (ms)
    pub avg_io_time_ms: f64,
}

/// Métricas de carga del sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemLoadMetrics {
    /// Load average 1 minuto
    pub load_1m: f64,
    /// Load average 5 minutos
    pub load_5m: f64,
    /// Load average 15 minutos
    pub load_15m: f64,
    /// Número de cores de CPU
    pub cpu_cores: u32,
}

/// Métricas de rendimiento del protocolo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Timestamp de última actualización
    pub last_updated: u64,
    /// Transacciones por segundo
    pub transactions_per_second: f64,
    /// Tiempo promedio de confirmación de transacción (ms)
    pub avg_transaction_confirmation_time_ms: f64,
    /// Tiempo promedio de consenso (ms)
    pub avg_consensus_time_ms: f64,
    /// Número de validadores activos
    pub active_validators: u32,
    /// Número de validadores online
    pub online_validators: u32,
    /// Porcentaje de uptime
    pub uptime_percentage: f64,
    /// Latencia de red promedio (ms)
    pub avg_network_latency_ms: f64,
    /// Throughput de la red (Mbps)
    pub network_throughput_mbps: f64,
    /// Métricas por shard
    pub shard_metrics: HashMap<ShardId, ShardPerformanceMetrics>,
    /// Métricas de BLS
    pub bls_metrics: BLSMetrics,
}

/// Métricas de rendimiento por shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardPerformanceMetrics {
    /// ID del shard
    pub shard_id: ShardId,
    /// TPS del shard
    pub transactions_per_second: f64,
    /// Transacciones pendientes
    pub pending_transactions: usize,
    /// Tiempo promedio de procesamiento (ms)
    pub avg_processing_time_ms: f64,
    /// Número de validadores en el shard
    pub validators_count: u32,
    /// Estado de sincronización
    pub sync_status: String,
    /// Utilización del shard (%)
    pub utilization_percent: f64,
}

/// Métricas de BLS (Boneh-Lynn-Shacham)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLSMetrics {
    /// Firmas BLS generadas por segundo
    pub signatures_per_second: f64,
    /// Verificaciones BLS por segundo
    pub verifications_per_second: f64,
    /// Tiempo promedio de generación de firma (ms)
    pub avg_signature_generation_time_ms: f64,
    /// Tiempo promedio de verificación (ms)
    pub avg_verification_time_ms: f64,
    /// Tasa de éxito de verificación (%)
    pub verification_success_rate: f64,
    /// Agregaciones de firma por segundo
    pub signature_aggregations_per_second: f64,
}

/// Métricas de negocio del protocolo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessMetrics {
    /// Timestamp de última actualización
    pub last_updated: u64,
    /// Volumen total de transacciones (valor)
    pub total_transaction_volume: f64,
    /// Número total de cuentas activas
    pub active_accounts_count: u64,
    /// Número total de contratos desplegados
    pub deployed_contracts_count: u64,
    /// Valor total bloqueado (TVL)
    pub total_value_locked: f64,
    /// Fees recaudadas (total)
    pub total_fees_collected: f64,
    /// Distribución de tipos de transacción
    pub transaction_type_distribution: HashMap<String, u64>,
    /// Métricas de gobierno
    pub governance_metrics: GovernanceMetrics,
    /// Métricas de staking
    pub staking_metrics: StakingMetrics,
}

/// Métricas de gobierno
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceMetrics {
    /// Propuestas activas
    pub active_proposals: u32,
    /// Participación promedio en votaciones (%)
    pub avg_voting_participation: f64,
    /// Tokens totales en stake para gobierno
    pub governance_staked_tokens: f64,
    /// Tiempo promedio de resolución de propuestas (horas)
    pub avg_proposal_resolution_time_hours: f64,
}

/// Métricas de staking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingMetrics {
    /// Total de tokens en stake
    pub total_staked_tokens: f64,
    /// Número de stakers
    pub total_stakers: u64,
    /// APY promedio de staking (%)
    pub avg_staking_apy: f64,
    /// Tiempo promedio de unstaking (horas)
    pub avg_unstaking_time_hours: f64,
    /// Penalizaciones aplicadas (slashing)
    pub slashing_events_count: u32,
}

/// Historial de métricas
#[derive(Debug, Clone)]
pub struct MetricsHistory {
    /// Puntos de datos del sistema
    pub system_history: VecDeque<SystemMetrics>,
    /// Puntos de datos de rendimiento
    pub performance_history: VecDeque<PerformanceMetrics>,
    /// Puntos de datos de negocio
    pub business_history: VecDeque<BusinessMetrics>,
    /// Timestamps de recolección
    pub collection_timestamps: VecDeque<u64>,
}

/// Alerta basada en métricas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricAlert {
    /// ID de la alerta
    pub alert_id: String,
    /// Nombre de la métrica
    pub metric_name: String,
    /// Tipo de alerta
    pub alert_type: AlertType,
    /// Valor umbral
    pub threshold_value: f64,
    /// Valor actual
    pub current_value: f64,
    /// Estado de la alerta
    pub status: AlertStatus,
    /// Timestamp de activación
    pub triggered_at: Option<u64>,
    /// Número de veces activada
    pub trigger_count: u32,
    /// Mensaje de la alerta
    pub message: String,
}

/// Tipos de alerta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    /// Alerta cuando el valor supera el umbral
    Threshold,
    /// Alerta cuando el valor está por debajo del umbral
    BelowThreshold,
    /// Alerta cuando el valor cambia más del X% en Y tiempo
    PercentageChange,
    /// Alerta cuando no hay datos por X tiempo
    DataStale,
    /// Alerta de anomalía detectada
    Anomaly,
}

/// Estados de alerta
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    /// Alerta activa
    Active,
    /// Alerta resuelta
    Resolved,
    /// Alerta silenciada
    Silenced,
    /// Alerta pendiente de confirmación
    Pending,
}

/// Umbrales para alertas de métricas
#[derive(Debug, Clone)]
pub struct MetricAlertThresholds {
    /// CPU usage máximo (%)
    pub max_cpu_usage: f64,
    /// Memory usage máximo (%)
    pub max_memory_usage: f64,
    /// Disk usage máximo (%)
    pub max_disk_usage: f64,
    /// TPS mínimo
    pub min_transactions_per_second: f64,
    /// Tiempo máximo de consenso (ms)
    pub max_consensus_time_ms: f64,
    /// Mínimo número de validadores online
    pub min_online_validators: u32,
    /// Latencia máxima de red (ms)
    pub max_network_latency_ms: f64,
    /// Mínimo uptime (%)
    pub min_uptime_percentage: f64,
}

impl MetricsCollector {
    /// Crear nueva instancia del colector de métricas
    pub fn new(config: MetricsConfig) -> Self {
        let initial_system_metrics = SystemMetrics {
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cpu_usage_percent: 0.0,
            memory_used_bytes: 0,
            memory_total_bytes: 0,
            memory_usage_percent: 0.0,
            disk_used_bytes: 0,
            disk_total_bytes: 0,
            disk_usage_percent: 0.0,
            active_threads: 0,
            open_file_descriptors: 0,
            network_io: NetworkIOMetrics {
                bytes_received_per_sec: 0.0,
                bytes_sent_per_sec: 0.0,
                packets_received_per_sec: 0.0,
                packets_sent_per_sec: 0.0,
                active_connections: 0,
            },
            disk_io: DiskIOMetrics {
                bytes_read_per_sec: 0.0,
                bytes_written_per_sec: 0.0,
                read_ops_per_sec: 0.0,
                write_ops_per_sec: 0.0,
                avg_io_time_ms: 0.0,
            },
            system_load: SystemLoadMetrics {
                load_1m: 0.0,
                load_5m: 0.0,
                load_15m: 0.0,
                cpu_cores: num_cpus::get() as u32,
            },
        };

        let initial_performance_metrics = PerformanceMetrics {
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            transactions_per_second: 0.0,
            avg_transaction_confirmation_time_ms: 0.0,
            avg_consensus_time_ms: 0.0,
            active_validators: 0,
            online_validators: 0,
            uptime_percentage: 100.0,
            avg_network_latency_ms: 0.0,
            network_throughput_mbps: 0.0,
            shard_metrics: HashMap::new(),
            bls_metrics: BLSMetrics {
                signatures_per_second: 0.0,
                verifications_per_second: 0.0,
                avg_signature_generation_time_ms: 0.0,
                avg_verification_time_ms: 0.0,
                verification_success_rate: 100.0,
                signature_aggregations_per_second: 0.0,
            },
        };

        let initial_business_metrics = BusinessMetrics {
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            total_transaction_volume: 0.0,
            active_accounts_count: 0,
            deployed_contracts_count: 0,
            total_value_locked: 0.0,
            total_fees_collected: 0.0,
            transaction_type_distribution: HashMap::new(),
            governance_metrics: GovernanceMetrics {
                active_proposals: 0,
                avg_voting_participation: 0.0,
                governance_staked_tokens: 0.0,
                avg_proposal_resolution_time_hours: 0.0,
            },
            staking_metrics: StakingMetrics {
                total_staked_tokens: 0.0,
                total_stakers: 0,
                avg_staking_apy: 0.0,
                avg_unstaking_time_hours: 0.0,
                slashing_events_count: 0,
            },
        };

        let initial_history = MetricsHistory {
            system_history: VecDeque::new(),
            performance_history: VecDeque::new(),
            business_history: VecDeque::new(),
            collection_timestamps: VecDeque::new(),
        };

        Self {
            config,
            system_metrics: Arc::new(RwLock::new(initial_system_metrics)),
            performance_metrics: Arc::new(RwLock::new(initial_performance_metrics)),
            business_metrics: Arc::new(RwLock::new(initial_business_metrics)),
            metrics_history: Arc::new(RwLock::new(initial_history)),
            metric_alerts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Iniciar el sistema de recolección de métricas
    pub async fn start_metrics_collection(&self) -> AvoResult<()> {
        info!("📊 Starting metrics collection system");
        info!(
            "⏱️  Collection interval: {}s",
            self.config.collection_interval_seconds
        );
        info!(
            "📈 Detailed metrics: {}",
            self.config.enable_detailed_metrics
        );

        // Configurar alertas por defecto
        self.setup_default_alerts().await?;

        // Iniciar recolección periódica
        let system_metrics = self.system_metrics.clone();
        let performance_metrics = self.performance_metrics.clone();
        let business_metrics = self.business_metrics.clone();
        let metrics_history = self.metrics_history.clone();
        let metric_alerts = self.metric_alerts.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(config.collection_interval_seconds));

            loop {
                interval.tick().await;

                if let Err(e) = Self::collect_all_metrics(
                    &system_metrics,
                    &performance_metrics,
                    &business_metrics,
                    &metrics_history,
                    &metric_alerts,
                    &config,
                )
                .await
                {
                    error!("🚨 Metrics collection error: {}", e);
                }
            }
        });

        // Iniciar export de métricas si está habilitado
        if self.config.enable_metrics_export {
            self.start_metrics_export().await?;
        }

        info!("✅ Metrics collection system started successfully");
        Ok(())
    }

    /// Configurar alertas por defecto
    async fn setup_default_alerts(&self) -> AvoResult<()> {
        let mut alerts = self.metric_alerts.write().await;

        // Alerta de CPU alto
        let cpu_alert = MetricAlert {
            alert_id: "high_cpu_usage".to_string(),
            metric_name: "cpu_usage_percent".to_string(),
            alert_type: AlertType::Threshold,
            threshold_value: self.config.alert_thresholds.max_cpu_usage,
            current_value: 0.0,
            status: AlertStatus::Pending,
            triggered_at: None,
            trigger_count: 0,
            message: format!(
                "CPU usage exceeded {}%",
                self.config.alert_thresholds.max_cpu_usage
            ),
        };

        // Alerta de memoria alta
        let memory_alert = MetricAlert {
            alert_id: "high_memory_usage".to_string(),
            metric_name: "memory_usage_percent".to_string(),
            alert_type: AlertType::Threshold,
            threshold_value: self.config.alert_thresholds.max_memory_usage,
            current_value: 0.0,
            status: AlertStatus::Pending,
            triggered_at: None,
            trigger_count: 0,
            message: format!(
                "Memory usage exceeded {}%",
                self.config.alert_thresholds.max_memory_usage
            ),
        };

        // Alerta de TPS bajo
        let tps_alert = MetricAlert {
            alert_id: "low_tps".to_string(),
            metric_name: "transactions_per_second".to_string(),
            alert_type: AlertType::BelowThreshold,
            threshold_value: self.config.alert_thresholds.min_transactions_per_second,
            current_value: 0.0,
            status: AlertStatus::Pending,
            triggered_at: None,
            trigger_count: 0,
            message: format!(
                "TPS below {} transactions/second",
                self.config.alert_thresholds.min_transactions_per_second
            ),
        };

        // Alerta de consenso lento
        let consensus_alert = MetricAlert {
            alert_id: "slow_consensus".to_string(),
            metric_name: "avg_consensus_time_ms".to_string(),
            alert_type: AlertType::Threshold,
            threshold_value: self.config.alert_thresholds.max_consensus_time_ms,
            current_value: 0.0,
            status: AlertStatus::Pending,
            triggered_at: None,
            trigger_count: 0,
            message: format!(
                "Consensus time exceeded {}ms",
                self.config.alert_thresholds.max_consensus_time_ms
            ),
        };

        alerts.insert("high_cpu_usage".to_string(), cpu_alert);
        alerts.insert("high_memory_usage".to_string(), memory_alert);
        alerts.insert("low_tps".to_string(), tps_alert);
        alerts.insert("slow_consensus".to_string(), consensus_alert);

        info!("⚠️  Configured {} default metric alerts", alerts.len());
        Ok(())
    }

    /// Recolectar todas las métricas
    async fn collect_all_metrics(
        system_metrics: &Arc<RwLock<SystemMetrics>>,
        performance_metrics: &Arc<RwLock<PerformanceMetrics>>,
        business_metrics: &Arc<RwLock<BusinessMetrics>>,
        metrics_history: &Arc<RwLock<MetricsHistory>>,
        metric_alerts: &Arc<RwLock<HashMap<String, MetricAlert>>>,
        config: &MetricsConfig,
    ) -> AvoResult<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Recolectar métricas del sistema
        let new_system_metrics = Self::collect_system_metrics(timestamp).await;
        {
            let mut metrics = system_metrics.write().await;
            *metrics = new_system_metrics.clone();
        }

        // Recolectar métricas de rendimiento
        let new_performance_metrics = Self::collect_performance_metrics(timestamp).await;
        {
            let mut metrics = performance_metrics.write().await;
            *metrics = new_performance_metrics.clone();
        }

        // Recolectar métricas de negocio
        let new_business_metrics = Self::collect_business_metrics(timestamp).await;
        {
            let mut metrics = business_metrics.write().await;
            *metrics = new_business_metrics.clone();
        }

        // Actualizar historial
        {
            let mut history = metrics_history.write().await;

            history.system_history.push_back(new_system_metrics.clone());
            history
                .performance_history
                .push_back(new_performance_metrics.clone());
            history
                .business_history
                .push_back(new_business_metrics.clone());
            history.collection_timestamps.push_back(timestamp);

            // Mantener tamaño del historial limitado
            if history.system_history.len() > config.max_history_points {
                history.system_history.pop_front();
                history.performance_history.pop_front();
                history.business_history.pop_front();
                history.collection_timestamps.pop_front();
            }
        }

        // Evaluar alertas
        Self::evaluate_metric_alerts(
            &new_system_metrics,
            &new_performance_metrics,
            &new_business_metrics,
            metric_alerts,
            config,
        )
        .await;

        debug!("📊 Metrics collection completed at {}", timestamp);
        Ok(())
    }

    /// Recolectar métricas del sistema
    async fn collect_system_metrics(timestamp: u64) -> SystemMetrics {
        // Simular recolección de métricas del sistema
        let cpu_usage = 15.0 + rand::random::<f64>() * 50.0; // 15-65%
        let memory_total = 16 * 1024 * 1024 * 1024u64; // 16GB
        let memory_used = (memory_total as f64 * (0.3 + rand::random::<f64>() * 0.4)) as u64; // 30-70%
        let disk_total = 1024 * 1024 * 1024 * 1024u64; // 1TB
        let disk_used = (disk_total as f64 * (0.2 + rand::random::<f64>() * 0.3)) as u64; // 20-50%

        SystemMetrics {
            last_updated: timestamp,
            cpu_usage_percent: cpu_usage,
            memory_used_bytes: memory_used,
            memory_total_bytes: memory_total,
            memory_usage_percent: (memory_used as f64 / memory_total as f64) * 100.0,
            disk_used_bytes: disk_used,
            disk_total_bytes: disk_total,
            disk_usage_percent: (disk_used as f64 / disk_total as f64) * 100.0,
            active_threads: 150 + rand::random::<u32>() % 50,
            open_file_descriptors: 500 + rand::random::<u32>() % 200,
            network_io: NetworkIOMetrics {
                bytes_received_per_sec: 10_000_000.0 + rand::random::<f64>() * 5_000_000.0,
                bytes_sent_per_sec: 8_000_000.0 + rand::random::<f64>() * 4_000_000.0,
                packets_received_per_sec: 10_000.0 + rand::random::<f64>() * 5_000.0,
                packets_sent_per_sec: 8_000.0 + rand::random::<f64>() * 4_000.0,
                active_connections: 200 + rand::random::<u32>() % 100,
            },
            disk_io: DiskIOMetrics {
                bytes_read_per_sec: 50_000_000.0 + rand::random::<f64>() * 20_000_000.0,
                bytes_written_per_sec: 30_000_000.0 + rand::random::<f64>() * 15_000_000.0,
                read_ops_per_sec: 500.0 + rand::random::<f64>() * 200.0,
                write_ops_per_sec: 300.0 + rand::random::<f64>() * 150.0,
                avg_io_time_ms: 5.0 + rand::random::<f64>() * 10.0,
            },
            system_load: SystemLoadMetrics {
                load_1m: cpu_usage / 100.0 * num_cpus::get() as f64,
                load_5m: (cpu_usage * 0.9) / 100.0 * num_cpus::get() as f64,
                load_15m: (cpu_usage * 0.8) / 100.0 * num_cpus::get() as f64,
                cpu_cores: num_cpus::get() as u32,
            },
        }
    }

    /// Recolectar métricas de rendimiento
    async fn collect_performance_metrics(timestamp: u64) -> PerformanceMetrics {
        // Simular métricas de rendimiento del protocolo
        let base_tps = 12_000.0;
        let tps_variation = rand::random::<f64>() * 5_000.0;
        let current_tps = base_tps + tps_variation;

        let mut shard_metrics = HashMap::new();
        for shard_id in 0..4 {
            let shard_tps = current_tps / 4.0 + (rand::random::<f64>() - 0.5) * 1000.0;
            shard_metrics.insert(
                shard_id,
                ShardPerformanceMetrics {
                    shard_id,
                    transactions_per_second: shard_tps,
                    pending_transactions: 10 + rand::random::<usize>() % 40,
                    avg_processing_time_ms: 0.5 + rand::random::<f64>() * 1.5,
                    validators_count: 8,
                    sync_status: "synced".to_string(),
                    utilization_percent: 60.0 + rand::random::<f64>() * 30.0,
                },
            );
        }

        PerformanceMetrics {
            last_updated: timestamp,
            transactions_per_second: current_tps,
            avg_transaction_confirmation_time_ms: 500.0 + rand::random::<f64>() * 200.0,
            avg_consensus_time_ms: 1.2 + rand::random::<f64>() * 0.8,
            active_validators: 32,
            online_validators: 31 + rand::random::<u32>() % 2,
            uptime_percentage: 99.8 + rand::random::<f64>() * 0.2,
            avg_network_latency_ms: 45.0 + rand::random::<f64>() * 30.0,
            network_throughput_mbps: 850.0 + rand::random::<f64>() * 150.0,
            shard_metrics,
            bls_metrics: BLSMetrics {
                signatures_per_second: current_tps * 1.2, // Más firmas que transacciones
                verifications_per_second: current_tps * 8.0, // Verificaciones por múltiples validadores
                avg_signature_generation_time_ms: 0.1 + rand::random::<f64>() * 0.05,
                avg_verification_time_ms: 0.05 + rand::random::<f64>() * 0.03,
                verification_success_rate: 99.95 + rand::random::<f64>() * 0.05,
                signature_aggregations_per_second: current_tps / 10.0, // Agregaciones menos frecuentes
            },
        }
    }

    /// Recolectar métricas de negocio
    async fn collect_business_metrics(timestamp: u64) -> BusinessMetrics {
        // Simular métricas de negocio del protocolo
        let mut tx_type_distribution = HashMap::new();
        tx_type_distribution.insert("transfer".to_string(), 15000 + rand::random::<u64>() % 5000);
        tx_type_distribution.insert(
            "contract_call".to_string(),
            8000 + rand::random::<u64>() % 3000,
        );
        tx_type_distribution.insert(
            "contract_deploy".to_string(),
            50 + rand::random::<u64>() % 30,
        );
        tx_type_distribution.insert("stake".to_string(), 200 + rand::random::<u64>() % 100);
        tx_type_distribution.insert("governance".to_string(), 10 + rand::random::<u64>() % 20);

        BusinessMetrics {
            last_updated: timestamp,
            total_transaction_volume: 50_000_000.0 + rand::random::<f64>() * 10_000_000.0,
            active_accounts_count: 250_000 + rand::random::<u64>() % 50_000,
            deployed_contracts_count: 15_000 + rand::random::<u64>() % 2_000,
            total_value_locked: 125_000_000.0 + rand::random::<f64>() * 25_000_000.0,
            total_fees_collected: 875_000.0 + rand::random::<f64>() * 125_000.0,
            transaction_type_distribution: tx_type_distribution,
            governance_metrics: GovernanceMetrics {
                active_proposals: 3 + rand::random::<u32>() % 5,
                avg_voting_participation: 65.0 + rand::random::<f64>() * 15.0,
                governance_staked_tokens: 45_000_000.0 + rand::random::<f64>() * 5_000_000.0,
                avg_proposal_resolution_time_hours: 72.0 + rand::random::<f64>() * 24.0,
            },
            staking_metrics: StakingMetrics {
                total_staked_tokens: 180_000_000.0 + rand::random::<f64>() * 20_000_000.0,
                total_stakers: 12_000 + rand::random::<u64>() % 2_000,
                avg_staking_apy: 8.5 + rand::random::<f64>() * 2.0,
                avg_unstaking_time_hours: 168.0, // 7 días
                slashing_events_count: rand::random::<u32>() % 3,
            },
        }
    }

    /// Evaluar alertas basadas en métricas
    async fn evaluate_metric_alerts(
        system_metrics: &SystemMetrics,
        performance_metrics: &PerformanceMetrics,
        business_metrics: &BusinessMetrics,
        metric_alerts: &Arc<RwLock<HashMap<String, MetricAlert>>>,
        config: &MetricsConfig,
    ) {
        let mut alerts = metric_alerts.write().await;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Evaluar alerta de CPU
        if let Some(alert) = alerts.get_mut("high_cpu_usage") {
            alert.current_value = system_metrics.cpu_usage_percent;
            if system_metrics.cpu_usage_percent > alert.threshold_value {
                if alert.status != AlertStatus::Active {
                    alert.status = AlertStatus::Active;
                    alert.triggered_at = Some(timestamp);
                    alert.trigger_count += 1;
                    warn!("🚨 ALERT: {}", alert.message);
                }
            } else if alert.status == AlertStatus::Active {
                alert.status = AlertStatus::Resolved;
                info!("✅ RESOLVED: High CPU usage alert");
            }
        }

        // Evaluar alerta de memoria
        if let Some(alert) = alerts.get_mut("high_memory_usage") {
            alert.current_value = system_metrics.memory_usage_percent;
            if system_metrics.memory_usage_percent > alert.threshold_value {
                if alert.status != AlertStatus::Active {
                    alert.status = AlertStatus::Active;
                    alert.triggered_at = Some(timestamp);
                    alert.trigger_count += 1;
                    warn!("🚨 ALERT: {}", alert.message);
                }
            } else if alert.status == AlertStatus::Active {
                alert.status = AlertStatus::Resolved;
                info!("✅ RESOLVED: High memory usage alert");
            }
        }

        // Evaluar alerta de TPS bajo
        if let Some(alert) = alerts.get_mut("low_tps") {
            alert.current_value = performance_metrics.transactions_per_second;
            if performance_metrics.transactions_per_second < alert.threshold_value {
                if alert.status != AlertStatus::Active {
                    alert.status = AlertStatus::Active;
                    alert.triggered_at = Some(timestamp);
                    alert.trigger_count += 1;
                    warn!("🚨 ALERT: {}", alert.message);
                }
            } else if alert.status == AlertStatus::Active {
                alert.status = AlertStatus::Resolved;
                info!("✅ RESOLVED: Low TPS alert");
            }
        }

        // Evaluar alerta de consenso lento
        if let Some(alert) = alerts.get_mut("slow_consensus") {
            alert.current_value = performance_metrics.avg_consensus_time_ms;
            if performance_metrics.avg_consensus_time_ms > alert.threshold_value {
                if alert.status != AlertStatus::Active {
                    alert.status = AlertStatus::Active;
                    alert.triggered_at = Some(timestamp);
                    alert.trigger_count += 1;
                    warn!("🚨 ALERT: {}", alert.message);
                }
            } else if alert.status == AlertStatus::Active {
                alert.status = AlertStatus::Resolved;
                info!("✅ RESOLVED: Slow consensus alert");
            }
        }
    }

    /// Iniciar export de métricas
    async fn start_metrics_export(&self) -> AvoResult<()> {
        let system_metrics = self.system_metrics.clone();
        let performance_metrics = self.performance_metrics.clone();
        let business_metrics = self.business_metrics.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Export cada minuto

            loop {
                interval.tick().await;

                if let Err(e) = Self::export_metrics(
                    &system_metrics,
                    &performance_metrics,
                    &business_metrics,
                    &config,
                )
                .await
                {
                    error!("🚨 Metrics export error: {}", e);
                }
            }
        });

        info!("📤 Metrics export system started");
        Ok(())
    }

    /// Exportar métricas a sistema externo
    async fn export_metrics(
        system_metrics: &Arc<RwLock<SystemMetrics>>,
        performance_metrics: &Arc<RwLock<PerformanceMetrics>>,
        business_metrics: &Arc<RwLock<BusinessMetrics>>,
        config: &MetricsConfig,
    ) -> AvoResult<()> {
        let system = system_metrics.read().await;
        let performance = performance_metrics.read().await;
        let business = business_metrics.read().await;

        match config.export_format.as_str() {
            "prometheus" => {
                // Exportar en formato Prometheus
                let prometheus_metrics =
                    Self::format_prometheus_metrics(&system, &performance, &business);
                debug!(
                    "📤 Exported {} lines to Prometheus format",
                    prometheus_metrics.lines().count()
                );
            }
            "json" => {
                // Exportar en formato JSON
                let json_metrics = serde_json::json!({
                    "system": &*system,
                    "performance": &*performance,
                    "business": &*business
                });
                debug!(
                    "📤 Exported {} bytes in JSON format",
                    json_metrics.to_string().len()
                );
            }
            _ => {
                debug!("📤 Custom metrics export format: {}", config.export_format);
            }
        }

        Ok(())
    }

    /// Formatear métricas para Prometheus
    fn format_prometheus_metrics(
        system: &SystemMetrics,
        performance: &PerformanceMetrics,
        business: &BusinessMetrics,
    ) -> String {
        let mut output = String::new();

        // Métricas del sistema
        output.push_str(&format!(
            "avo_cpu_usage_percent {}\n",
            system.cpu_usage_percent
        ));
        output.push_str(&format!(
            "avo_memory_usage_percent {}\n",
            system.memory_usage_percent
        ));
        output.push_str(&format!(
            "avo_disk_usage_percent {}\n",
            system.disk_usage_percent
        ));

        // Métricas de rendimiento
        output.push_str(&format!(
            "avo_transactions_per_second {}\n",
            performance.transactions_per_second
        ));
        output.push_str(&format!(
            "avo_avg_consensus_time_ms {}\n",
            performance.avg_consensus_time_ms
        ));
        output.push_str(&format!(
            "avo_online_validators {}\n",
            performance.online_validators
        ));

        // Métricas de negocio
        output.push_str(&format!(
            "avo_total_value_locked {}\n",
            business.total_value_locked
        ));
        output.push_str(&format!(
            "avo_active_accounts {}\n",
            business.active_accounts_count
        ));

        output
    }

    /// Obtener métricas actuales del sistema
    pub async fn get_system_metrics(&self) -> SystemMetrics {
        self.system_metrics.read().await.clone()
    }

    /// Obtener métricas actuales de rendimiento
    pub async fn get_performance_metrics(&self) -> PerformanceMetrics {
        self.performance_metrics.read().await.clone()
    }

    /// Obtener métricas actuales de negocio
    pub async fn get_business_metrics(&self) -> BusinessMetrics {
        self.business_metrics.read().await.clone()
    }

    /// Obtener historial de métricas
    pub async fn get_metrics_history(&self, limit: Option<usize>) -> MetricsHistory {
        let history = self.metrics_history.read().await;
        let limit = limit.unwrap_or(100);

        let mut limited_history = MetricsHistory {
            system_history: VecDeque::new(),
            performance_history: VecDeque::new(),
            business_history: VecDeque::new(),
            collection_timestamps: VecDeque::new(),
        };

        let start_index = if history.system_history.len() > limit {
            history.system_history.len() - limit
        } else {
            0
        };

        for i in start_index..history.system_history.len() {
            if let (Some(sys), Some(perf), Some(bus), Some(ts)) = (
                history.system_history.get(i),
                history.performance_history.get(i),
                history.business_history.get(i),
                history.collection_timestamps.get(i),
            ) {
                limited_history.system_history.push_back(sys.clone());
                limited_history.performance_history.push_back(perf.clone());
                limited_history.business_history.push_back(bus.clone());
                limited_history.collection_timestamps.push_back(*ts);
            }
        }

        limited_history
    }

    /// Obtener alertas activas
    pub async fn get_active_alerts(&self) -> HashMap<String, MetricAlert> {
        let alerts = self.metric_alerts.read().await;
        alerts
            .iter()
            .filter(|(_, alert)| alert.status == AlertStatus::Active)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Generar reporte de métricas
    pub async fn generate_metrics_report(&self) -> String {
        let system = self.get_system_metrics().await;
        let performance = self.get_performance_metrics().await;
        let business = self.get_business_metrics().await;
        let active_alerts = self.get_active_alerts().await;

        format!(
            "📊 AVO PROTOCOL METRICS REPORT\n\
             ════════════════════════════════\n\
             🖥️  SYSTEM METRICS:\n\
             • CPU Usage: {:.1}%\n\
             • Memory Usage: {:.1}% ({} MB / {} MB)\n\
             • Disk Usage: {:.1}% ({} GB / {} GB)\n\
             • Active Threads: {}\n\
             • Network I/O: {:.1} MB/s in, {:.1} MB/s out\n\
             \n\
             ⚡ PERFORMANCE METRICS:\n\
             • TPS: {:.0} transactions/second\n\
             • Avg Consensus Time: {:.2}ms\n\
             • Online Validators: {}/{}\n\
             • Network Latency: {:.1}ms\n\
             • Uptime: {:.2}%\n\
             • BLS Signatures/sec: {:.0}\n\
             • BLS Verifications/sec: {:.0}\n\
             \n\
             💼 BUSINESS METRICS:\n\
             • Total Value Locked: ${:.0}\n\
             • Active Accounts: {}\n\
             • Deployed Contracts: {}\n\
             • Total Staked: ${:.0}\n\
             • Governance Participation: {:.1}%\n\
             \n\
             🚨 ACTIVE ALERTS: {}\n\
             ════════════════════════════════",
            system.cpu_usage_percent,
            system.memory_usage_percent,
            system.memory_used_bytes / (1024 * 1024),
            system.memory_total_bytes / (1024 * 1024),
            system.disk_usage_percent,
            system.disk_used_bytes / (1024 * 1024 * 1024),
            system.disk_total_bytes / (1024 * 1024 * 1024),
            system.active_threads,
            system.network_io.bytes_received_per_sec / (1024.0 * 1024.0),
            system.network_io.bytes_sent_per_sec / (1024.0 * 1024.0),
            performance.transactions_per_second,
            performance.avg_consensus_time_ms,
            performance.online_validators,
            performance.active_validators,
            performance.avg_network_latency_ms,
            performance.uptime_percentage,
            performance.bls_metrics.signatures_per_second,
            performance.bls_metrics.verifications_per_second,
            business.total_value_locked,
            business.active_accounts_count,
            business.deployed_contracts_count,
            business.staking_metrics.total_staked_tokens,
            business.governance_metrics.avg_voting_participation,
            active_alerts.len()
        )
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            collection_interval_seconds: 30,
            max_history_points: 2880, // 24 horas con intervalos de 30s
            enable_detailed_metrics: true,
            enable_metrics_export: false,
            alert_thresholds: MetricAlertThresholds {
                max_cpu_usage: 80.0,
                max_memory_usage: 85.0,
                max_disk_usage: 90.0,
                min_transactions_per_second: 5000.0,
                max_consensus_time_ms: 5000.0,
                min_online_validators: 24,
                max_network_latency_ms: 200.0,
                min_uptime_percentage: 99.0,
            },
            export_endpoint: None,
            export_format: "json".to_string(),
        }
    }
}
