use crate::error::*;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Sistema de health checks para producción
#[derive(Debug)]
pub struct ProductionHealthMonitor {
    /// Métricas de salud actuales
    health_metrics: Arc<RwLock<HealthMetrics>>,
    /// Configuración de monitoring
    config: HealthConfig,
    /// Historial de checks
    check_history: Arc<RwLock<Vec<HealthCheckResult>>>,
    /// Estado de alertas activas
    active_alerts: Arc<RwLock<HashMap<String, AlertInfo>>>,
}

/// Métricas de salud del sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// Timestamp del último check
    pub last_check: u64,
    /// Estado general del sistema
    pub overall_status: HealthStatus,
    /// Métricas del consenso
    pub consensus_health: ConsensusHealth,
    /// Métricas de la red
    pub network_health: NetworkHealth,
    /// Métricas de los shards
    pub shard_health: HashMap<ShardId, ShardHealth>,
    /// Métricas de recursos del sistema
    pub system_resources: SystemResourceHealth,
    /// Uptime del nodo
    pub uptime_seconds: u64,
}

/// Estado de salud
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Down,
}

/// Salud del consenso
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusHealth {
    /// Tiempo promedio de consenso en ms
    pub avg_consensus_time_ms: f64,
    /// Número de epochs fallidas en la última hora
    pub failed_epochs_hour: u32,
    /// Porcentaje de validadores online
    pub validators_online_percent: f64,
    /// Tiempo desde la última finalización
    pub last_finality_seconds: u64,
    /// Verificaciones BLS exitosas (%)
    pub bls_verification_success_rate: f64,
}

/// Salud de la red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealth {
    /// Número de peers conectados
    pub connected_peers: u32,
    /// Latencia promedio de red en ms
    pub avg_network_latency_ms: f64,
    /// Mensajes enviados por segundo
    pub messages_per_second: f64,
    /// Tasa de pérdida de paquetes (%)
    pub packet_loss_rate: f64,
    /// Bandwidth utilizado en Mbps
    pub bandwidth_utilization_mbps: f64,
}

/// Salud de un shard específico
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardHealth {
    /// ID del shard
    pub shard_id: ShardId,
    /// TPS actual del shard
    pub current_tps: f64,
    /// Transacciones pendientes
    pub pending_transactions: usize,
    /// Validadores activos en el shard
    pub active_validators: usize,
    /// Tiempo promedio de procesamiento
    pub avg_processing_time_ms: f64,
    /// Estado de sincronización
    pub sync_status: SyncStatus,
}

/// Estado de sincronización
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStatus {
    Synced,
    Syncing,
    Lagging,
    Stalled,
}

/// Salud de recursos del sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResourceHealth {
    /// Uso de CPU (%)
    pub cpu_usage_percent: f64,
    /// Uso de memoria (%)
    pub memory_usage_percent: f64,
    /// Uso de disco (%)
    pub disk_usage_percent: f64,
    /// Número de file descriptors abiertos
    pub open_file_descriptors: u32,
    /// Número de threads activos
    pub active_threads: u32,
}

/// Resultado de un health check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Timestamp del check
    pub timestamp: u64,
    /// Componente verificado
    pub component: String,
    /// Estado resultante
    pub status: HealthStatus,
    /// Mensaje descriptivo
    pub message: String,
    /// Tiempo que tomó el check en ms
    pub check_duration_ms: u64,
}

/// Información de una alerta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInfo {
    /// ID único de la alerta
    pub alert_id: String,
    /// Timestamp cuando se activó
    pub triggered_at: u64,
    /// Severidad de la alerta
    pub severity: AlertSeverity,
    /// Mensaje de la alerta
    pub message: String,
    /// Número de veces que se ha disparado
    pub trigger_count: u32,
}

/// Severidad de alertas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Configuración del sistema de health monitoring
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Intervalo entre checks en segundos
    pub check_interval_seconds: u64,
    /// Límites para alertas
    pub alert_thresholds: AlertThresholds,
    /// Número máximo de entradas en el historial
    pub max_history_entries: usize,
    /// Timeout para health checks en ms
    pub check_timeout_ms: u64,
}

/// Umbrales para alertas
#[derive(Debug, Clone)]
pub struct AlertThresholds {
    /// Tiempo máximo de consenso antes de alerta (ms)
    pub max_consensus_time_ms: f64,
    /// Mínimo porcentaje de validadores online
    pub min_validators_online_percent: f64,
    /// Máximo tiempo sin finalización (segundos)
    pub max_time_without_finality_seconds: u64,
    /// Mínimo número de peers conectados
    pub min_connected_peers: u32,
    /// Máxima latencia de red (ms)
    pub max_network_latency_ms: f64,
    /// Máximo uso de CPU (%)
    pub max_cpu_usage_percent: f64,
    /// Máximo uso de memoria (%)
    pub max_memory_usage_percent: f64,
    /// Máximo uso de disco (%)
    pub max_disk_usage_percent: f64,
}

impl ProductionHealthMonitor {
    /// Crear nueva instancia del monitor de salud
    pub fn new(config: HealthConfig) -> Self {
        let initial_metrics = HealthMetrics {
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            overall_status: HealthStatus::Healthy,
            consensus_health: ConsensusHealth {
                avg_consensus_time_ms: 0.0,
                failed_epochs_hour: 0,
                validators_online_percent: 100.0,
                last_finality_seconds: 0,
                bls_verification_success_rate: 100.0,
            },
            network_health: NetworkHealth {
                connected_peers: 0,
                avg_network_latency_ms: 0.0,
                messages_per_second: 0.0,
                packet_loss_rate: 0.0,
                bandwidth_utilization_mbps: 0.0,
            },
            shard_health: HashMap::new(),
            system_resources: SystemResourceHealth {
                cpu_usage_percent: 0.0,
                memory_usage_percent: 0.0,
                disk_usage_percent: 0.0,
                open_file_descriptors: 0,
                active_threads: 0,
            },
            uptime_seconds: 0,
        };

        Self {
            health_metrics: Arc::new(RwLock::new(initial_metrics)),
            config,
            check_history: Arc::new(RwLock::new(Vec::new())),
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Iniciar el sistema de monitoring
    pub async fn start_monitoring(&self) -> AvoResult<()> {
        info!("🔍 Starting production health monitoring system");
        info!("📊 Check interval: {}s", self.config.check_interval_seconds);
        info!("⚠️  Alert thresholds configured for production environment");

        let health_metrics = self.health_metrics.clone();
        let check_history = self.check_history.clone();
        let active_alerts = self.active_alerts.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(config.check_interval_seconds));
            let start_time = Instant::now();

            loop {
                interval.tick().await;

                let check_start = Instant::now();

                // Realizar health check completo
                if let Err(e) = Self::perform_comprehensive_health_check(
                    &health_metrics,
                    &check_history,
                    &active_alerts,
                    &config,
                    start_time.elapsed().as_secs(),
                )
                .await
                {
                    error!("🚨 Health check failed: {}", e);
                }

                let check_duration = check_start.elapsed();
                debug!("✅ Health check completed in {:?}", check_duration);
            }
        });

        Ok(())
    }

    /// Realizar health check completo del sistema
    async fn perform_comprehensive_health_check(
        health_metrics: &Arc<RwLock<HealthMetrics>>,
        check_history: &Arc<RwLock<Vec<HealthCheckResult>>>,
        active_alerts: &Arc<RwLock<HashMap<String, AlertInfo>>>,
        config: &HealthConfig,
        uptime_seconds: u64,
    ) -> AvoResult<()> {
        let check_start = Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Check consensus health
        let consensus_result = Self::check_consensus_health().await;
        Self::record_check_result(check_history, "consensus", &consensus_result, check_start).await;

        // 2. Check network health
        let network_result = Self::check_network_health().await;
        Self::record_check_result(check_history, "network", &network_result, check_start).await;

        // 3. Check shard health
        let shard_results = Self::check_all_shards_health().await;
        for (shard_id, result) in &shard_results {
            Self::record_check_result(
                check_history,
                &format!("shard_{}", shard_id),
                result,
                check_start,
            )
            .await;
        }

        // 4. Check system resources
        let resource_result = Self::check_system_resources().await;
        Self::record_check_result(
            check_history,
            "system_resources",
            &resource_result,
            check_start,
        )
        .await;

        // 5. Update health metrics
        Self::update_health_metrics(
            health_metrics,
            timestamp,
            uptime_seconds,
            &consensus_result,
            &network_result,
            &shard_results,
            &resource_result,
        )
        .await;

        // 6. Evaluate alerts
        Self::evaluate_and_trigger_alerts(health_metrics, active_alerts, config).await;

        info!(
            "🔍 Health check completed - System status: {:?}",
            health_metrics.read().await.overall_status
        );

        Ok(())
    }

    /// Verificar salud del consenso
    async fn check_consensus_health() -> HealthCheckResult {
        // Simular métricas de consenso (en producción vendría del motor real)
        let avg_time = 1.5; // ms
        let validators_online = 96.9; // %
        let bls_success_rate = 100.0; // %

        let status = if avg_time < 5.0 && validators_online > 90.0 && bls_success_rate > 95.0 {
            HealthStatus::Healthy
        } else if avg_time < 10.0 && validators_online > 80.0 && bls_success_rate > 90.0 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        };

        HealthCheckResult {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            component: "consensus".to_string(),
            status,
            message: format!(
                "Consensus: {}ms avg, {}% validators online, {}% BLS success",
                avg_time, validators_online, bls_success_rate
            ),
            check_duration_ms: 2,
        }
    }

    /// Verificar salud de la red
    async fn check_network_health() -> HealthCheckResult {
        // Simular métricas de red
        let connected_peers = 47;
        let avg_latency = 45.0; // ms
        let packet_loss = 0.1; // %

        let status = if connected_peers > 10 && avg_latency < 100.0 && packet_loss < 1.0 {
            HealthStatus::Healthy
        } else if connected_peers > 5 && avg_latency < 200.0 && packet_loss < 5.0 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        };

        HealthCheckResult {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            component: "network".to_string(),
            status,
            message: format!(
                "Network: {} peers, {}ms latency, {}% packet loss",
                connected_peers, avg_latency, packet_loss
            ),
            check_duration_ms: 3,
        }
    }

    /// Verificar salud de todos los shards
    async fn check_all_shards_health() -> HashMap<ShardId, HealthCheckResult> {
        let mut results = HashMap::new();

        for shard_id in 0..4 {
            let tps = 10_000.0 + (shard_id as f64 * 1000.0);
            let pending_txs = 15 + (shard_id * 5);
            let processing_time = 0.8 + (shard_id as f64 * 0.2);

            let status = if tps > 5000.0 && pending_txs < 100 && processing_time < 2.0 {
                HealthStatus::Healthy
            } else if tps > 1000.0 && pending_txs < 500 && processing_time < 5.0 {
                HealthStatus::Warning
            } else {
                HealthStatus::Critical
            };

            let result = HealthCheckResult {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                component: format!("shard_{}", shard_id),
                status,
                message: format!(
                    "Shard {}: {} TPS, {} pending txs, {}ms processing",
                    shard_id, tps as u64, pending_txs, processing_time
                ),
                check_duration_ms: 1,
            };

            results.insert(shard_id, result);
        }

        results
    }

    /// Verificar recursos del sistema
    async fn check_system_resources() -> HealthCheckResult {
        // Simular métricas de recursos
        let cpu_usage = 25.3; // %
        let memory_usage = 68.7; // %
        let disk_usage = 42.1; // %

        let status = if cpu_usage < 80.0 && memory_usage < 85.0 && disk_usage < 90.0 {
            HealthStatus::Healthy
        } else if cpu_usage < 90.0 && memory_usage < 95.0 && disk_usage < 95.0 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        };

        HealthCheckResult {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            component: "system_resources".to_string(),
            status,
            message: format!(
                "Resources: {}% CPU, {}% Memory, {}% Disk",
                cpu_usage, memory_usage, disk_usage
            ),
            check_duration_ms: 5,
        }
    }

    /// Registrar resultado de un check
    async fn record_check_result(
        check_history: &Arc<RwLock<Vec<HealthCheckResult>>>,
        component: &str,
        result: &HealthCheckResult,
        _check_start: Instant,
    ) {
        let mut history = check_history.write().await;
        history.push(result.clone());

        // Mantener solo las últimas 1000 entradas
        if history.len() > 1000 {
            history.remove(0);
        }

        match result.status {
            HealthStatus::Healthy => {
                debug!("✅ {} health check passed: {}", component, result.message)
            }
            HealthStatus::Warning => {
                warn!("⚠️  {} health check warning: {}", component, result.message)
            }
            HealthStatus::Critical => {
                error!("🚨 {} health check critical: {}", component, result.message)
            }
            HealthStatus::Down => {
                error!("💀 {} health check failed: {}", component, result.message)
            }
        }
    }

    /// Actualizar métricas de salud
    async fn update_health_metrics(
        health_metrics: &Arc<RwLock<HealthMetrics>>,
        timestamp: u64,
        uptime_seconds: u64,
        consensus_result: &HealthCheckResult,
        network_result: &HealthCheckResult,
        shard_results: &HashMap<ShardId, HealthCheckResult>,
        resource_result: &HealthCheckResult,
    ) {
        let mut metrics = health_metrics.write().await;

        metrics.last_check = timestamp;
        metrics.uptime_seconds = uptime_seconds;

        // Determinar estado general
        let mut statuses = vec![
            &consensus_result.status,
            &network_result.status,
            &resource_result.status,
        ];

        for result in shard_results.values() {
            statuses.push(&result.status);
        }

        metrics.overall_status = if statuses
            .iter()
            .any(|s| matches!(s, HealthStatus::Critical | HealthStatus::Down))
        {
            HealthStatus::Critical
        } else if statuses.iter().any(|s| matches!(s, HealthStatus::Warning)) {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        // Actualizar métricas específicas (simuladas para demo)
        metrics.consensus_health.avg_consensus_time_ms = 1.5;
        metrics.consensus_health.validators_online_percent = 96.9;
        metrics.consensus_health.bls_verification_success_rate = 100.0;

        metrics.network_health.connected_peers = 47;
        metrics.network_health.avg_network_latency_ms = 45.0;

        metrics.system_resources.cpu_usage_percent = 25.3;
        metrics.system_resources.memory_usage_percent = 68.7;
        metrics.system_resources.disk_usage_percent = 42.1;
    }

    /// Evaluar y disparar alertas según los umbrales
    async fn evaluate_and_trigger_alerts(
        health_metrics: &Arc<RwLock<HealthMetrics>>,
        active_alerts: &Arc<RwLock<HashMap<String, AlertInfo>>>,
        config: &HealthConfig,
    ) {
        let metrics = health_metrics.read().await;
        let mut alerts = active_alerts.write().await;

        // Lógica de alertas (ejemplo para CPU)
        if metrics.system_resources.cpu_usage_percent
            > config.alert_thresholds.max_cpu_usage_percent
        {
            let alert_id = "high_cpu_usage".to_string();
            if let Some(existing_alert) = alerts.get_mut(&alert_id) {
                existing_alert.trigger_count += 1;
            } else {
                let alert = AlertInfo {
                    alert_id: alert_id.clone(),
                    triggered_at: metrics.last_check,
                    severity: if metrics.system_resources.cpu_usage_percent > 90.0 {
                        AlertSeverity::Critical
                    } else {
                        AlertSeverity::Warning
                    },
                    message: format!(
                        "High CPU usage: {}%",
                        metrics.system_resources.cpu_usage_percent
                    ),
                    trigger_count: 1,
                };

                info!("🚨 NEW ALERT: {}", alert.message);
                alerts.insert(alert_id, alert);
            }
        }

        // Más alertas se agregarían aquí...
    }

    /// Obtener métricas actuales de salud
    pub async fn get_health_metrics(&self) -> HealthMetrics {
        self.health_metrics.read().await.clone()
    }

    /// Obtener historial de checks
    pub async fn get_check_history(&self, limit: Option<usize>) -> Vec<HealthCheckResult> {
        let history = self.check_history.read().await;
        let limit = limit.unwrap_or(100);

        if history.len() <= limit {
            history.clone()
        } else {
            history[history.len() - limit..].to_vec()
        }
    }

    /// Obtener alertas activas
    pub async fn get_active_alerts(&self) -> HashMap<String, AlertInfo> {
        self.active_alerts.read().await.clone()
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval_seconds: 30, // Check cada 30 segundos
            alert_thresholds: AlertThresholds {
                max_consensus_time_ms: 10000.0,
                min_validators_online_percent: 80.0,
                max_time_without_finality_seconds: 120,
                min_connected_peers: 5,
                max_network_latency_ms: 200.0,
                max_cpu_usage_percent: 80.0,
                max_memory_usage_percent: 85.0,
                max_disk_usage_percent: 90.0,
            },
            max_history_entries: 1000,
            check_timeout_ms: 5000,
        }
    }
}
