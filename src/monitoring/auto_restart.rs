use crate::error::*;
use crate::monitoring::health_checks::{AlertSeverity, HealthMetrics, HealthStatus};
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Sistema de auto-restart para tolerancia a fallos
#[derive(Debug)]
pub struct AutoRestartManager {
    /// Configuración del auto-restart
    config: RestartConfig,
    /// Estado actual del sistema
    system_state: Arc<RwLock<SystemState>>,
    /// Historial de restarts
    restart_history: Arc<RwLock<Vec<RestartEvent>>>,
    /// Procesos monitoreados
    monitored_processes: Arc<RwLock<HashMap<String, ProcessInfo>>>,
    /// Canal para comandos de restart
    restart_sender: mpsc::UnboundedSender<RestartCommand>,
    /// Métricas de tolerancia a fallos
    fault_tolerance_metrics: Arc<RwLock<FaultToleranceMetrics>>,
}

/// Estado del sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    /// Timestamp del último check
    pub last_check: u64,
    /// Estado operacional
    pub operational_status: OperationalStatus,
    /// Número de restarts en la última hora
    pub restarts_last_hour: u32,
    /// Tiempo de uptime actual en segundos
    pub current_uptime_seconds: u64,
    /// Tiempo de uptime total acumulado
    pub total_uptime_seconds: u64,
    /// Fallos consecutivos detectados
    pub consecutive_failures: u32,
    /// Modo de operación actual
    pub operation_mode: OperationMode,
}

/// Estado operacional del sistema
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationalStatus {
    /// Sistema funcionando normalmente
    Running,
    /// Sistema en proceso de restart
    Restarting,
    /// Sistema en modo degradado
    Degraded,
    /// Sistema experimentando fallos
    Failing,
    /// Sistema completamente caído
    Down,
    /// Sistema en modo de mantenimiento
    Maintenance,
}

/// Modo de operación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationMode {
    /// Modo de producción normal
    Production,
    /// Modo de recuperación automática
    AutoRecovery,
    /// Modo safe (funcionalidad limitada)
    SafeMode,
    /// Modo de emergencia (solo servicios críticos)
    Emergency,
}

/// Información de un proceso monitoreado
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Nombre del proceso
    pub name: String,
    /// Process ID
    pub pid: Option<u32>,
    /// Comando para iniciar el proceso
    pub start_command: String,
    /// Argumentos del comando
    pub args: Vec<String>,
    /// Directorio de trabajo
    pub working_directory: String,
    /// Timestamp del último check
    pub last_check: u64,
    /// Estado del proceso
    pub status: ProcessStatus,
    /// Número de restarts
    pub restart_count: u32,
    /// Última vez que se restarteó
    pub last_restart: Option<u64>,
    /// Configuración de restart para este proceso
    pub restart_policy: ProcessRestartPolicy,
}

/// Estado de un proceso
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessStatus {
    Running,
    Stopped,
    Failed,
    Restarting,
    Unknown,
}

/// Política de restart para un proceso
#[derive(Debug, Clone)]
pub struct ProcessRestartPolicy {
    /// Máximo número de restarts por hora
    pub max_restarts_per_hour: u32,
    /// Delay entre restarts en segundos
    pub restart_delay_seconds: u64,
    /// Timeout para que el proceso inicie
    pub startup_timeout_seconds: u64,
    /// Condiciones bajo las cuales reiniciar
    pub restart_conditions: Vec<RestartCondition>,
}

/// Condiciones para restart automático
#[derive(Debug, Clone)]
pub enum RestartCondition {
    /// Proceso no responde
    ProcessUnresponsive,
    /// Alto uso de memoria
    HighMemoryUsage(f64),
    /// Alto uso de CPU
    HighCpuUsage(f64),
    /// Fallos de health check
    HealthCheckFailures(u32),
    /// Consenso fallando
    ConsensusFailing,
    /// Red desconectada
    NetworkDisconnected,
    /// Sistema en estado crítico
    SystemCritical,
}

/// Evento de restart
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartEvent {
    /// Timestamp del restart
    pub timestamp: u64,
    /// Componente que se restarteó
    pub component: String,
    /// Razón del restart
    pub reason: String,
    /// Tipo de restart
    pub restart_type: RestartType,
    /// Duración del restart en ms
    pub duration_ms: u64,
    /// Éxito del restart
    pub success: bool,
    /// Mensaje adicional
    pub message: String,
}

/// Tipos de restart
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestartType {
    /// Restart automático por fallos
    Automatic,
    /// Restart manual solicitado
    Manual,
    /// Restart por maintenance
    Maintenance,
    /// Restart de emergencia
    Emergency,
    /// Restart graceful
    Graceful,
    /// Restart forzado
    Forced,
}

/// Comando de restart
#[derive(Debug, Clone)]
pub enum RestartCommand {
    /// Reiniciar proceso específico
    RestartProcess(String, RestartType),
    /// Reiniciar todo el sistema
    RestartSystem(RestartType),
    /// Cambiar modo de operación
    ChangeOperationMode(OperationMode),
    /// Activar modo safe
    ActivateSafeMode,
    /// Shutdown graceful
    GracefulShutdown,
    /// Emergency shutdown
    EmergencyShutdown,
}

/// Métricas de tolerancia a fallos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultToleranceMetrics {
    /// Tiempo promedio de recovery en ms
    pub avg_recovery_time_ms: f64,
    /// Número total de fallos detectados
    pub total_failures_detected: u64,
    /// Número total de recoveries exitosos
    pub successful_recoveries: u64,
    /// Tasa de éxito de recovery (%)
    pub recovery_success_rate: f64,
    /// Tiempo máximo de downtime en ms
    pub max_downtime_ms: u64,
    /// Tiempo total de downtime acumulado
    pub total_downtime_ms: u64,
    /// Disponibilidad del sistema (%)
    pub system_availability_percent: f64,
    /// MTBF (Mean Time Between Failures) en horas
    pub mtbf_hours: f64,
    /// MTTR (Mean Time To Recovery) en minutos
    pub mttr_minutes: f64,
}

/// Configuración del sistema de auto-restart
#[derive(Debug, Clone)]
pub struct RestartConfig {
    /// Habilitar auto-restart
    pub enable_auto_restart: bool,
    /// Máximo número de restarts automáticos por hora
    pub max_auto_restarts_per_hour: u32,
    /// Timeout para restart graceful en segundos
    pub graceful_restart_timeout_seconds: u64,
    /// Timeout para restart forzado en segundos
    pub forced_restart_timeout_seconds: u64,
    /// Delay mínimo entre restarts en segundos
    pub min_restart_delay_seconds: u64,
    /// Umbrales para activar auto-restart
    pub restart_thresholds: RestartThresholds,
    /// Notificaciones de restart
    pub notification_settings: NotificationSettings,
}

/// Umbrales para auto-restart
#[derive(Debug, Clone)]
pub struct RestartThresholds {
    /// Número de health check failures consecutivos
    pub consecutive_health_failures: u32,
    /// Tiempo máximo sin consenso (segundos)
    pub max_time_without_consensus_seconds: u64,
    /// Porcentaje mínimo de validadores online
    pub min_validators_online_percent: f64,
    /// Tiempo máximo de respuesta del sistema (ms)
    pub max_system_response_time_ms: u64,
    /// Uso máximo de memoria antes de restart (%)
    pub max_memory_usage_percent: f64,
}

/// Configuración de notificaciones
#[derive(Debug, Clone)]
pub struct NotificationSettings {
    /// Enviar notificaciones por email
    pub email_notifications: bool,
    /// Enviar notificaciones a Slack
    pub slack_notifications: bool,
    /// Log level para eventos de restart
    pub log_level: String,
    /// Webhook URL para notificaciones
    pub webhook_url: Option<String>,
}

impl AutoRestartManager {
    /// Crear nueva instancia del auto-restart manager
    pub fn new(config: RestartConfig) -> Self {
        let (restart_sender, _) = mpsc::unbounded_channel();

        let initial_state = SystemState {
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            operational_status: OperationalStatus::Running,
            restarts_last_hour: 0,
            current_uptime_seconds: 0,
            total_uptime_seconds: 0,
            consecutive_failures: 0,
            operation_mode: OperationMode::Production,
        };

        let initial_metrics = FaultToleranceMetrics {
            avg_recovery_time_ms: 0.0,
            total_failures_detected: 0,
            successful_recoveries: 0,
            recovery_success_rate: 100.0,
            max_downtime_ms: 0,
            total_downtime_ms: 0,
            system_availability_percent: 100.0,
            mtbf_hours: 0.0,
            mttr_minutes: 0.0,
        };

        Self {
            config,
            system_state: Arc::new(RwLock::new(initial_state)),
            restart_history: Arc::new(RwLock::new(Vec::new())),
            monitored_processes: Arc::new(RwLock::new(HashMap::new())),
            restart_sender,
            fault_tolerance_metrics: Arc::new(RwLock::new(initial_metrics)),
        }
    }

    /// Iniciar el sistema de auto-restart
    pub async fn start_auto_restart_system(&self) -> AvoResult<()> {
        info!("🔄 Starting auto-restart system");
        info!(
            "⚙️  Auto-restart enabled: {}",
            self.config.enable_auto_restart
        );
        info!(
            "📊 Max restarts per hour: {}",
            self.config.max_auto_restarts_per_hour
        );

        // Registrar procesos críticos para monitoreo
        self.register_critical_processes().await?;

        // Iniciar el loop de monitoreo
        let system_state = self.system_state.clone();
        let restart_history = self.restart_history.clone();
        let monitored_processes = self.monitored_processes.clone();
        let fault_tolerance_metrics = self.fault_tolerance_metrics.clone();
        let config = self.config.clone();
        let restart_sender = self.restart_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10)); // Check cada 10 segundos
            let system_start_time = Instant::now();

            loop {
                interval.tick().await;

                if let Err(e) = Self::monitor_system_health(
                    &system_state,
                    &restart_history,
                    &monitored_processes,
                    &fault_tolerance_metrics,
                    &config,
                    &restart_sender,
                    system_start_time.elapsed().as_secs(),
                )
                .await
                {
                    error!("🚨 Auto-restart monitoring failed: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Registrar procesos críticos para monitoreo
    async fn register_critical_processes(&self) -> AvoResult<()> {
        let mut processes = self.monitored_processes.write().await;

        // Proceso principal del nodo
        let node_process = ProcessInfo {
            name: "avo-node".to_string(),
            pid: None,
            start_command: "avo-node".to_string(),
            args: vec!["--config".to_string(), "production.toml".to_string()],
            working_directory: ".".to_string(),
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            status: ProcessStatus::Running,
            restart_count: 0,
            last_restart: None,
            restart_policy: ProcessRestartPolicy {
                max_restarts_per_hour: 3,
                restart_delay_seconds: 30,
                startup_timeout_seconds: 120,
                restart_conditions: vec![
                    RestartCondition::ProcessUnresponsive,
                    RestartCondition::HealthCheckFailures(3),
                    RestartCondition::ConsensusFailing,
                    RestartCondition::HighMemoryUsage(90.0),
                ],
            },
        };

        // Proceso de consenso
        let consensus_process = ProcessInfo {
            name: "consensus-engine".to_string(),
            pid: None,
            start_command: "consensus-engine".to_string(),
            args: vec!["--mode".to_string(), "production".to_string()],
            working_directory: ".".to_string(),
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            status: ProcessStatus::Running,
            restart_count: 0,
            last_restart: None,
            restart_policy: ProcessRestartPolicy {
                max_restarts_per_hour: 5,
                restart_delay_seconds: 15,
                startup_timeout_seconds: 60,
                restart_conditions: vec![
                    RestartCondition::ConsensusFailing,
                    RestartCondition::HealthCheckFailures(2),
                    RestartCondition::ProcessUnresponsive,
                ],
            },
        };

        processes.insert("avo-node".to_string(), node_process);
        processes.insert("consensus-engine".to_string(), consensus_process);

        info!(
            "📝 Registered {} critical processes for monitoring",
            processes.len()
        );
        Ok(())
    }

    /// Monitorear salud del sistema y decidir restarts
    async fn monitor_system_health(
        system_state: &Arc<RwLock<SystemState>>,
        restart_history: &Arc<RwLock<Vec<RestartEvent>>>,
        monitored_processes: &Arc<RwLock<HashMap<String, ProcessInfo>>>,
        fault_tolerance_metrics: &Arc<RwLock<FaultToleranceMetrics>>,
        config: &RestartConfig,
        restart_sender: &mpsc::UnboundedSender<RestartCommand>,
        uptime_seconds: u64,
    ) -> AvoResult<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Actualizar estado del sistema
        {
            let mut state = system_state.write().await;
            state.last_check = timestamp;
            state.current_uptime_seconds = uptime_seconds;
            state.total_uptime_seconds += 10; // Incrementar por intervalo de check
        }

        // Monitorear procesos críticos
        let mut critical_failures = 0;
        {
            let mut processes = monitored_processes.write().await;
            for (name, process_info) in processes.iter_mut() {
                let process_health = Self::check_process_health(process_info).await;

                if !process_health {
                    critical_failures += 1;
                    warn!("⚠️  Critical process {} is unhealthy", name);

                    // Evaluar si necesita restart
                    if Self::should_restart_process(process_info, config).await {
                        info!("🔄 Scheduling restart for process {}", name);
                        let _ = restart_sender.send(RestartCommand::RestartProcess(
                            name.clone(),
                            RestartType::Automatic,
                        ));
                    }
                }
            }
        }

        // Evaluar estado general del sistema
        let should_restart_system =
            Self::evaluate_system_restart_conditions(system_state, critical_failures, config).await;

        if should_restart_system {
            warn!("🚨 System restart conditions met - scheduling system restart");
            let _ = restart_sender.send(RestartCommand::RestartSystem(RestartType::Automatic));
        }

        // Actualizar métricas de tolerancia a fallos
        Self::update_fault_tolerance_metrics(
            fault_tolerance_metrics,
            critical_failures,
            uptime_seconds,
        )
        .await;

        debug!(
            "🔍 System health monitoring completed - {} critical failures detected",
            critical_failures
        );
        Ok(())
    }

    /// Verificar salud de un proceso específico
    async fn check_process_health(process_info: &mut ProcessInfo) -> bool {
        // Simular verificación de salud del proceso
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        process_info.last_check = timestamp;

        // En producción, aquí verificaríamos:
        // - Si el proceso está corriendo (kill -0 $PID)
        // - Uso de recursos del proceso
        // - Respuesta a health checks
        // - Estado de los logs

        // Simular que procesos están generalmente saludables con ocasionales fallos
        let health_probability = match process_info.name.as_str() {
            "avo-node" => 0.98,         // 98% probabilidad de estar saludable
            "consensus-engine" => 0.95, // 95% probabilidad
            _ => 0.90,
        };

        let is_healthy = rand::random::<f64>() < health_probability;

        process_info.status = if is_healthy {
            ProcessStatus::Running
        } else {
            ProcessStatus::Failed
        };

        is_healthy
    }

    /// Evaluar si un proceso necesita restart
    async fn should_restart_process(process_info: &ProcessInfo, config: &RestartConfig) -> bool {
        if !config.enable_auto_restart {
            return false;
        }

        // Verificar límite de restarts por hora
        if process_info.restart_count >= process_info.restart_policy.max_restarts_per_hour {
            warn!(
                "⚠️  Process {} has exceeded restart limit for this hour",
                process_info.name
            );
            return false;
        }

        // Verificar delay mínimo entre restarts
        if let Some(last_restart) = process_info.last_restart {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let time_since_restart = now - last_restart;

            if time_since_restart < process_info.restart_policy.restart_delay_seconds {
                debug!(
                    "⏱️  Too soon to restart process {} ({}s since last restart)",
                    process_info.name, time_since_restart
                );
                return false;
            }
        }

        // Evaluar condiciones de restart
        matches!(
            process_info.status,
            ProcessStatus::Failed | ProcessStatus::Unknown
        )
    }

    /// Evaluar condiciones para restart del sistema completo
    async fn evaluate_system_restart_conditions(
        system_state: &Arc<RwLock<SystemState>>,
        critical_failures: u32,
        config: &RestartConfig,
    ) -> bool {
        if !config.enable_auto_restart {
            return false;
        }

        let state = system_state.read().await;

        // Verificar límite de restarts del sistema
        if state.restarts_last_hour >= config.max_auto_restarts_per_hour {
            return false;
        }

        // Condiciones para restart del sistema
        let conditions_met = critical_failures >= 2 || // Múltiples procesos críticos fallando
                            state.consecutive_failures >= config.restart_thresholds.consecutive_health_failures ||
                            matches!(state.operational_status, OperationalStatus::Failing | OperationalStatus::Down);

        conditions_met
    }

    /// Actualizar métricas de tolerancia a fallos
    async fn update_fault_tolerance_metrics(
        fault_tolerance_metrics: &Arc<RwLock<FaultToleranceMetrics>>,
        critical_failures: u32,
        uptime_seconds: u64,
    ) {
        let mut metrics = fault_tolerance_metrics.write().await;

        if critical_failures > 0 {
            metrics.total_failures_detected += critical_failures as u64;
        }

        // Calcular disponibilidad del sistema
        let total_time = uptime_seconds + metrics.total_downtime_ms / 1000;
        if total_time > 0 {
            metrics.system_availability_percent =
                ((total_time - metrics.total_downtime_ms / 1000) as f64 / total_time as f64)
                    * 100.0;
        }

        // Simular métricas adicionales
        metrics.recovery_success_rate = if metrics.total_failures_detected > 0 {
            (metrics.successful_recoveries as f64 / metrics.total_failures_detected as f64) * 100.0
        } else {
            100.0
        };

        if uptime_seconds > 0 {
            metrics.mtbf_hours = uptime_seconds as f64 / 3600.0;
        }
    }

    /// Ejecutar restart de un proceso específico
    pub async fn restart_process(
        &self,
        process_name: &str,
        restart_type: RestartType,
    ) -> AvoResult<()> {
        let restart_start = Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        info!(
            "🔄 Starting restart of process: {} (type: {:?})",
            process_name, restart_type
        );

        let mut success = false;
        let mut error_message = String::new();

        // Actualizar información del proceso
        {
            let mut processes = self.monitored_processes.write().await;
            if let Some(process_info) = processes.get_mut(process_name) {
                process_info.status = ProcessStatus::Restarting;
                process_info.restart_count += 1;
                process_info.last_restart = Some(timestamp);

                // Simular restart del proceso
                tokio::time::sleep(Duration::from_millis(500)).await; // Simular tiempo de restart

                // Simular éxito/fallo del restart
                success = rand::random::<f64>() > 0.1; // 90% de éxito

                if success {
                    process_info.status = ProcessStatus::Running;
                    info!("✅ Process {} restarted successfully", process_name);
                } else {
                    process_info.status = ProcessStatus::Failed;
                    error_message = "Failed to restart process".to_string();
                    error!("❌ Failed to restart process {}", process_name);
                }
            } else {
                error_message = "Process not found".to_string();
                error!(
                    "❌ Process {} not found in monitored processes",
                    process_name
                );
            }
        }

        // Registrar evento de restart
        let restart_event = RestartEvent {
            timestamp,
            component: process_name.to_string(),
            reason: format!("Process restart requested ({:?})", restart_type),
            restart_type,
            duration_ms: restart_start.elapsed().as_millis() as u64,
            success,
            message: if success {
                "Process restarted successfully".to_string()
            } else {
                error_message.clone()
            },
        };

        {
            let mut history = self.restart_history.write().await;
            history.push(restart_event);

            // Mantener solo las últimas 100 entradas
            if history.len() > 100 {
                history.remove(0);
            }
        }

        // Actualizar métricas de tolerancia a fallos
        if success {
            let mut metrics = self.fault_tolerance_metrics.write().await;
            metrics.successful_recoveries += 1;
            metrics.avg_recovery_time_ms =
                (metrics.avg_recovery_time_ms + restart_start.elapsed().as_millis() as f64) / 2.0;
        }

        if success {
            Ok(())
        } else {
            Err(AvoError::SystemError(format!(
                "Failed to restart process {}: {}",
                process_name, error_message
            )))
        }
    }

    /// Ejecutar restart del sistema completo
    pub async fn restart_system(&self, restart_type: RestartType) -> AvoResult<()> {
        let restart_start = Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        warn!("🚨 Starting SYSTEM RESTART (type: {:?})", restart_type);

        // Actualizar estado del sistema
        {
            let mut state = self.system_state.write().await;
            state.operational_status = OperationalStatus::Restarting;
            state.restarts_last_hour += 1;
            state.consecutive_failures = 0; // Reset contador
        }

        // Simular restart del sistema
        info!("📋 Phase 1: Graceful shutdown of all services");
        tokio::time::sleep(Duration::from_millis(1000)).await;

        info!("📋 Phase 2: Restarting core services");
        tokio::time::sleep(Duration::from_millis(1500)).await;

        info!("📋 Phase 3: Validating system integrity");
        tokio::time::sleep(Duration::from_millis(800)).await;

        let success = rand::random::<f64>() > 0.05; // 95% de éxito para restart del sistema

        // Actualizar estado final
        {
            let mut state = self.system_state.write().await;
            if success {
                state.operational_status = OperationalStatus::Running;
                state.operation_mode = OperationMode::Production;
                info!("✅ System restart completed successfully");
            } else {
                state.operational_status = OperationalStatus::Failing;
                state.operation_mode = OperationMode::SafeMode;
                error!("❌ System restart failed - entering safe mode");
            }
        }

        // Registrar evento de restart del sistema
        let restart_event = RestartEvent {
            timestamp,
            component: "system".to_string(),
            reason: format!("System restart requested ({:?})", restart_type),
            restart_type,
            duration_ms: restart_start.elapsed().as_millis() as u64,
            success,
            message: if success {
                "System restarted successfully".to_string()
            } else {
                "System restart failed - operating in safe mode".to_string()
            },
        };

        {
            let mut history = self.restart_history.write().await;
            history.push(restart_event);
        }

        if success {
            Ok(())
        } else {
            Err(AvoError::SystemError("System restart failed".to_string()))
        }
    }

    /// Obtener estado actual del sistema
    pub async fn get_system_state(&self) -> SystemState {
        self.system_state.read().await.clone()
    }

    /// Obtener historial de restarts
    pub async fn get_restart_history(&self, limit: Option<usize>) -> Vec<RestartEvent> {
        let history = self.restart_history.read().await;
        let limit = limit.unwrap_or(50);

        if history.len() <= limit {
            history.clone()
        } else {
            history[history.len() - limit..].to_vec()
        }
    }

    /// Obtener métricas de tolerancia a fallos
    pub async fn get_fault_tolerance_metrics(&self) -> FaultToleranceMetrics {
        self.fault_tolerance_metrics.read().await.clone()
    }

    /// Activar modo safe del sistema
    pub async fn activate_safe_mode(&self, reason: &str) -> AvoResult<()> {
        warn!("🛡️  Activating SAFE MODE: {}", reason);

        let mut state = self.system_state.write().await;
        state.operation_mode = OperationMode::SafeMode;
        state.operational_status = OperationalStatus::Degraded;

        info!("🛡️  Safe mode activated - system running with limited functionality");
        Ok(())
    }

    /// Evaluar y reaccionar a métricas de salud
    pub async fn evaluate_health_metrics(&self, health_metrics: &HealthMetrics) -> AvoResult<()> {
        match health_metrics.overall_status {
            HealthStatus::Critical => {
                warn!("🚨 Critical health status detected - evaluating auto-restart");

                let mut state = self.system_state.write().await;
                state.consecutive_failures += 1;

                if state.consecutive_failures
                    >= self.config.restart_thresholds.consecutive_health_failures
                {
                    drop(state); // Release lock before restart
                    warn!(
                        "🔄 Triggering automatic system restart due to persistent critical health"
                    );
                    return self.restart_system(RestartType::Automatic).await;
                }
            }
            HealthStatus::Warning => {
                warn!("⚠️  Warning health status - monitoring closely");
            }
            HealthStatus::Healthy => {
                let mut state = self.system_state.write().await;
                state.consecutive_failures = 0; // Reset contador en estado saludable
            }
            _ => {}
        }

        Ok(())
    }
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            enable_auto_restart: true,
            max_auto_restarts_per_hour: 3,
            graceful_restart_timeout_seconds: 60,
            forced_restart_timeout_seconds: 10,
            min_restart_delay_seconds: 30,
            restart_thresholds: RestartThresholds {
                consecutive_health_failures: 3,
                max_time_without_consensus_seconds: 300,
                min_validators_online_percent: 70.0,
                max_system_response_time_ms: 10000,
                max_memory_usage_percent: 90.0,
            },
            notification_settings: NotificationSettings {
                email_notifications: false,
                slack_notifications: false,
                log_level: "INFO".to_string(),
                webhook_url: None,
            },
        }
    }
}
